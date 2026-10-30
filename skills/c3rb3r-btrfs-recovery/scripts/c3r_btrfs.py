#!/usr/bin/env python3
"""C3RB3R (.L0CK3D) 受害 Btrfs 卷的只读恢复工具（在 NAS 上以 root 运行，仅用 Python 3.6+ 标准库）。

原理：C3RB3R 原地部分覆盖文件。若覆盖写在 Btrfs 上走了 CoW（CoW 共享，或 NoCOW 但数据早于子卷最后一次快照），
被覆盖区段的原始明文仍留在旧 extent 中；只要文件未加密部分仍引用该 extent，它就不会被释放。
本工具读 EXTENT_DATA 项（BTRFS_IOC_TREE_SEARCH），把每个被改写的字节映射回旧 extent，并可用校验和树逐块证实。

只读保证：只做 open(O_RDONLY)、ioctl 查询、pread 块设备、运行 dump-tree。不写数据卷；输出全部走 stdout。

子命令：
  preflight [PATH|FILE]             环境自检：逐项 OK/WARN/FAIL 并给出处理建议（任何设备上都先跑这个）
  env      [PATH]                    卷、块设备、chunk 映射、子卷 lastsnap、共享 NoCOW 属性、工具可用性
  gens     ROOT|@LIST [--sample N]   统计加密文件新旧 extent 代数，给出 G_ATTACK 建议
  survey   ROOT|@LIST --g G          逐文件分类，JSONL(gzip) -> stdout
  extract  ROOT|@LIST --g G          重组原文件，tar 流 -> stdout（末尾附 _c3r_manifest.jsonl）
  csum     ROOT|@LIST --g G          用校验和树核对 exact 段的每个 4K 块，JSONL -> stdout
  plan     FILE --g G                打印单个文件的 extent 项与重组计划（人工排查用）
通用选项：--dev 块设备（默认按路径自动识别）  --exclude 目录名（可多次；默认 @eaDir #snapshot @docker）
"""
import argparse
import fcntl
import gzip
import hashlib
import io
import json
import os
import re
import struct
import subprocess
import sys
import tarfile

FOOTER = 588
BLK = 4096
PIECE = 8 << 20
MAX_EXTENT = 128 << 20

# ---------- 尾部格式 ----------
# [0:48] AES-CBC(file_key32|nonce8|nonce8)  [568:572] 会话标记（每次运行不同）
# [572] 模式 0x24 全加密 / 0x25 分段 / 0x26 前缀  [573] 百分比参数  [574] 加密方式（0x20）  [580:588] 原始长度 u64 LE


def parse_footer(tail, size):
    if len(tail) != FOOTER:
        return None
    n = struct.unpack_from('<Q', tail, 580)[0]
    if n + FOOTER != size:
        return None
    return {'marker': tail[568:572].hex(), 'mode': tail[572:576].hex(), 'orig': n}


def formula_ranges(mode_hex, n):
    """已知模式的加密区间；未知模式返回 None（此时只靠新 extent 推断改写范围）。"""
    mode, pct = int(mode_hex[0:2], 16), int(mode_hex[2:4], 16)
    if mode == 0x24:
        return [(0, n)]
    if mode == 0x26:
        return [(0, min(n, 1 << 20))]
    if mode == 0x25 and pct == 0x0a:
        w = 4 * (n // 100)
        gap = (n - 3 * w) // 2
        return [(0, w), (w + gap, 2 * w + gap), (2 * (w + gap), 3 * w + 2 * gap)]
    return None


def down(x):
    return x // BLK * BLK


def up(x):
    return (x + BLK - 1) // BLK * BLK


# ---------- Btrfs ioctl ----------
TREE_SEARCH = 0xD0009411      # BTRFS_IOC_TREE_SEARCH（4KB 缓冲）
TREE_SEARCH_V2 = 0xC0709411   # BTRFS_IOC_TREE_SEARCH_V2（自定缓冲；csum 项可达 16KB 必须用它）
FS_IOC_GETFLAGS = 0x80086601
FS_NOCOW_FL = 0x00800000
EXTENT_DATA_KEY = 108
CSUM_OBJECTID = 0xFFFFFFFFFFFFFFF6
CSUM_KEY = 128
KEY_FMT = '7Q4I4Q'
KEY_LEN = struct.calcsize(KEY_FMT)
HDR_FMT = '3Q2I'
HDR_LEN = struct.calcsize(HDR_FMT)
U64 = 2 ** 64 - 1


USE_V1 = False   # 内核 < 3.16 无 TREE_SEARCH_V2 时自动退回 V1（V1 缓冲 4KB，csum 查询会受限）


def search(fd, tree, objid, typ, min_off, max_off, bufsize=1 << 16):
    global USE_V1
    key = struct.pack(KEY_FMT, tree, objid, objid, min_off, max_off, 0, U64, typ, typ, 4096, 0, 0, 0, 0, 0)
    if not USE_V1:
        buf = bytearray(key + struct.pack('Q', bufsize) + b'\0' * bufsize)
        try:
            fcntl.ioctl(fd, TREE_SEARCH_V2, buf)
            pos = KEY_LEN + 8
        except OSError as ex:
            if ex.errno not in (25, 22):   # ENOTTY / EINVAL：接口不存在
                raise
            USE_V1 = True
    if USE_V1:
        buf = bytearray(key + b'\0' * (4096 - KEY_LEN))
        fcntl.ioctl(fd, TREE_SEARCH, buf)
        pos = KEY_LEN
    nr = struct.unpack_from('I', buf, 64)[0]
    out = []
    for _ in range(nr):
        _, oid, off, t, ln = struct.unpack_from(HDR_FMT, buf, pos)
        out.append((oid, off, t, bytes(buf[pos + HDR_LEN:pos + HDR_LEN + ln])))
        pos += HDR_LEN + ln
    return out


def extent_items(fd, ino):
    items, min_off = [], 0
    while True:
        res = search(fd, 0, ino, EXTENT_DATA_KEY, min_off, U64)
        if not res:
            return items
        for oid, off, t, data in res:
            if oid != ino or t != EXTENT_DATA_KEY:
                continue
            gen, ram, comp, enc, oenc, etype = struct.unpack_from('<QQBBHB', data, 0)
            it = {'pos': off, 'gen': gen, 'type': etype, 'comp': comp}
            if etype in (1, 2):
                it['bytenr'], it['dnum'], it['eoff'], it['num'] = struct.unpack_from('<4Q', data, 21)
            else:
                it['num'] = ram
                it['bytenr'] = 0
            items.append(it)
        if res[-1][1] == U64:
            return items
        min_off = res[-1][1] + 1


_CRC = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CRC.append(_c)


def crc32c(data):
    c, t = 0xFFFFFFFF, _CRC
    for b in data:
        c = t[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


# 超级块 csum_type -> (名称, 每块校验和字节数, 计算函数)；xxhash64 需第三方实现，未支持
CSUM_TYPES = {
    0: ('crc32c', 4, lambda d: struct.pack('<I', crc32c(d))),
    1: ('xxhash64', 8, None),
    2: ('sha256', 32, lambda d: hashlib.sha256(d).digest()),
    3: ('blake2b', 32, lambda d: hashlib.blake2b(d, digest_size=32).digest()),
}
CSUM_TYPE = 0


def block_csum(data):
    fn = CSUM_TYPES.get(CSUM_TYPE, (None, None, None))[2]
    return fn(data) if fn else None


def csum_of(fd, logical):
    """校验和树中 logical 所在扇区的 csum；无记录返回 None。"""
    csize = CSUM_TYPES.get(CSUM_TYPE, ('?', 4, None))[1]
    for oid, off, t, data in search(fd, 7, CSUM_OBJECTID, CSUM_KEY, max(0, logical - (64 << 20)), logical, 1 << 20):
        if t == CSUM_KEY and off <= logical < off + len(data) // csize * BLK:
            i = (logical - off) // BLK * csize
            return data[i:i + csize]
    return None


# ---------- 设备与 chunk 映射 ----------
def run(cmd):
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False).stdout.decode('utf-8', 'replace')
    except OSError:
        return ''


def dump_tree(dev, tree):
    for cmd in (['btrfs', 'inspect-internal', 'dump-tree', '-t', str(tree), dev], ['btrfs-debug-tree', '-t', str(tree), dev]):
        out = run(cmd)
        if 'item ' in out:
            return out
    sys.exit('无法运行 btrfs inspect-internal dump-tree 或 btrfs-debug-tree')


def device_for(path):
    best = ('', '')
    for line in open('/proc/mounts'):
        dev, mnt, fs = line.split()[:3]
        mnt = mnt.replace('\\040', ' ')
        if fs == 'btrfs' and (path == mnt or path.startswith(mnt.rstrip('/') + '/')) and len(mnt) > len(best[1]):
            best = (dev, mnt)
    return best[0]


def read_superblock(dev):
    """读主超级块（设备偏移 64KiB）：返回 (sectorsize, csum_type)。"""
    fd = os.open(dev, os.O_RDONLY)
    try:
        sb = os.pread(fd, 4096, 65536)
    finally:
        os.close(fd)
    if sb[0x40:0x48] != b'_BHRfS_M':
        sys.exit('%s 的 64KiB 处没有 Btrfs 超级块：设备选错了（群晖常见 /dev/mapper/cachedev_N、/dev/vgN/volume_N、/dev/mdN）' % dev)
    return struct.unpack_from('<I', sb, 0x90)[0], struct.unpack_from('<H', sb, 0xC4)[0]


def parse_chunks(text):
    """逐项解析 chunk tree 文本（兼容 btrfs-progs 4.x 的 "chunk length" 与新版 "length" 两种写法）。"""
    chunks = []
    for block in re.split(r'\n\s*item \d+ key ', text):
        m = re.search(r'CHUNK_ITEM (\d+)\)', block)
        if not m:
            continue
        ln = re.search(r'length (\d+)', block)
        ty = re.search(r'type (\S+)', block)
        st = re.search(r'stripe 0 devid (\d+) offset (\d+)', block)
        if not (ln and ty and st):
            continue
        typ = ty.group(1)
        if 'DATA' in typ.split('|'):
            chunks.append((int(m.group(1)), int(ln.group(1)), int(st.group(2)), typ, int(st.group(1))))
    return sorted(chunks)


class Volume:
    def __init__(self, dev):
        global BLK, CSUM_TYPE
        self.dev = dev
        BLK, CSUM_TYPE = read_superblock(dev)
        self.chunks = parse_chunks(dump_tree(dev, 3))
        if not self.chunks:
            sys.exit('chunk tree 中没有解析到 DATA chunk：dump-tree 输出格式可能不同，请运行 preflight 并按 references/compatibility.md 调整 parse_chunks')
        bad = sorted({c[3] for c in self.chunks if any(k in c[3] for k in ('RAID0', 'RAID10', 'RAID5', 'RAID6'))})
        if bad:
            sys.exit('DATA 剖面 %s 需要按条带换算，本工具只支持 single/DUP/RAID1 类（群晖 SHR/RAID 由 mdraid 负责，Btrfs 层通常为 single）' % bad)
        if len({c[4] for c in self.chunks}) > 1:
            sys.exit('多设备 Btrfs：stripe 0 可能不在 %s 上，需要按 devid 打开对应设备（见 references/compatibility.md）' % dev)
        self.starts = [c[0] for c in self.chunks]
        self.fd = os.open(dev, os.O_RDONLY)

    def to_phys(self, addr):
        import bisect
        i = bisect.bisect_right(self.starts, addr) - 1
        if i >= 0:
            start, length, phys = self.chunks[i][:3]
            if addr < start + length:
                return phys + addr - start, start + length - addr
        raise ValueError('逻辑地址 %d 不在任何 DATA chunk 中' % addr)

    def read(self, addr, size):
        out = b''
        while size > 0:
            phys, room = self.to_phys(addr)
            k = min(size, room)
            out += os.pread(self.fd, k, phys)
            addr += k
            size -= k
        return out


# ---------- 文件分类与重组计划 ----------
def plan_file(path, g_attack, vol, check=True):
    """返回 (rec, segs)。segs 覆盖 [0, N)：(start, end, kind, src)
    kind: cur 读当前文件 | exact 读旧 extent（src=逻辑地址偏移） | infer 外推（src=(prev_delta, next_delta)） | lost 无数据"""
    rec = {'path': path}
    fd = os.open(path, os.O_RDONLY)
    try:
        st = os.fstat(fd)
        rec['size'] = st.st_size
        ft = parse_footer(os.pread(fd, FOOTER, st.st_size - FOOTER), st.st_size) if st.st_size >= FOOTER else None
        if not ft:
            rec['status'] = 'no_footer'
            return rec, None
        rec.update(ft)
        try:
            flags = struct.unpack('I', fcntl.ioctl(fd, FS_IOC_GETFLAGS, b'\0' * 4))[0]
            rec['nocow'] = bool(flags & FS_NOCOW_FL)
        except OSError:
            pass
        items = extent_items(fd, st.st_ino)
    finally:
        os.close(fd)
    n = rec['orig']
    if any(it['type'] == 0 for it in items):
        rec['status'] = 'inline'
        return rec, None
    if any(it['comp'] for it in items):
        rec['status'] = 'compressed'
        return rec, None
    formula = formula_ranges(rec['mode'], n)
    new = [(it['pos'], min(it['pos'] + it['num'], n)) for it in items if it['gen'] >= g_attack and it['pos'] < n]
    old_items = [it for it in items if it['gen'] < g_attack and it['bytenr']]
    olds = sorted({it['bytenr']: (it['pos'] - it['eoff'], it['pos'] - it['eoff'] + it['dnum'], it['bytenr'])
                   for it in old_items}.values())
    rec['n_items'], rec['n_new'] = len(items), len(new)

    def old_at(x):
        for b, e, bn in olds:
            if b <= x < e:
                return b, e, bn
        return None

    # 被改写的范围：新 extent 覆盖处（CoW 写入）+ 公式区间中仍由旧 extent 映射处（NoCOW 原地覆盖）
    spans = []
    for s, e in sorted(new):
        if spans and s <= spans[-1][1]:
            spans[-1] = (spans[-1][0], max(spans[-1][1], e))
        else:
            spans.append((s, e))
    inplace = []
    if formula:
        for a, b in formula:
            x = a
            for s, e in spans:
                if e <= x or s >= b:
                    continue
                if s > x:
                    inplace.append((x, s))
                x = max(x, e)
            if x < b:
                inplace.append((x, b))
    segs = []
    counts = {'exact': 0, 'infer': 0, 'no_candidate': 0, 'inplace': 0}
    for s, e in inplace:
        counts['inplace'] += e - s
    rewritten = sorted([(s, e, 'new') for s, e in spans] + [(s, e, 'inplace') for s, e in inplace])
    pos = 0
    for s, e, why in rewritten:
        if pos < s:
            segs.append((pos, s, 'cur', None))
        s = max(s, pos)
        if why == 'inplace':
            segs.append((s, e, 'lost', None))
            pos = max(pos, e)
            continue
        x = s
        while x < e:
            o = old_at(x)
            if o:
                y = min(e, o[1])
                segs.append((x, y, 'exact', o[2] - o[0]))
                counts['exact'] += y - x
                x = y
                continue
            y = min([ob for ob, oe, bn in olds if ob > x] + [e])
            prev = [(oe, bn - ob) for ob, oe, bn in olds if oe <= x]
            nxt = [(ob, bn - ob) for ob, oe, bn in olds if ob >= y]
            dp = max(prev)[1] if prev else None
            dn = min(nxt)[1] if nxt else None
            if dp is None and dn is None:
                segs.append((x, y, 'lost', None))
                counts['no_candidate'] += y - x
            else:
                segs.append((x, y, 'infer', (dp, dn)))
                counts['infer'] += y - x
            x = y
        pos = max(pos, e)
    if pos < n:
        segs.append((pos, n, 'cur', None))
    rec['bytes'] = counts
    rec['rewritten'] = sum(e - s for s, e, _ in rewritten)
    if rec['rewritten'] == 0:
        rec['status'] = 'no_rewrite_found'
        return rec, segs
    if formula is None:
        rec['formula'] = 'unknown_mode_spans_from_new_extents'
    lost = counts['inplace'] + counts['no_candidate']
    good = counts['exact'] + counts['infer']
    if lost and not good:
        rec['status'] = 'inplace_lost' if counts['inplace'] else 'no_candidate'
    elif lost:
        rec['status'] = 'partial'
    elif counts['infer']:
        rec['status'] = 'needs_inference'
    else:
        rec['status'] = 'exact'
    if check and good:
        ok = bad = 0
        with open(path, 'rb', buffering=0) as f:
            for s, e, kind, src in segs:
                if kind != 'exact':
                    continue
                # 新 extent 内、公式区间外的字节，是加密器按 4K 对齐重写时顺带写回的明文，必须与旧 extent 同位置相同
                if formula:
                    plain = [(s, e)]
                    for a, b in formula:
                        plain = [p for q in plain for p in ((q[0], min(q[1], a)), (max(q[0], b), q[1])) if p[1] > p[0]]
                    for lo, hi in plain:
                        hi = min(hi, lo + 65536)
                        if os.pread(f.fileno(), hi - lo, lo) == vol.read(src + lo, hi - lo):
                            ok += 1
                        else:
                            bad += 1
                    enc = [(max(s, a), min(e, b)) for a, b in formula if max(s, a) < min(e, b)]
                    probe = enc[0][0] if enc else None
                else:
                    probe = s + (e - s) // 2 if e - s >= 64 else None
                # 加密区内：旧数据不应与当前密文相同，否则读到的不是改写前的版本
                if probe is not None:
                    k = min(64, e - probe)
                    if os.pread(f.fileno(), k, probe) == vol.read(src + probe, k):
                        bad += 1
        rec['bchk_ok'], rec['bchk_bad'] = ok, bad
        if bad:
            rec['status'] = 'boundary_mismatch'
    return rec, segs


# ---------- 遍历 ----------
def iter_paths(targets, exclude):
    for t in targets:
        if t.startswith('@'):
            with open(t[1:], encoding='utf-8', errors='surrogateescape') as f:
                for line in f:
                    line = line.rstrip('\n')
                    if line:
                        yield line
            continue
        if os.path.isfile(t):
            yield t
            continue
        for dp, dns, fns in os.walk(t):
            dns[:] = [d for d in dns if d not in exclude]
            for fn in fns:
                if fn.endswith('.L0CK3D'):
                    yield os.path.join(dp, fn)


class Rebuilt(io.RawIOBase):
    def __init__(self, path, segs, variant, vol):
        self.f = open(path, 'rb', buffering=0)
        self.segs, self.variant, self.vol, self.i, self.pos = segs, variant, vol, 0, 0
        self.sha = hashlib.sha256()

    def readable(self):
        return True

    def readinto(self, b):
        while self.i < len(self.segs) and self.pos >= self.segs[self.i][1]:
            self.i += 1
        if self.i >= len(self.segs):
            return 0
        s, e, kind, src = self.segs[self.i]
        k = min(len(b), PIECE, e - self.pos)
        data = None
        if kind == 'cur':
            data = os.pread(self.f.fileno(), k, self.pos)
        elif kind == 'exact':
            data = self.vol.read(src + self.pos, k)
        elif kind == 'infer':
            d = src[0] if self.variant == 'prev' else src[1]
            d = d if d is not None else (src[1] if src[0] is None else src[0])
            try:
                data = self.vol.read(d + self.pos, k)
            except ValueError:
                data = None
        if data is None:
            data = b'\0' * k
        b[:len(data)] = data
        self.sha.update(data)
        self.pos += len(data)
        return len(data)

    def close(self):
        self.f.close()
        super().close()


def member_name(path, variant, status):
    base = os.path.relpath(path, '/')[:-len('.L0CK3D')]
    if variant == 'exact' and status == 'exact':
        return base
    stem, ext = os.path.splitext(base)
    return '%s.__%s%s__%s' % (stem, variant, '_partial' if status == 'partial' else '', ext)


def cmd_extract(args, vol):
    tar = tarfile.open(fileobj=sys.stdout.buffer, mode='w|', format=tarfile.PAX_FORMAT)
    manifest = []
    for p in iter_paths(args.targets, args.exclude):
        try:
            rec, segs = plan_file(p, args.g, vol)
        except Exception as ex:
            manifest.append({'path': p, 'status': 'error', 'err': repr(ex)})
            continue
        if segs is None or rec['status'] not in ('exact', 'needs_inference', 'partial'):
            manifest.append(rec)
            continue
        variants = ['exact']
        if rec['bytes']['infer']:
            differ = any(k == 'infer' and None not in src and src[0] != src[1] for _, _, k, src in segs)
            variants = ['prev', 'next'] if differ else ['prev']
        for v in variants:
            name = member_name(p, v, rec['status'])
            ti = tarfile.TarInfo(name)
            ti.size = rec['orig']
            ti.mtime = int(os.stat(p).st_mtime)
            src = Rebuilt(p, segs, v, vol)
            try:
                tar.addfile(ti, io.BufferedReader(src, PIECE))
            finally:
                src.close()
            manifest.append(dict(rec, variant=v, member=name, sha256=src.sha.hexdigest()))
    data = ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in manifest).encode('utf-8', 'surrogateescape')
    ti = tarfile.TarInfo('_c3r_manifest.jsonl')
    ti.size = len(data)
    tar.addfile(ti, io.BytesIO(data))
    tar.close()


def cmd_survey(args, vol):
    out = gzip.GzipFile(fileobj=sys.stdout.buffer, mode='wb')
    for p in iter_paths(args.targets, args.exclude):
        try:
            rec, _ = plan_file(p, args.g, vol)
        except Exception as ex:
            rec = {'path': p, 'status': 'error', 'err': repr(ex)}
        out.write((json.dumps(rec, ensure_ascii=False) + '\n').encode('utf-8', 'surrogateescape'))
    out.close()


def cmd_csum(args, vol):
    if CSUM_TYPES.get(CSUM_TYPE, (None, None, None))[2] is None:
        sys.exit('本卷校验和算法为 %s，本工具未实现，无法做逐块证实；改用解码与已知原件对照'
                 % CSUM_TYPES.get(CSUM_TYPE, ('未知(%d)' % CSUM_TYPE,))[0])
    for p in iter_paths(args.targets, args.exclude):
        out = {'path': p, 'ok': 0, 'bad': 0, 'nocsum': 0, 'bad_blocks': []}
        try:
            rec, segs = plan_file(p, args.g, vol, check=False)
            out['status'] = rec['status']
            fd = os.open(p, os.O_RDONLY)
            try:
                for s, e, kind, src in segs or []:
                    if kind != 'exact':
                        continue
                    for x in range(up(s), down(e), BLK):
                        want = csum_of(fd, src + x)
                        if want is None:
                            out['nocsum'] += 1
                        elif block_csum(vol.read(src + x, BLK)) == want:
                            out['ok'] += 1
                        else:
                            out['bad'] += 1
                            if len(out['bad_blocks']) < 20:
                                out['bad_blocks'].append(x)
                # 自检：当前仍被引用的旧块必须与其 csum 一致，否则说明 csum 算法/查询有误
                for it in [i for i in extent_items(fd, os.fstat(fd).st_ino) if i['gen'] < args.g and i['bytenr']][:3]:
                    want = csum_of(fd, it['bytenr'] + it['eoff'])
                    if want is not None:
                        key = 'self_ok' if block_csum(vol.read(it['bytenr'] + it['eoff'], BLK)) == want else 'self_bad'
                        out[key] = out.get(key, 0) + 1
            finally:
                os.close(fd)
        except Exception as ex:
            out['error'] = repr(ex)
        print(json.dumps(out, ensure_ascii=False), flush=True)


def cmd_gens(args):
    import random
    paths = list(iter_paths(args.targets, args.exclude))
    random.seed(1)
    paths = random.sample(paths, min(args.sample, len(paths)))
    pos0, others = [], []
    for p in paths:
        fd = os.open(p, os.O_RDONLY)
        try:
            items = extent_items(fd, os.fstat(fd).st_ino)
        finally:
            os.close(fd)
        g0 = [i['gen'] for i in items if i['pos'] == 0]
        if g0:
            pos0.append(g0[0])
        others += [i['gen'] for i in items]
    pos0.sort()
    allg = sorted(set(others))
    lo = pos0[0] if pos0 else None
    below = [g for g in allg if lo is not None and g < lo]
    gap_top = below[-1] if below else None
    print(json.dumps({
        'files_sampled': len(paths), 'pos0_gen_min': lo, 'pos0_gen_max': pos0[-1] if pos0 else None,
        'pos0_gen_p01': pos0[len(pos0) // 100] if pos0 else None,
        'highest_gen_below_pos0_min': gap_top,
        'suggest_G_ATTACK': lo - 16 if lo else None,
        'note': '若 highest_gen_below_pos0_min 与 pos0_gen_min 很接近，说明有攻击前不久写入的数据或样本里混有未在开头加密的文件，需人工确认',
    }, ensure_ascii=False, indent=1))


def cmd_env(args):
    path = args.targets[0] if args.targets else '/volume1'
    dev = args.dev or device_for(path)
    info = {'python': sys.version.split()[0], 'path': path, 'device': dev, 'uid': os.getuid()}
    info['tools'] = {t: bool(run(['sh', '-c', 'command -v ' + t]).strip())
                     for t in ('btrfs', 'btrfs-debug-tree', 'btrfs-map-logical', 'lsattr')}
    info['mounts'] = [l.strip() for l in open('/proc/mounts') if ' btrfs ' in l]
    if dev:
        vol = Volume(dev)
        info['data_chunks'] = len(vol.chunks)
        info['data_profiles'] = sorted({c[3] for c in vol.chunks})
        roots = {}
        cur = None
        for line in dump_tree(dev, 1).splitlines():
            m = re.search(r'key \((\d+) ROOT_ITEM', line)
            if m:
                cur = int(m.group(1))
            m = re.search(r'lastsnap (\d+)', line)
            if m and cur is not None and cur >= 256:
                roots[cur] = int(m.group(1))
                cur = None
        names = {}
        for line in run(['btrfs', 'subvolume', 'list', path]).splitlines():
            m = re.match(r'ID (\d+) .* path (.+)$', line)
            if m:
                names[int(m.group(1))] = m.group(2)
        info['subvolumes'] = [{'id': k, 'path': names.get(k, '?'), 'lastsnap': v} for k, v in sorted(roots.items())
                              if not names.get(k, '').startswith('@docker/btrfs/subvolumes')]
    shares = []
    for name in sorted(os.listdir(path)) if os.path.isdir(path) else []:
        p = os.path.join(path, name)
        if os.path.isdir(p) and not os.path.islink(p):
            try:
                fd = os.open(p, os.O_RDONLY)
                fl = struct.unpack('I', fcntl.ioctl(fd, FS_IOC_GETFLAGS, b'\0' * 4))[0]
                os.close(fd)
                shares.append({'dir': p, 'nocow': bool(fl & FS_NOCOW_FL)})
            except OSError:
                pass
    info['share_roots'] = shares
    print(json.dumps(info, ensure_ascii=False, indent=1))


def cmd_preflight(args):
    """逐项自检；每项给出 OK / WARN / FAIL 与处理建议。任何 FAIL 都应先按建议解决再继续。"""
    res = []

    def rep(level, name, detail, hint=''):
        res.append({'level': level, 'check': name, 'detail': detail, 'hint': hint})
        sys.stderr.write('[%s] %s: %s%s\n' % (level, name, detail, ('\n       -> ' + hint) if hint else ''))

    path = args.targets[0] if args.targets else '/volume1'
    rep('OK' if sys.version_info >= (3, 6) else 'FAIL', 'python', sys.version.split()[0],
        '' if sys.version_info >= (3, 6) else '需要 Python 3.6+：见 compatibility.md 的"没有 Python 3"一节')
    root = os.geteuid() == 0
    rep('OK' if root else 'FAIL', 'root', 'euid=%d' % os.geteuid(), '' if root else '用 sudo 运行（sudo -S ... sh -s），或切换到 root')
    if not root:
        return print(json.dumps(res, ensure_ascii=False, indent=1))
    fs = ''
    for line in open('/proc/mounts'):
        p = line.split()
        if path == p[1] or path.startswith(p[1].rstrip('/') + '/'):
            fs = p[2]
    dev = args.dev or device_for(path)
    if fs != 'btrfs' or not dev:
        hint = {'ext4': 'ext4 没有写时复制，本方法不适用；只能找其他副本或做文件雕刻（成功率很低）',
                'zfs': 'ZFS 也是 CoW，但工具链不同：见 compatibility.md 的 ZFS 一节'}.get(fs, '确认路径是否为数据卷挂载点，或用 --dev 指定块设备')
        rep('FAIL', 'filesystem', '%s 的文件系统是 %s' % (path, fs or '未知'), hint)
        return print(json.dumps(res, ensure_ascii=False, indent=1))
    rep('OK', 'filesystem', 'btrfs on %s' % dev)
    global BLK, CSUM_TYPE
    try:
        BLK, CSUM_TYPE = read_superblock(dev)
        cname = CSUM_TYPES.get(CSUM_TYPE, ('未知(%d)' % CSUM_TYPE, 0, None))
        rep('OK' if BLK == 4096 else 'WARN', 'superblock', 'sectorsize=%d csum=%s' % (BLK, cname[0]),
            '' if BLK == 4096 else '扇区不是 4K：工具会按实际值处理，但请先用已知原件验证')
        if cname[2] is None:
            rep('WARN', 'csum', '校验和算法 %s 未实现' % cname[0], '可以照常恢复，但无法做逐块证实；用解码和已知原件对照代替')
    except SystemExit as ex:
        rep('FAIL', 'superblock', str(ex), '用 --dev 指定正确的块设备（lsblk / cat /proc/mounts）')
        return print(json.dumps(res, ensure_ascii=False, indent=1))
    except OSError as ex:
        rep('FAIL', 'device_read', repr(ex), '需要 root 读取块设备；某些系统还要关闭块设备只读保护或 SELinux 限制')
        return print(json.dumps(res, ensure_ascii=False, indent=1))
    tool = next((c for c in (['btrfs', 'inspect-internal', 'dump-tree'], ['btrfs-debug-tree'])
                 if 'item ' in run(c + ['-t', '3', dev])[:20000]), None)
    if not tool:
        rep('FAIL', 'dump_tree', '没有可用的 btrfs inspect-internal dump-tree / btrfs-debug-tree',
            '安装 btrfs-progs；或把 chunk tree 文本在别的机器上生成后提供（见 compatibility.md）')
        return print(json.dumps(res, ensure_ascii=False, indent=1))
    try:
        vol = Volume(dev)
        rep('OK', 'chunk_map', '%s：%d 个 DATA chunk，剖面 %s' % (' '.join(tool), len(vol.chunks), sorted({c[3] for c in vol.chunks})))
    except SystemExit as ex:
        rep('FAIL', 'chunk_map', str(ex), '见 compatibility.md 的"chunk 映射"一节')
        return print(json.dumps(res, ensure_ascii=False, indent=1))
    # 找样本：优先加密文件，其次任意 >=64KB 的普通文件
    sample = None
    for t in ([path] if os.path.isfile(path) else []):
        sample = t
    if not sample:
        seen = 0
        for dp, dns, fns in os.walk(path):
            dns[:] = [d for d in dns if d not in ('@eaDir', '#snapshot', '@docker', '@tmp')]
            for fn in fns:
                seen += 1
                p = os.path.join(dp, fn)
                if fn.endswith('.L0CK3D') and os.path.getsize(p) > 65536:
                    sample = p
                    break
                if seen > 200000:
                    break
            if sample or seen > 200000:
                break
    if not sample:
        rep('WARN', 'sample', '在 %s 下没找到 .L0CK3D 样本' % path, '用 preflight <某个加密文件路径> 指定样本')
        return print(json.dumps(res, ensure_ascii=False, indent=1))
    rep('OK', 'sample', sample)
    fd = os.open(sample, os.O_RDONLY)
    try:
        st = os.fstat(fd)
        ft = parse_footer(os.pread(fd, FOOTER, st.st_size - FOOTER), st.st_size) if st.st_size >= FOOTER else None
        rep('OK' if ft else 'WARN', 'footer', json.dumps(ft) if ft else '样本尾部不符合 C3RB3R 588 字节结构',
            '' if ft else '可能是别的勒索家族或别的版本：先人工 hexdump -C 文件尾部，对照 c3rb3r-format.md')
        try:
            items = extent_items(fd, st.st_ino)
            rep('OK', 'tree_search', '%d 个 EXTENT_DATA 项（%s）' % (len(items), 'V1' if USE_V1 else 'V2'),
                '内核无 TREE_SEARCH_V2：csum 证实可能查不到大项' if USE_V1 else '')
        except OSError as ex:
            rep('FAIL', 'tree_search', repr(ex), 'EPERM=非 root；ENOTTY=不是 btrfs 或内核过旧；见 compatibility.md')
            return print(json.dumps(res, ensure_ascii=False, indent=1))
        regs = [i for i in items if i['type'] in (1, 2) and i['bytenr'] and not i['comp'] and i['num'] >= BLK]
        if any(i['comp'] for i in items):
            rep('WARN', 'compression', '样本 extent 被透明压缩', '压缩 extent 需解压后才能用，本工具会把这类文件标为 compressed')
        if regs:
            it = regs[0]
            mine = vol.read(it['bytenr'] + it['eoff'], BLK)
            cur = os.pread(fd, BLK, it['pos'])
            rep('OK' if mine == cur else 'FAIL', 'end_to_end_read', '按 extent 映射读块设备 %s 读文件同位置' % ('==' if mine == cur else '!='),
                '' if mine == cur else '地址映射有误：多设备、RAID 条带或设备选错；先不要继续（见 compatibility.md）')
            if shutil_which('btrfs-map-logical'):
                tmp = '/tmp/.c3r_maplog.%d' % os.getpid()
                run(['btrfs-map-logical', '-l', str(it['bytenr'] + it['eoff']), '-b', str(BLK), '-o', tmp, dev])
                try:
                    other = open(tmp, 'rb').read()
                    rep('OK' if other == mine else 'WARN', 'map_logical_crosscheck', '与 btrfs-map-logical 结果%s' % ('一致' if other == mine else '不一致'))
                except OSError:
                    pass
                finally:
                    if os.path.exists(tmp):
                        os.remove(tmp)
            if CSUM_TYPES.get(CSUM_TYPE, (None, None, None))[2]:
                want = csum_of(fd, it['bytenr'] + it['eoff'])
                if want is None:
                    rep('WARN', 'csum_lookup', '样本块没有校验和记录', '样本所在共享可能是 NoCOW / nodatasum；csum 证实只对开启校验和的共享有效')
                else:
                    rep('OK' if block_csum(mine) == want else 'FAIL', 'csum_selfcheck',
                        '样本块 %s 与校验和树记录%s' % (CSUM_TYPES[CSUM_TYPE][0], '一致' if block_csum(mine) == want else '不一致'),
                        '' if block_csum(mine) == want else 'csum 查询或算法有误，csum 结论不可用')
        try:
            fl = struct.unpack('I', fcntl.ioctl(fd, FS_IOC_GETFLAGS, b'\0' * 4))[0]
            rep('OK', 'nocow_flag', 'NoCOW=%s' % bool(fl & FS_NOCOW_FL))
        except OSError as ex:
            rep('WARN', 'nocow_flag', repr(ex))
    finally:
        os.close(fd)
    fails = [r for r in res if r['level'] == 'FAIL']
    sys.stderr.write('\n结论：%s\n' % ('全部关键检查通过，可以继续 gens / survey' if not fails else '有 %d 项 FAIL，请先处理' % len(fails)))
    print(json.dumps(res, ensure_ascii=False, indent=1))


def shutil_which(name):
    import shutil
    return shutil.which(name)


def cmd_plan(args, vol):
    for p in iter_paths(args.targets, args.exclude):
        fd = os.open(p, os.O_RDONLY)
        try:
            items = extent_items(fd, os.fstat(fd).st_ino)
        finally:
            os.close(fd)
        rec, segs = plan_file(p, args.g, vol)
        print(json.dumps({'rec': rec, 'items': items, 'segs': segs}, ensure_ascii=False, indent=1))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('cmd', choices=['preflight', 'env', 'gens', 'survey', 'extract', 'csum', 'plan'])
    ap.add_argument('targets', nargs='*', help='目录、文件，或 @列表文件（每行一个路径）')
    ap.add_argument('--g', type=int, help='G_ATTACK：代数 >= 此值的 extent 视为加密时新写')
    ap.add_argument('--dev', help='块设备，默认按第一个目标所在挂载点识别')
    ap.add_argument('--exclude', action='append', default=None, help='遍历时跳过的目录名')
    ap.add_argument('--sample', type=int, default=3000)
    args = ap.parse_args()
    args.exclude = set(args.exclude or ['@eaDir', '#snapshot', '@docker'])
    if args.cmd == 'preflight':
        return cmd_preflight(args)
    if os.geteuid() != 0:
        sys.exit('需要 root（TREE_SEARCH 与读块设备都要求 CAP_SYS_ADMIN）')
    if args.cmd == 'env':
        return cmd_env(args)
    if not args.targets:
        sys.exit('需要目标路径')
    if args.cmd == 'gens':
        return cmd_gens(args)
    if args.g is None:
        sys.exit('需要 --g G_ATTACK（先运行 gens 子命令确定）')
    first = args.targets[0]
    if first.startswith('@'):
        with open(first[1:], encoding='utf-8', errors='surrogateescape') as f:
            first = f.readline().strip()
    dev = args.dev or device_for(first)
    if not dev:
        sys.exit('找不到 %s 所在的 btrfs 块设备，请用 --dev 指定' % first)
    vol = Volume(dev)
    {'survey': cmd_survey, 'extract': cmd_extract, 'csum': cmd_csum, 'plan': cmd_plan}[args.cmd](args, vol)


if __name__ == '__main__':
    main()
