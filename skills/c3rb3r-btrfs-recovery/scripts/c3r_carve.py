#!/usr/bin/env python3
"""只读的空闲空间雕刻工具：找回被 C3RB3R 整体加密的小文件（survey 状态 no_candidate）。

原理：小文件被整体改写时，CoW 把密文写到新位置，旧 extent 不再被引用而被释放。释放只是 extent 树里少了一项，
原始字节仍留在盘上，直到这块空间被重新分配。本工具只读 DATA chunk 中的**空闲区间**（extent 树中相邻
EXTENT_ITEM 之间的空档），在 4KiB 边界上找文件签名，并且只保留长度**恰好等于**某个丢失文件原始大小的候选
（原始大小来自 .L0CK3D 尾部，即 survey 记录里的 orig）。每个候选都给出 MD5 和 SHA-256，供本地与应用自己存的
校验和、已知原件等比对。候选不等于恢复成功，判定方法见 references/free-space-carving.md。

只读保证：open(O_RDONLY)、TREE_SEARCH ioctl、pread 块设备。输出全部走 stdout，进度走 stderr。
需要同目录的 c3r_btrfs.py（Volume、device_for、TREE_SEARCH 常量）。用 mkjob.py --tool carve 打包时会一并带上。

子命令：
  freemap  [--mount M] [--dev DEV]               各 DATA chunk 的已用 / 空闲统计（只做 ioctl，很快）
  scan     --targets FILE [--mount M] [--dev DEV] 候选 JSONL(gzip) -> stdout，进度 -> stderr
  extract  --picks FILE [--mount M] [--dev DEV]   按挑选结果导出 tar 流 -> stdout（末尾附 _carve_manifest.jsonl）
测试模式（不需要 Btrfs，也不需要 root）：--image FILE 把一个普通文件当作一整块空闲的 DATA chunk。

targets 文件：每行 "类型<TAB>原始大小"（类型：pdf jpg zip png bmp ole；zip 也涵盖 docx/xlsx/pptx/odt 等）
picks 文件：  每行 "逻辑地址<TAB>长度<TAB>tar 成员名"
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import struct
import sys
import tarfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BLK = 4096
PIECE = 16 << 20
U64 = 2 ** 64 - 1
EXTENT_TREE = 2
EXTENT_ITEM_KEY = 168

SIGS = {
    'pdf': [b'%PDF-'],
    'jpg': [b'\xff\xd8\xff'],
    'zip': [b'PK\x03\x04'],
    'png': [b'\x89PNG\r\n\x1a\n'],
    'bmp': [b'BM'],
    'ole': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
}


def log(obj):
    # DSM 7 的 Python 3.8 在 stderr 被重定向时整块缓冲，不 flush 就看不到进度
    sys.stderr.write(json.dumps(obj) + '\n')
    sys.stderr.flush()


# ---------- 各格式的候选长度（从签名处的窗口里找所有可能的结尾） ----------
def _ends(w, marker, extra):
    i = w.find(marker)
    while i != -1:
        yield i + len(marker) + extra
        i = w.find(marker, i + 1)


def lengths_pdf(w):
    # 增量保存的 PDF 有多个 %%EOF；结尾可能还跟 \r、\n 或 \r\n
    for n in _ends(w, b'%%EOF', 0):
        yield n
        if w[n:n + 1] in (b'\r', b'\n'):
            yield n + 1
            if w[n:n + 2] == b'\r\n':
                yield n + 2


def lengths_jpg(w):
    return _ends(w, b'\xff\xd9', 0)


def lengths_png(w):
    return _ends(w, b'IEND\xaeB`\x82', 0)


def lengths_zip(w):
    # End of central directory：22 字节 + 注释长度
    i = w.find(b'PK\x05\x06')
    while i != -1:
        if i + 22 <= len(w):
            yield i + 22 + struct.unpack_from('<H', w, i + 20)[0]
        i = w.find(b'PK\x05\x06', i + 1)


def lengths_bmp(w):
    # 文件头自带总长度；保留字段必须为 0，否则多半是随机数据里的 "BM"
    if len(w) >= 14 and w[6:10] == b'\0\0\0\0':
        yield struct.unpack_from('<I', w, 2)[0]


def lengths_ole(w):
    """OLE2（老式 doc/xls/ppt/msg）：按 FAT 中最后一个已用扇区推出长度。只支持头部 DIFAT 内的 FAT（<=109 个）。"""
    if len(w) < 512:
        return
    shift = struct.unpack_from('<H', w, 0x1E)[0]
    if shift not in (9, 12):
        return
    ss = 1 << shift
    nfat = struct.unpack_from('<I', w, 0x2C)[0]
    if not 0 < nfat <= 109:
        return
    top = -1
    for k in range(nfat):
        sid = struct.unpack_from('<I', w, 0x4C + 4 * k)[0]
        off = (sid + 1) * ss
        if sid >= 0xFFFFFFFA or off + ss > len(w):
            return
        ents = struct.unpack_from('<%dI' % (ss // 4), w, off)
        for j in range(len(ents) - 1, -1, -1):
            if ents[j] != 0xFFFFFFFF:
                top = max(top, k * (ss // 4) + j)
                break
    if top >= 0:
        yield (top + 2) * ss


LENGTHS = {'pdf': lengths_pdf, 'jpg': lengths_jpg, 'zip': lengths_zip, 'png': lengths_png,
           'bmp': lengths_bmp, 'ole': lengths_ole}


# ---------- 卷访问 ----------
class ImageVolume:
    """测试替身：普通文件 = 逻辑地址 0 处的一整块 DATA chunk，全部空闲。"""

    def __init__(self, path):
        self.fd = os.open(path, os.O_RDONLY)
        self.size = os.fstat(self.fd).st_size
        self.chunks = [(0, self.size, 0, 'DATA', 1)]

    def read(self, addr, size):
        return os.pread(self.fd, size, addr)


def search_range(fd, tree, lo, hi, bufsize=1 << 16):
    """TREE_SEARCH_V2 遍历键 lo..hi（(objectid, type, offset)，含两端），逐项 yield (objectid, type, offset, data)。"""
    import fcntl
    from c3r_btrfs import KEY_FMT, KEY_LEN, HDR_FMT, HDR_LEN, TREE_SEARCH_V2
    oid, typ, off = lo
    while True:
        key = struct.pack(KEY_FMT, tree, oid, hi[0], off, hi[2], 0, U64, typ, hi[1], 4096, 0, 0, 0, 0, 0)
        buf = bytearray(key + struct.pack('Q', bufsize) + b'\0' * bufsize)
        fcntl.ioctl(fd, TREE_SEARCH_V2, buf)
        nr = struct.unpack_from('I', buf, 64)[0]
        if not nr:
            return
        pos = KEY_LEN + 8
        for _ in range(nr):
            _, o, f, t, ln = struct.unpack_from(HDR_FMT, buf, pos)
            yield o, t, f, bytes(buf[pos + HDR_LEN:pos + HDR_LEN + ln])
            pos += HDR_LEN + ln
        oid, typ, off = o, t, f
        if off < U64:
            off += 1
        elif typ < 255:
            typ, off = typ + 1, 0
        else:
            oid, typ, off = oid + 1, 0, 0
        if (oid, typ, off) > tuple(hi):
            return


def gaps_between(start, end, extents):
    """[start, end) 中不被任何 (逻辑地址, 长度) extent 覆盖的区间，extents 须按地址升序。"""
    gaps, cur = [], start
    for addr, length in extents:
        if addr + length <= start or addr >= end:
            continue
        if addr > cur:
            gaps.append((cur, addr))
        cur = max(cur, addr + length)
    if cur < end:
        gaps.append((cur, end))
    return gaps


def free_gaps(mnt_fd, start, length):
    """一个 DATA chunk 内的空闲区间 [a, b) = 相邻 EXTENT_ITEM 之间的空档（EXTENT_ITEM 的 offset 就是长度）。"""
    if mnt_fd is None:
        return [(start, start + length)]
    items = ((oid, off) for oid, typ, off, _ in
             search_range(mnt_fd, EXTENT_TREE, (start, 0, 0), (start + length - 1, 255, U64))
             if typ == EXTENT_ITEM_KEY)
    return gaps_between(start, start + length, items)


def open_volume(args):
    if args.image:
        return ImageVolume(args.image), None
    from c3r_btrfs import Volume, device_for
    if os.geteuid() != 0:
        sys.exit('需要 root（TREE_SEARCH 与读块设备都要求 CAP_SYS_ADMIN）')
    dev = args.dev or device_for(args.mount)
    if not dev:
        sys.exit('找不到 %s 所在的 btrfs 块设备，请用 --dev 指定' % args.mount)
    return Volume(dev), os.open(args.mount, os.O_RDONLY)


# ---------- 子命令 ----------
def cmd_freemap(args):
    vol, mfd = open_volume(args)
    tot = used = nchunks = ngaps = 0
    biggest = []
    for start, length, *_ in vol.chunks:
        gaps = free_gaps(mfd, start, length)
        free = sum(b - a for a, b in gaps)
        tot += length
        used += length - free
        nchunks += 1
        ngaps += len(gaps)
        biggest.append((free, start, length))
    biggest.sort(reverse=True)
    print(json.dumps({'data_chunks': nchunks, 'chunk_bytes': tot, 'used_bytes': used, 'free_bytes': tot - used,
                      'free_gaps': ngaps, 'top_free_chunks': biggest[:5]}, indent=1))


def load_targets(path):
    sizes = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            if len(parts) >= 2 and parts[0] in SIGS:
                sizes.setdefault(parts[0], set()).add(int(parts[1]))
    return sizes


def cmd_scan(args):
    vol, mfd = open_volume(args)
    sizes = load_targets(args.targets)
    if not sizes:
        sys.exit('targets 文件里没有可识别的行（类型<TAB>大小，类型取 %s）' % ' '.join(sorted(SIGS)))
    maxlen = {k: max(v) for k, v in sizes.items()}
    out = gzip.GzipFile(fileobj=sys.stdout.buffer, mode='wb')
    stat = {'scanned': 0, 'hits': 0, 'cands': 0}
    t0 = last = time.time()
    plan = []
    for start, length, *_ in vol.chunks:
        plan += free_gaps(mfd, start, length)
    total = sum(b - a for a, b in plan)
    log({'free_bytes_to_scan': total, 'gaps': len(plan)})
    for ga, gb in plan:
        base = (ga + BLK - 1) // BLK * BLK
        while base < gb:
            n = min(PIECE, gb - base)
            buf = vol.read(base, n)
            hits = set()
            for kind in sizes:
                for sig in SIGS[kind]:
                    i = buf.find(sig)
                    while i != -1:
                        # 文件总是从块边界开始；不在 4K 边界上的签名是别的文件内部的数据
                        if i % BLK == 0:
                            hits.add((i, kind))
                        i = buf.find(sig, i + 1)
            for i, kind in sorted(hits):
                addr = base + i
                # 候选不能越过空闲区间的结尾：后面是仍在使用的 extent，不可能是同一个旧文件
                win = min(maxlen[kind], gb - addr)
                w = buf[i:i + win] if i + win <= len(buf) else vol.read(addr, win)
                stat['hits'] += 1
                seen = set()
                for ln in LENGTHS[kind](w):
                    if ln in seen or ln not in sizes[kind] or ln > len(w):
                        continue
                    seen.add(ln)
                    d = w[:ln]
                    rec = {'addr': addr, 'len': ln, 'kind': kind,
                           'md5': hashlib.md5(d).hexdigest(), 'sha256': hashlib.sha256(d).hexdigest()}
                    out.write((json.dumps(rec) + '\n').encode())
                    stat['cands'] += 1
            base += n
            stat['scanned'] += n
            if time.time() - last > 30:
                last = time.time()
                el = last - t0
                log(dict(stat, pct=round(100 * stat['scanned'] / max(total, 1), 2),
                         mb_s=round(stat['scanned'] / 1e6 / max(el, 1), 1)))
                out.flush()
    out.close()
    log(dict(stat, done=True, seconds=int(time.time() - t0)))


def cmd_extract(args):
    vol, _ = open_volume(args)
    tar = tarfile.open(fileobj=sys.stdout.buffer, mode='w|', format=tarfile.PAX_FORMAT)
    manifest = []
    with open(args.picks, encoding='utf-8', errors='surrogateescape') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            if len(parts) < 3:
                continue
            addr, ln, name = int(parts[0]), int(parts[1]), parts[2]
            d = vol.read(addr, ln)
            ti = tarfile.TarInfo(name)
            ti.size = len(d)
            tar.addfile(ti, io.BytesIO(d))
            manifest.append({'member': name, 'addr': addr, 'len': ln,
                             'md5': hashlib.md5(d).hexdigest(), 'sha256': hashlib.sha256(d).hexdigest()})
    data = ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in manifest).encode('utf-8', 'surrogateescape')
    ti = tarfile.TarInfo('_carve_manifest.jsonl')
    ti.size = len(data)
    tar.addfile(ti, io.BytesIO(data))
    tar.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('cmd', choices=['freemap', 'scan', 'extract'])
    ap.add_argument('--mount', default='/volume1', help='卷的挂载点（TREE_SEARCH 在它上面查询 extent 树）')
    ap.add_argument('--dev', help='块设备，默认按挂载点识别')
    ap.add_argument('--image', help='测试模式：用普通文件代替 Btrfs 卷')
    ap.add_argument('--targets', help='scan：类型<TAB>原始大小 列表')
    ap.add_argument('--picks', help='extract：逻辑地址<TAB>长度<TAB>成员名 列表')
    args = ap.parse_args()
    if args.cmd == 'scan' and not args.targets:
        sys.exit('scan 需要 --targets')
    if args.cmd == 'extract' and not args.picks:
        sys.exit('extract 需要 --picks')
    {'freemap': cmd_freemap, 'scan': cmd_scan, 'extract': cmd_extract}[args.cmd](args)


if __name__ == '__main__':
    main()
