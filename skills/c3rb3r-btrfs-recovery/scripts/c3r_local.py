#!/usr/bin/env python3
"""本地端：接收 c3r_btrfs.py 的输出，解包、验证、挑选最佳候选、生成统计。

依赖：Python 3.8+；可选 Pillow（图片完整解码）、pillow-heif（HEIC）、ffmpeg（视频/音频解码，需在 PATH 中）。
没有这些依赖时对应格式记为 not_checked，不会误判为失败。

子命令：
  extract  STREAM.tar|-  OUT_DIR          解包 tar 流（- 为 stdin），边写边算 SHA-256 -> OUT_DIR/_extracted.jsonl
  validate OUT_DIR [--known DIR ...] [--workers N]
                                          核对 SHA、完整解码、与已知原件对照，为每个源文件选最佳候选
                                          -> _validation.jsonl、_best.jsonl、_summary.json
  apply-patch  DIR                       把 *.c3rpatch 打到同名已导出文件上（原字节存 *.c3rbak）
  revert-patch DIR [--only FILE]          用 *.c3rbak 回退补丁
  report   SURVEY.jsonl.gz [--depth N]   按目录层级汇总 survey 结果（文件数 / 原始字节）
"""
import argparse
import collections
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

IMG = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tif', '.tiff', '.heic', '.heif'}
AV = {'.mp4', '.mov', '.m4v', '.avi', '.mkv', '.3gp', '.mts', '.m2ts', '.ts', '.wmv', '.flv', '.webm',
      '.mp3', '.flac', '.m4a', '.aac', '.wav', '.ogg'}
# ffmpeg 输出到空 muxer 时，iPhone 可变帧率视频会触发这类时间戳警告，与数据完整性无关
BENIGN = (b'non monotonically increasing dts to muxer', b'Last message repeated',
          b'Decoding requested, but no decoder found')


def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(8 << 20), b''):
            h.update(b)
    return h.hexdigest()


def decode(p):
    ext = p.suffix.lower()
    if ext in IMG:
        try:
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = None
            try:
                from pillow_heif import register_heif_opener
                register_heif_opener()
            except ImportError:
                if ext in ('.heic', '.heif'):
                    return 'not_checked'
        except ImportError:
            return 'not_checked'
        try:
            with Image.open(p) as im:
                im.load()
            return 'decoded'
        except Exception as e:
            return 'decode_error: %s' % e
    if ext in AV:
        if not shutil.which('ffmpeg'):
            return 'not_checked'
        r = subprocess.run(['ffmpeg', '-v', 'error', '-xerror', '-i', str(p), '-f', 'null', '-'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        err = b'\n'.join(l for l in r.stderr.splitlines() if not any(k in l for k in BENIGN))
        return 'decoded' if r.returncode == 0 and not err.strip() else 'decode_error: %s' % err[:300].decode('utf-8', 'replace')
    return 'not_checked'


def cmd_extract(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    src = sys.stdin.buffer if args.stream == '-' else open(args.stream, 'rb')
    n = 0
    with tarfile.open(fileobj=src, mode='r|') as tar, open(out / '_extracted.jsonl', 'a', encoding='utf-8') as log:
        for m in tar:
            parts = Path(m.name).parts
            if not m.isfile() or '..' in parts or Path(m.name).is_absolute():
                continue
            dest = out / m.name
            dest.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha256()
            with tar.extractfile(m) as f, open(dest, 'wb') as d:
                for b in iter(lambda: f.read(8 << 20), b''):
                    h.update(b)
                    d.write(b)
            log.write(json.dumps({'name': m.name, 'size': m.size, 'sha256': h.hexdigest()}, ensure_ascii=False) + '\n')
            log.flush()
            n += 1
    print('extracted %d members -> %s' % (n, out))


def known_index(dirs):
    idx = {}
    for d in dirs or []:
        for p in Path(d).rglob('*'):
            if p.is_file():
                size = p.stat().st_size
                names = {p.name.lower()}
                head, sep, rest = p.name.partition('-')
                if sep and head.isdigit():
                    names.add(rest.lower())   # 兼容整理时加的 "0056-原名" 序号前缀
                for nm in names:
                    idx.setdefault((nm, size), []).append(p)
    return idx


def check(job):
    rec, p, ext_sha, known = job
    row = {'path': rec['path'], 'member': rec['member'], 'variant': rec['variant'], 'status': rec['status'],
           'bytes': rec.get('bytes')}
    if ext_sha is None and p.exists():
        ext_sha = sha256(p)
    row['sha_ok'] = ext_sha == rec['sha256'] and p.exists()
    row['decode'] = decode(p) if row['sha_ok'] else 'missing'
    if known:
        # 同名同大小可能有多个副本；任一一致即算一致，全部不一致才算不一致（本地副本本身也可能有坏块）
        row['known_original_match'] = any(sha256(k) == rec['sha256'] for k in known)
    ok = row['sha_ok'] and row['decode'] in ('decoded', 'not_checked')
    row['verdict'] = 'ok' if ok else 'bad'
    return row


def cmd_validate(args):
    out = Path(args.out)
    manifest = [json.loads(l) for l in open(out / '_c3r_manifest.jsonl', encoding='utf-8')]
    extracted = {}
    if (out / '_extracted.jsonl').exists():
        for l in open(out / '_extracted.jsonl', encoding='utf-8'):
            r = json.loads(l)
            extracted[r['name']] = r['sha256']
    known = known_index(args.known)
    jobs, skipped = [], collections.Counter()
    for rec in manifest:
        if 'member' not in rec:
            skipped[rec['status']] += 1
            continue
        orig_name = os.path.basename(rec['path'])[:-len('.L0CK3D')]
        jobs.append((rec, out / rec['member'], extracted.get(rec['member']), known.get((orig_name.lower(), rec['orig']))))
    with ProcessPoolExecutor(args.workers) as ex:
        rows = list(ex.map(check, jobs, chunksize=4))
    with open(out / '_validation.jsonl', 'w', encoding='utf-8') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    by_src = collections.defaultdict(list)
    for r in rows:
        by_src[r['path']].append(r)
    outcomes, best = collections.Counter(), []
    for src, rs in by_src.items():
        good = [r for r in rs if r['verdict'] == 'ok']
        pick = next((r for r in good if r.get('known_original_match')), good[0] if good else rs[0])
        if not good:
            kind = 'failed'
        elif pick['status'] == 'exact':
            kind = 'exact_' + ('decoded' if pick['decode'] == 'decoded' else 'sha_only')
        elif pick['status'] == 'needs_inference':
            kind = 'inferred_decoded' if pick['decode'] == 'decoded' else 'inferred_unverifiable'
        else:
            kind = 'partial_' + ('decoded' if pick['decode'] == 'decoded' else 'unverified')
        if len(good) > 1 and pick['status'] != 'exact':
            kind += '_multi_candidates_ok'
        outcomes[kind] += 1
        best.append(dict(pick, outcome=kind, candidates=len(rs)))
    with open(out / '_best.jsonl', 'w', encoding='utf-8') as f:
        for r in best:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    km = collections.Counter(r.get('known_original_match') for r in rows if 'known_original_match' in r)
    summary = {'sources': len(by_src), 'outcomes': dict(outcomes), 'not_extracted': dict(skipped),
               'known_original_match': {str(k): v for k, v in km.items()},
               'note': 'exact 段若来自开启校验和的共享，应再用 c3r_btrfs.py csum 逐块证实；'
                       'exact 文件解码报错可能是原文件固有问题；known_original_match=False 时先怀疑本地副本'}
    (out / '_summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=1))


def _records(path):
    import struct
    with open(path, 'rb') as f:
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                return
            off, ln = struct.unpack('<QQ', hdr)
            yield off, f.read(ln)


def cmd_apply_patch(args):
    """把 c3r_btrfs.py patch 导出的 *.c3rpatch 打到同名已导出文件上；被覆盖的原字节存为 *.c3rbak，可用 revert-patch 回退。"""
    import struct
    root = Path(args.dir)
    done = 0
    for pf in root.rglob('*.c3rpatch'):
        target = Path(str(pf)[:-len('.c3rpatch')].rsplit('.', 1)[0])
        bak = Path(str(target) + '.c3rbak')
        if not target.exists() or bak.exists():
            continue
        with open(target, 'r+b') as t, open(bak, 'wb') as b:
            for off, data in _records(pf):
                t.seek(off)
                old = t.read(len(data))
                b.write(struct.pack('<QQ', off, len(old)) + old)
                t.seek(off)
                t.write(data)
        done += 1
    print('patched %d files' % done)


def cmd_revert_patch(args):
    root = Path(args.dir)
    n = 0
    for bak in root.rglob('*.c3rbak'):
        target = Path(str(bak)[:-len('.c3rbak')])
        if args.only and str(target) not in set(args.only):
            continue
        with open(target, 'r+b') as t:
            for off, data in _records(bak):
                t.seek(off)
                t.write(data)
        bak.unlink()
        n += 1
    print('reverted %d files' % n)


def cmd_report(args):
    rows = [json.loads(l) for l in gzip.open(args.survey, 'rt', encoding='utf-8', errors='surrogateescape')]
    c, b, eb = collections.Counter(), collections.Counter(), collections.Counter()
    for x in rows:
        parts = x['path'].strip('/').split('/')
        meta = any(s in ('@eaDir', '#recycle') for s in parts)
        key = ('/'.join(parts[:args.depth]), 'meta' if meta else 'file', x['status'])
        c[key] += 1
        b[key] += x.get('orig', 0)
        for k, v in (x.get('bytes') or {}).items():
            eb[(key, k)] += v
    tot, totb = collections.Counter(), collections.Counter()
    print('%-60s %-5s %-20s %9s %10s' % ('dir', 'kind', 'status', 'files', 'GB'))
    for key in sorted(c, key=lambda k: (k[0], -b[k])):
        print('%-60s %-5s %-20s %9d %10.2f' % (key[0][:60], key[1], key[2], c[key], b[key] / 1e9))
        if key[1] == 'file':
            tot[key[2]] += c[key]
            totb[key[2]] += b[key]
    print('\n总计（不含 @eaDir/#recycle）：')
    for s in sorted(tot, key=lambda s: -totb[s]):
        print('  %-22s %9d 个  %10.2f GB' % (s, tot[s], totb[s] / 1e9))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    e = sub.add_parser('extract')
    e.add_argument('stream')
    e.add_argument('out')
    v = sub.add_parser('validate')
    v.add_argument('out')
    v.add_argument('--known', action='append', help='已知原件目录（同名同大小即对照），可多次')
    v.add_argument('--workers', type=int, default=max(1, (os.cpu_count() or 2) // 2))
    a = sub.add_parser('apply-patch')
    a.add_argument('dir')
    rv = sub.add_parser('revert-patch')
    rv.add_argument('dir')
    rv.add_argument('--only', action='append', help='只回退这些目标文件（完整路径）')
    r = sub.add_parser('report')
    r.add_argument('survey')
    r.add_argument('--depth', type=int, default=3)
    args = ap.parse_args()
    {'extract': cmd_extract, 'validate': cmd_validate, 'report': cmd_report,
     'apply-patch': cmd_apply_patch, 'revert-patch': cmd_revert_patch}[args.cmd](args)


if __name__ == '__main__':
    main()
