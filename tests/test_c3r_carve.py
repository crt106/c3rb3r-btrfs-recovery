"""c3r_carve.py 的离线测试：用 --image 测试模式扫描一个合成的"空闲空间"镜像。

在仓库根目录运行：python3 -m unittest
"""
import gzip
import hashlib
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       'skills', 'c3rb3r-btrfs-recovery', 'scripts')
sys.path.insert(0, SCRIPTS)
import c3r_carve  # noqa: E402

CARVE = os.path.join(SCRIPTS, 'c3r_carve.py')
MKJOB = os.path.join(SCRIPTS, 'mkjob.py')
BLK = 4096
RNG = random.Random(4242)


def noise(n):
    return bytes(RNG.getrandbits(8) for _ in range(n))


def make_pdf(n_body, incremental=False):
    d = b'%PDF-1.4\n' + noise(n_body) + b'\n%%EOF\n'
    if incremental:
        # 增量保存：中间已有一个 %%EOF，真正的结尾在后面
        d += noise(n_body // 2) + b'\n%%EOF\r\n'
    return d


def make_jpg(n_body):
    return b'\xff\xd8\xff\xe0' + noise(n_body).replace(b'\xff', b'\x00') + b'\xff\xd9'


def make_png(n_body):
    ihdr = b'\0\0\0\x0dIHDR' + noise(17)
    return b'\x89PNG\r\n\x1a\n' + ihdr + noise(n_body) + b'\0\0\0\0IEND\xaeB`\x82'


def make_zip(n_files):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w', zipfile.ZIP_STORED) as z:
        for k in range(n_files):
            z.writestr('part%d.bin' % k, noise(1500))
    return bio.getvalue()


def make_bmp(n_pixels):
    body = noise(n_pixels)
    return b'BM' + struct.pack('<IHHI', 14 + 40 + len(body), 0, 0, 54) + b'\0' * 40 + body


def make_ole(n_sectors):
    """最小的 OLE2：512 字节扇区，1 个 FAT 扇区（扇区 0），后面 n_sectors 个数据扇区。"""
    hdr = bytearray(512)
    hdr[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    struct.pack_into('<H', hdr, 0x1E, 9)
    struct.pack_into('<I', hdr, 0x2C, 1)
    struct.pack_into('<109I', hdr, 0x4C, 0, *([0xFFFFFFFF] * 108))
    fat = [0xFFFFFFFD] + list(range(2, n_sectors + 1)) + [0xFFFFFFFE]
    fat += [0xFFFFFFFF] * (128 - len(fat))
    return bytes(hdr) + struct.pack('<128I', *fat) + noise(512 * n_sectors)


class SyntheticImage:
    """把文件按块放进一段随机数据里，记录哪些应当被找到。"""

    def __init__(self, nblocks):
        self.buf = bytearray(noise(nblocks * BLK))
        self.expect = []    # (addr, kind, data)
        self.targets = []   # (kind, size)

    def put(self, block, kind, data, offset=0, expect=True, target=True):
        addr = block * BLK + offset
        assert addr + len(data) <= len(self.buf)
        self.buf[addr:addr + len(data)] = data
        if expect:
            self.expect.append((addr, kind, data))
        if target:
            self.targets.append((kind, len(data)))
        return addr


class CarveScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        img = SyntheticImage(200)
        cls.pdf = img.put(2, 'pdf', make_pdf(6000))
        img.put(6, 'pdf', make_pdf(5000, incremental=True))
        img.put(12, 'jpg', make_jpg(9000))
        img.put(20, 'zip', make_zip(3))
        img.put(26, 'png', make_png(7000))
        img.put(32, 'bmp', make_bmp(5000))
        img.put(36, 'ole', make_ole(6))
        # 诱饵 1：完整的 JPEG，但不在 4K 边界上（是别的文件内部的数据）
        img.put(50, 'jpg', make_jpg(3000), offset=100, expect=False)
        # 诱饵 2：PDF 开头在块边界上，但后半段已被别的数据覆盖，没有 %%EOF
        trunc = make_pdf(7000)
        img.put(60, 'pdf', trunc[:4000], expect=False, target=False)
        img.targets.append(('pdf', len(trunc)))
        # 诱饵 3：完整的 PNG，但原始大小不在 targets 里（不是我们要找的文件）
        img.put(70, 'png', make_png(2000), expect=False, target=False)
        # 诱饵 4：BMP 头里写的长度越过了空闲区间的结尾（后面是仍在使用的数据）
        b = make_bmp(9000)
        img.buf[198 * BLK:199 * BLK] = b[:BLK]
        img.targets.append(('bmp', len(b)))
        # 诱饵 5：ZIP 从镜像最后一块开始，被空闲区间的结尾截断
        z = make_zip(4)
        img.buf[199 * BLK:] = z[:BLK]
        img.targets.append(('zip', len(z)))
        cls.img = img
        cls.image = os.path.join(cls.tmp, 'free.img')
        with open(cls.image, 'wb') as f:
            f.write(img.buf)
        cls.targets = os.path.join(cls.tmp, 'targets.tsv')
        with open(cls.targets, 'w') as f:
            f.write('# 注释行与未知类型应被忽略\nxyz\t123\n')
            f.writelines('%s\t%d\n' % t for t in img.targets)
        p = subprocess.run([sys.executable, CARVE, 'scan', '--image', cls.image, '--targets', cls.targets],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        cls.cands = [json.loads(l) for l in gzip.decompress(p.stdout).decode().splitlines()]
        cls.log = [json.loads(l) for l in p.stderr.decode().splitlines()]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_finds_every_aligned_complete_file(self):
        got = {(c['addr'], c['kind'], c['len']) for c in self.cands}
        for addr, kind, data in self.img.expect:
            self.assertIn((addr, kind, len(data)), got, kind)

    def test_no_decoys(self):
        want = {(a, k, len(d)) for a, k, d in self.img.expect}
        extra = [c for c in self.cands if (c['addr'], c['kind'], c['len']) not in want]
        self.assertEqual(extra, [])

    def test_hashes(self):
        by = {c['addr']: c for c in self.cands}
        for addr, _, data in self.img.expect:
            self.assertEqual(by[addr]['md5'], hashlib.md5(data).hexdigest())
            self.assertEqual(by[addr]['sha256'], hashlib.sha256(data).hexdigest())

    def test_progress_log(self):
        self.assertEqual(self.log[0]['free_bytes_to_scan'], len(self.img.buf))
        self.assertTrue(self.log[-1]['done'])
        self.assertEqual(self.log[-1]['cands'], len(self.cands))

    def test_extract_roundtrip(self):
        picks = os.path.join(self.tmp, 'picks.tsv')
        with open(picks, 'w', encoding='utf-8') as f:
            for addr, kind, data in self.img.expect:
                f.write('%d\t%d\tvolume1/share/目录/f%d.%s\n' % (addr, len(data), addr, kind))
        p = subprocess.run([sys.executable, CARVE, 'extract', '--image', self.image, '--picks', picks],
                           stdout=subprocess.PIPE, check=True)
        members = {}
        with tarfile.open(fileobj=io.BytesIO(p.stdout), mode='r|') as t:
            for m in t:
                members[m.name] = t.extractfile(m).read()
        manifest = [json.loads(l) for l in members.pop('_carve_manifest.jsonl').decode().splitlines()]
        self.assertEqual(len(members), len(self.img.expect))
        for addr, kind, data in self.img.expect:
            self.assertEqual(members['volume1/share/目录/f%d.%s' % (addr, kind)], data)
        for r in manifest:
            self.assertEqual(r['sha256'], hashlib.sha256(members[r['member']]).hexdigest())

    def test_freemap_image(self):
        p = subprocess.run([sys.executable, CARVE, 'freemap', '--image', self.image],
                           stdout=subprocess.PIPE, check=True)
        r = json.loads(p.stdout)
        self.assertEqual(r['free_bytes'], len(self.img.buf))
        self.assertEqual(r['used_bytes'], 0)


class GapTest(unittest.TestCase):
    def test_gaps_between(self):
        g = c3r_carve.gaps_between
        self.assertEqual(g(0, 100, []), [(0, 100)])
        self.assertEqual(g(0, 100, [(0, 10), (10, 5), (30, 20), (90, 10)]), [(15, 30), (50, 90)])
        # 重叠项、超出 chunk 两端的项
        self.assertEqual(g(100, 200, [(50, 60), (120, 30), (130, 10), (190, 50)]), [(110, 120), (150, 190)])
        self.assertEqual(g(0, 100, [(0, 100)]), [])


class LengthTest(unittest.TestCase):
    def test_pdf_line_endings(self):
        w = b'%PDF-1.7\n...%%EOF\r\nXX'
        self.assertEqual(sorted(set(c3r_carve.lengths_pdf(w))), [17, 18, 19])

    def test_bmp_rejects_random_bm(self):
        self.assertEqual(list(c3r_carve.lengths_bmp(b'BM\x10\0\0\0\x01\0\0\0' + b'\0' * 10)), [])

    def test_ole_length(self):
        d = make_ole(6)
        self.assertEqual(list(c3r_carve.lengths_ole(d + noise(2000))), [len(d)])


@unittest.skipUnless(shutil.which('sh') and shutil.which('base64'), 'needs sh and base64')
class MkjobCarveTest(unittest.TestCase):
    def test_job_runs_carver(self):
        tmp = tempfile.mkdtemp()
        try:
            img = os.path.join(tmp, 'free.img')
            data = make_pdf(3000)
            with open(img, 'wb') as f:
                f.write(noise(BLK) + data + noise(3 * BLK))
            targets = os.path.join(tmp, 'targets.tsv')
            with open(targets, 'w') as f:
                f.write('pdf\t%d\n' % len(data))
            job = subprocess.run([sys.executable, MKJOB, '--tool', 'carve', '--list', targets, '--',
                                  'scan', '--image', img, '--targets', '@LIST'],
                                 stdout=subprocess.PIPE, check=True).stdout
            self.assertIn(b'__C3R_TOOL__', job)
            self.assertIn(b'__C3R_CARVE__', job)
            self.assertNotIn(b'\r\n', job)
            p = subprocess.run(['sh', '-s'], input=job, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            cands = [json.loads(l) for l in gzip.decompress(p.stdout).decode().splitlines()]
            self.assertEqual([(c['addr'], c['len']) for c in cands], [(BLK, len(data))])
        finally:
            shutil.rmtree(tmp)


if __name__ == '__main__':
    unittest.main()
