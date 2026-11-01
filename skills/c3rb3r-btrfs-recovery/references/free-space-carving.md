# 空闲空间雕刻：找回被整体加密的小文件

`survey` 里的 `no_candidate` 多半是 1MiB 以下、被**整体**加密的小文件：扫描件 PDF、Office 文档、小 JPEG、PNG。
整个文件被改写后，CoW 把密文写到新位置，旧 extent 不再被任何文件引用，于是被释放。释放只是 extent 树里少了一项，
**原始字节还留在盘上，直到这块空间被重新分配**。`scripts/c3r_carve.py` 只读这些空闲区间，按签名和原始大小找回候选。

和 extent 重组不同，这里**没有 Btrfs 校验和可以证实**（空闲块的 csum 项随 extent 一起删掉了），
空闲空间里还混着攻击前就删掉的文件、旧版本和临时文件。所以本方法的核心不是"找到"，而是"判定候选属于哪个文件"。

## 什么时候值得做

- `survey` 中 `no_candidate` 数量可观，而且这些文件对用户重要（文档、照片）。
- **机械盘，或者没有 TRIM / discard**。SSD 卷开了 TRIM 后，释放的块会被丢弃，读出来是全 0，雕刻没有意义。先 `freemap`，再抽几段空闲区读一下看是不是全 0。
- **空闲空间多、事发后写入少**。卷越满、事发后写入越多（导出到同一个卷、Docker、录像、索引），被复用的越多。
- 不适用：`inplace_lost`（NoCOW 原地覆盖，没有旧副本）、`compressed`、`inline`。

## 开始之前

1. **关掉 DSM 存储管理器里卷的定时"空间回收"（Space Reclamation）**，雕刻和导出期间不要手动运行。它在后台整理、回收空间，属于不必要的写入，在 SSD 上还可能触发 discard。
2. 照常停掉 Container Manager、Surveillance Station、Photos 索引、同步任务。
3. extent 重组的导出先做完。雕刻只读，但耗时很长，期间 NAS 不应再有写入。

## 流程

```bash
cd scripts
# 1. 空闲空间概况（只做 ioctl，几秒到几分钟）
python mkjob.py --tool carve -- freemap --mount /volume1 > job.sh
# 2. 从 survey 生成 targets.tsv（本地，见下）
# 3. 扫描（顺序读全部空闲区，机械盘上 TB 级空闲空间要数小时）
python mkjob.py --tool carve --list targets.tsv -- scan --targets @LIST > job.sh
{ printf '%s\n' "$SUDO_PW"; cat job.sh; } | ssh USER@NAS "sudo -S -p '' sh -s" > candidates.jsonl.gz 2> scan.log
# 4. 本地判定，写 picks.tsv（逻辑地址<TAB>长度<TAB>成员名）
# 5. 导出选中的候选，边传边解包
python mkjob.py --tool carve --list picks.tsv -- extract --picks @LIST > job.sh
{ printf '%s\n' "$SUDO_PW"; cat job.sh; } | ssh USER@NAS "sudo -S -p '' sh -s" | python c3r_local.py extract - OUT_DIR
```

`scan.log` 每 30 秒一行 JSON 进度（已扫字节、百分比、MB/s）。`tail -1 scan.log` 即可查看。

生成 targets 的最简单做法（类型由扩展名决定，`zip` 也涵盖 docx/xlsx/pptx/odt 等，`ole` 是老式 doc/xls/ppt/msg）：

```python
import gzip, json, os
KIND = {'.pdf': 'pdf', '.jpg': 'jpg', '.jpeg': 'jpg', '.png': 'png', '.bmp': 'bmp', '.zip': 'zip',
        '.docx': 'zip', '.xlsx': 'zip', '.pptx': 'zip', '.odt': 'zip', '.ods': 'zip', '.epub': 'zip',
        '.doc': 'ole', '.xls': 'ole', '.ppt': 'ole', '.msg': 'ole'}
pairs = set()
for line in gzip.open('survey.jsonl.gz', 'rt', encoding='utf-8', errors='surrogateescape'):
    r = json.loads(line)
    if r.get('status') == 'no_candidate':
        k = KIND.get(os.path.splitext(r['path'][:-len('.L0CK3D')])[1].lower())
        if k:
            pairs.add((k, r['orig']))
open('targets.tsv', 'w').writelines('%s\t%d\n' % p for p in sorted(pairs))
```

工具的规则：签名必须落在 4KiB 边界上（文件总是从块开头存放），候选长度必须**恰好等于**某个丢失文件的原始大小，
而且不能越过空闲区间的结尾。每个候选带 MD5 和 SHA-256。

## 判定候选属于哪个文件

按证据强弱排列。每个结果都要记下用的是哪一种证据。

### 1. 应用自己存的校验和（最强）

很多应用在数据库里给每个文件存了哈希，候选的哈希与之相等，就是逐字节证实：

- 文档管理系统：Paperless-ngx 的 `documents_document` 表存原件 MD5（`checksum`）和归档 PDF 的 MD5（`archive_checksum`），一行里同时有文件名，能直接映射回路径；Mayan EDMS 存 SHA-256。
- 照片管理：Immich、PhotoPrism 等存 SHA-1。雕刻工具只算 MD5 和 SHA-256，这类情况要先把同大小的候选导出，再在本地算 SHA-1。

应用的数据库文件本身一般被整体加密了，但**数据库转储**往往大于 1MiB，可能已被 exact 恢复：升级前手动做的转储、定时备份任务生成的 `.dump` / `.sql.gz`、应用自带导出功能的 manifest。转储比雕刻结果旧时，转储之后新增的文件没有哈希，只能用下面的方法。

**不装 PostgreSQL 读 custom 格式转储（`pg_dump -Fc`）**：每个表的数据是一串"长度 + zlib 压缩数据"的小段，以长度 0 结尾；
解压后就是 COPY 文本（制表符分隔，`\N` 表示 NULL）。下面的脚本把所有表数据还原成文本行，再按 32 位十六进制串筛出带 MD5 的行：

```python
import re, sys, zlib

def copy_rows(path):
    """从 pg_dump -Fc（zlib 压缩）的转储里取出所有表数据的 COPY 文本行，不需要 PostgreSQL。"""
    b = open(path, 'rb').read()
    assert b[:5] == b'PGDMP', '不是 custom 格式转储'
    isz = b[8]                       # 头部：PGDMP, 版本 3 字节, intSize, offSize, format
    def rd_int(p):                   # 1 个符号字节 + intSize 字节小端
        v = int.from_bytes(b[p + 1:p + 1 + isz], 'little')
        return (-v if b[p] else v), p + 1 + isz
    i = 0
    while True:
        i = b.find(b'\x78', i + 1)
        if i < 0:
            return
        p = i - 1 - isz              # 每个数据块是一串 [长度][压缩数据] 小段，以长度 0 结尾
        if p < 0 or b[p] != 0 or b[i + 1] not in (0x01, 0x5e, 0x9c, 0xda):
            continue
        z, out, q = zlib.decompressobj(), [], p
        try:
            while True:
                n, q = rd_int(q)
                if n <= 0 or q + n > len(b):
                    break
                out.append(z.decompress(b[q:q + n]))
                q += n
            if not z.eof:
                continue
        except zlib.error:
            continue
        yield from b''.join(out).decode('utf-8', 'replace').splitlines()
        i = q

for line in copy_rows(sys.argv[1]):
    if re.search(r'\b[0-9a-f]{32}\b', line):
        print(line)
```

列的顺序看 TOC 里的 `COPY ... (列名, ...) FROM stdin;`（在转储开头部分，是明文）。用 `-Z0` 做的未压缩转储可以直接按文本搜；
PostgreSQL 16 以上用 lz4 / zstd 压缩的转储，需要同版本或更新的 `pg_restore -f - --data-only 转储文件`（只需要客户端程序，不需要服务器）。

### 2. 大小唯一

某个类型、某个大小，只对应**一个**丢失文件，扫描也只找到**一个**候选。这已经相当可靠，但仍可能是同一文件的旧版本或早就删掉的副本，
所以还要做第 5、6 项检查。同一大小有多个候选时，相同哈希的候选是同一份数据的多个副本，可以合并；哈希不同才是真正的歧义。

### 3. 盘上位置：与同目录文件挨在一起

同一批写入的文件（一次导入、一次拷贝、相机一次同步）在盘上通常是连续分配的，被加密释放后，它们的旧 extent 仍然挨在一起。
据此给有歧义的候选打分：

- 锚点：同一目录里已经确定的文件——第 1、2 项判定过的候选地址，或者 exact 恢复的文件原来的 extent 地址（`plan` 可以看到）。
- 候选离同目录锚点越近越可信。只有当一个候选明显比其他候选近（例如相差一个数量级以上）时才采用，否则标为"不确定"。
- 没有任何锚点的目录不要硬猜。

在第一个用上这套方法的案例里，按"大小 + 位置"判定的结果拿独立原件核对，九成以上正确，但仍有几个百分点配错了。所以这一类必须单独登记，能找到原件的要换成原件。

### 4. 原件与派生文件成对出现

一些应用会**同时**写两个相关文件，它们的候选也会挨在一起，互相印证：

- 文档管理系统的原件和 OCR 后的归档 PDF（大小不同，但地址相邻）；
- 相机的 RAW + JPEG、照片与 XMP 旁车文件、视频与缩略图。

一对里有一个已经确定（比如有哈希），另一个就有了很强的位置锚点。

### 5. EXIF 年份与目录

照片按年份或日期分目录存放时，候选的 EXIF 拍摄时间应该落在目录对应的时间段里。不一致的，多半是配错了，或者是别处的同大小照片，要降级为"不确定"。

### 6. 完整解码

用 `c3r_local.py validate` 做完整解码，PDF 至少检查开头 `%PDF` 和结尾 `%%EOF`，ZIP 跑 `unzip -t`。
解码通过是**必要条件，不是证据**：同样大小的另一张完好照片也能解码。

## 用独立原件验证

拿手机、相机卡、旧硬盘、云盘里的副本，先按文件名 + 大小找对应，再比 SHA-256：

- 按证据类别分别统计"一致 / 不一致"，在报告里写出每一类的实测错配率，而不是只写"已恢复 N 个"。
- 配错的换成原件；雕刻结果里没有、但原件里有的，直接补上。
- 同名同大小却有几个内容不同的原件时，标为"不确定"，不要随便挑一个。
- exact 恢复的文件也抽一部分对一下，作为整条流程的对照组。

## 汇总到一个目录

各种来源（extent 重组、推测候选、雕刻、外部原件）最后汇总到**一个**目录里，按原路径存放，方便用户直接使用：

- 一份来源日志（TSV）：每个文件一行，写清来源、证据类别、是否不确定。
- 不确定的文件留在原位置，但在扩展名前加标记，例如 `name.__uncertain__.jpg`：仍然能直接打开，也能用 `find -name '*.__uncertain__.*'` 一次列出。
- 从不覆盖：目标已存在时加 `.__duplicate__` 之类的标记。
- 先空跑只打印统计，确认后再移动；记一份移动日志以便回退。
- 比对文件名前统一做 Unicode NFC 规范化（见 pitfalls 中 exFAT / macOS 一条）。
