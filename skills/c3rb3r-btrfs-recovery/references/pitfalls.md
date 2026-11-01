# 实战踩过的坑（排查清单）

| 现象 | 原因 | 处理 |
|---|---|---|
| 用 FIEMAP 相邻 delta 重组的大视频报"moov atom not found" | 加密段跨越了一块已被完全覆盖并释放的 128MiB 原 extent，相邻 delta 推算读到了别的数据 | 改用 EXTENT_DATA 树（`c3r_btrfs.py`）区分 exact 和 infer，后者需要解码裁决 |
| csum 核对几乎全是"无记录"，自检为 0 | 用了 TREE_SEARCH V1，4KB 缓冲装不下单个 csum 项（最大约 16KB），内核返回 0 项 | 用 TREE_SEARCH_V2 配 1MB 缓冲（脚本已处理） |
| 普查时 NoCOW 文件全部被跳过 | 早期脚本见到 +C 属性就直接排除 | NoCOW 只是一个标签。子卷 lastsnap 之前的数据仍会 CoW，必须照常分析 |
| 小文件被列为"需要推测"，数量巨大 | 整文件加密时文件内没有任何旧 extent 可供外推 | 归为 no_candidate（脚本已处理），不要计入"可恢复" |
| exact 文件和"已知原件"有一个 4K 块不同 | 本地副本本身有坏块，或是另一个版本 | 用 csum 判定：NAS 侧逐块一致，说明恢复结果才是对的 |
| exact 文件 ffmpeg 解码报错（cu_qp_delta、slice_qp、SEI truncated、AC3 incomplete frame、PNG truncated） | 原文件本身就有这些问题 | csum 一致即算成功；NoCOW 共享无 csum 时注明"原文件可能固有问题" |
| 大量"non monotonically increasing dts to muxer"导致误判失败 | ffmpeg 输出到 null muxer 时，iPhone 可变帧率视频会触发时间戳警告 | 过滤这类良性警告（`c3r_local.py` 已处理），并去掉随之出现的 "Last message repeated" |
| HEIC 全部"无法识别" | 缺少 pillow-heif | 安装 pillow-heif；没有它时应记为 not_checked，而不是失败 |
| 传输停在约 100MB | paramiko 窗口或流控问题 | 改用原生 OpenSSH |
| ssh 报 Connection reset | 命令行参数过长（内嵌了 base64 列表） | 用 stdin 传作业（`mkjob.py`） |
| 远端报 `set: -: invalid option` | 在 Windows 上生成的脚本是 CRLF 换行 | 按字节写出 LF |
| 目标盘写入极慢、磁盘占用率显示 1000% | 近满的 SATA SSD（SLC 缓存耗尽） | 换盘；写入前先测速 |
| 验证阶段 E 盘几乎没有写入、NAS 闲置 | 导出和单线程验证串行执行 | 拆开，验证多进程并行 |
| ssh "Permission denied" 后导出为空 | 自动化时忘了传密码环境变量 | 每次检查 `.err` 输出和 tar 是否为空，不要只看退出码 |
| `25142000` 等未知模式 | 百分比参数不是 0x0a，公式未知 | 改写范围由新 extent 推出；若根本没有新 extent，多为 NoCOW 原地覆盖 |
| 选错 G | 采样只覆盖了单个目录 | 多个共享一起采样；确认 G 以下存在代数空档；边界自校验会暴露错误 |
| 推测类压缩包大量 CRC 失败，换 next 候选也不行 | 释放的原 extent 已被复用（数据区接近写满时很常见） | 接受现实：抢救未受影响的成员；不要反复猜参数 |
| 压缩包测试被误判为"分卷"等 | 按输出文字关键词分类时，路径里的 `/volume1/` 命中了 "volume" | 按 `Total errors: N` 和明确的错误信息分类 |
| `inline` 状态 | 2KB 左右的小文件内联存放在元数据里，元数据也 CoW，旧的叶子节点多半已被复用 | 一般放弃；可以考虑 btrfs-find-root 加旧树根，属于专家级个案 |
| `compressed` 状态 | 共享启用了透明压缩，extent 内是压缩数据 | 需要按 extent 读出整块再解压（zlib、lzo、zstd），本工具未实现 |
| 输出目录里有 `homes`、`volume1` 等不同前缀 | 不同版本脚本的成员名基准不同 | 本工具统一以 `/` 为基准，成员名形如 `volume1/...` |
| `gens` 给出的 `pos0_gen_min` 很老，G 明显偏小 | 采样里混进了 NoCOW 共享：原地覆盖的文件开头仍指向原来的 extent，代数是写入原件时的 | `gens` 只采样 CoW 共享（`env` 里 `nocow` 为 false 的）；NoCOW 共享单独按 lastsnap 分析 |
| `/volume1/docker` 之类的共享被漏掉 | 误以为是系统目录。默认 `--exclude` 跳过的是 DSM 内部的 `@docker`，而 Container Manager 的数据共享是普通共享，里面常有数据库转储、文档和照片库 | 和其他共享一样 `survey`；其中的数据库转储可能被 exact 恢复，雕刻时能当校验和来源（见 `free-space-carving.md`） |
| 空闲空间雕刻找到的候选越来越少，或同一位置前后两次扫描结果不同 | DSM 存储管理器里卷的定时"空间回收"在后台运行 | 雕刻和导出期间关掉定时空间回收，也不要手动触发 |
| 全量 `csum` 要跑好几天 | CRC32C 用纯 Python 计算，低功耗 NAS CPU 上很慢 | 做分层抽样：按共享、大小档、状态各抽一批文件，每个文件核对全部块；报告中写明是抽样及样本量 |
| 后台作业的 stderr 日志一直是空的，结束时才一次性出现 | DSM 7 的 Python 3.8 在 stderr 被重定向到文件时整块缓冲（3.9 起才改为行缓冲） | 进度输出后显式 `flush()`（`c3r_carve.py` 已处理）；不要因为日志为空就以为作业卡住，看 `top` 里的读 I/O |
| Synology Drive 版本库里的文件全是哈希名，导出后对不上路径 | 卷根下 `@synologydrive` 中的历史版本以内容哈希命名，文件名、目录、版本关系都在 Drive 的数据库里，而数据库被整体加密了 | 没有 Drive 数据库就只能当作无名文件池：按大小、哈希去匹配丢失的文件；不要指望整体还原 |
| 导出到 exFAT 盘后空间不够、文件数翻倍 | exFAT 大容量盘默认 1MiB 簇，每个小文件至少占 1MiB；macOS 还会给有扩展属性的文件写 `._` AppleDouble 旁车文件，每个也占一簇 | 小文件多时目标盘用 APFS / ext4 / NTFS；清理 `._` 文件时只删 4096 字节以内、以 `00 05 16 07` 开头、且不在导出清单里的（NAS 上本来就可能有 `._` 文件） |
| exFAT 上按文件名比对，带变音或组合字符的文件全部"缺失" | macOS 在 exFAT 上返回分解形式（NFD）的文件名，tar 成员名和清单是组合形式（NFC） | 比对前统一 `unicodedata.normalize('NFC', ...)` |
| 文件名里的 `:` 变成了奇怪的字符 | macOS 把 `:` 映射为私有区字符 U+F022 存放 | 比对前把 U+F022 换回 `:`；复制到其他系统前按需重命名 |
| exFAT 上导出的文件全都带可执行权限 | exFAT 没有权限位，挂载时统一显示为可执行 | 复制到正式存储后 `find DIR -type f -exec chmod 644 {} +` |
| 导出速度只有 30–40MB/s，远低于预期 | 目标盘经 USB 集线器或线缆降到 USB 2.0（480Mbit/s） | 长时间导出前查一下链路速率（macOS：`system_profiler SPUSBDataType`；Linux：`lsusb -t`），并用 `dd` 测一次写速度 |

## 内存路线常见误区

- "没重启就一定能找到密钥"：不对。关键是**加密进程是否还活着**。进程退出后，它的内存页很快就会被回收复用。
- 只拿内存中的 ChaCha 状态对少数几个已知文件做试解：覆盖面不够。要对全部加密文件的开头字节试解，才能下结论。
- 忽略磁盘 swap：群晖除了 zram，还有 md1 交换分区，也应该扫描（通常为空）。
