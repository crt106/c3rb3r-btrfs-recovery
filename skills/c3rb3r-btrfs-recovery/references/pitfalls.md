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
| `inline` 状态 | 2KB 左右的小文件内联存放在元数据里，元数据也 CoW，旧的叶子节点多半已被复用 | 一般放弃；可以考虑 btrfs-find-root 加旧树根，属于专家级个案 |
| `compressed` 状态 | 共享启用了透明压缩，extent 内是压缩数据 | 需要按 extent 读出整块再解压（zlib、lzo、zstd），本工具未实现 |
| 输出目录里有 `homes`、`volume1` 等不同前缀 | 不同版本脚本的成员名基准不同 | 本工具统一以 `/` 为基准，成员名形如 `volume1/...` |

## 内存路线常见误区

- "没重启就一定能找到密钥"：不对。关键是**加密进程是否还活着**。进程退出后，它的内存页很快就会被回收复用。
- 只拿内存中的 ChaCha 状态对少数几个已知文件做试解：覆盖面不够。要对全部加密文件的开头字节试解，才能下结论。
- 忽略磁盘 swap：群晖除了 zram，还有 md1 交换分区，也应该扫描（通常为空）。
