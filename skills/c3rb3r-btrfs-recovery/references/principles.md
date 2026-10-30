# 原理：为什么没有密钥也能找回原文件

## 目录
1. Btrfs 的写时复制与 bookend extent
2. NoCOW 与 last_snapshot 例外
3. EXTENT_DATA 项与字节级映射
4. G_ATTACK：区分新旧 extent
5. 逻辑地址到块设备偏移
6. 校验和树：逐块证实
7. 分类判定细节
8. 何时救不回

## 1. Btrfs 的写时复制与 bookend extent

在 CoW 文件上改写一段数据时，Btrfs 会把新数据写到新的位置，然后把文件的映射指向新位置；旧数据块不会被擦除。

关键在于 **Btrfs 不拆分 extent**。比如一个文件原本是一整块 5.5MB 的 extent，C3RB3R 只改写了头、中、尾三段。改写之后，文件中未加密的两段仍引用那块原 extent，只是带上了 offset。只要还有任何引用存在，**整个原 extent 都保持已分配**，包括被改写那三段对应的原始明文。这就是所谓的 "bookend extent"。

所以：

- 部分加密的文件（mode 25、26）通常能完整找回；
- 整文件加密的文件（mode 24，即 1MiB 以下的小文件）找不回：所有引用都换成了新 extent，原 extent 被释放，可能已被复用；
- 加密段长于 128MiB（单个 extent 的上限）时，中间可能有一整块原 extent 被完全覆盖后释放，只能"外推"它原来的位置。

## 2. NoCOW 与 last_snapshot 例外

NoCOW（`chattr +C`，在 DSM 里对应"未勾选数据校验和"）会就地覆盖，正常情况下旧数据直接消失。**但有一个例外**：只要一个 extent 的代数小于等于所属子卷 ROOT_ITEM 里的 `last_snapshot`，覆盖写就必须走 CoW。原因是这个 extent 可能仍被快照共享，内核不能原地改。

- 即使快照后来被删除，`last_snapshot` 也不会清零。
- 群晖的每个共享文件夹都是一个子卷。只要曾经对它做过快照（Snapshot Replication、Hyper Backup 某些模式、手动快照），**快照之前写入的数据在 NoCOW 共享里也能恢复**。
- 查看方法：`c3r_btrfs.py env` 输出的 `subvolumes[].lastsnap`；或者 `btrfs inspect-internal dump-tree -t 1 DEV`（旧版本用 `btrfs-debug-tree -t 1`），看 ROOT_ITEM 那一行的 `lastsnap`。`/volume1/@sharesnap/*.meta` 的日期可以帮助估计快照时间。
- 第一个案例：document 和 movie 的 lastsnap 约为 677,706（对应 2024-06）。2024-06 之前存入的 1 万个文件可以精确还原，之后写入的约 28.7 万个文件被原地覆盖。

## 3. EXTENT_DATA 项与字节级映射

用 `BTRFS_IOC_TREE_SEARCH(_V2)` 按 inode 查询 `EXTENT_DATA`（key type 108），每一项给出：

| 字段 | 含义 |
|---|---|
| key.offset（pos） | 本段在文件中的起点 |
| generation | 写入这段数据时的事务代数 |
| disk_bytenr | 所在 extent 的起始逻辑地址 |
| disk_num_bytes | 整个 extent 的长度（不是本段长度） |
| offset（eoff） | 本段在 extent 内的偏移 |
| num_bytes | 本段长度 |

由此可以推出：这个旧 extent 覆盖的**文件区间**是 `[pos - eoff, pos - eoff + disk_num_bytes)`，其中文件位置 x 的原始字节位于逻辑地址 `disk_bytenr + (x - (pos - eoff))`。

只要某个被改写的位置落在某个仍被引用的旧 extent 的覆盖区间内，就能精确取回，不需要猜。

用 FIEMAP 只能拿到 `phys = disk_bytenr + eoff`，看不到 extent 的完整长度。所以只靠"相邻区段 delta 推算"会把跨 extent 的情况读错。第一个案例里，前期用 FIEMAP 推算的方法在约 50 个大视频上失败，换成 extent 树后能精确区分哪些字节可以精确取回、哪些只能推测。

## 4. G_ATTACK：区分新旧 extent

加密时新写的 extent 代数集中在攻击时段。取被加密文件 pos=0 那一项的代数（加密总是从文件头开始），其最小值减去一点余量，就是 G。代数不小于 G 的 extent 是新写的，小于 G 的是旧的。

- `c3r_btrfs.py gens` 自动统计，采样要覆盖多个共享。
- 检查"G 以下的最高代数"，确认存在明显空档。

## 5. 逻辑地址到块设备偏移

`dump-tree -t 3`（chunk tree）给出每个 DATA chunk 的逻辑起点、长度和 stripe 0 的设备偏移。single、DUP、RAID1 类剖面可以直接用 stripe 0。群晖 SHR 和 RAID 由 mdraid 负责，Btrfs 层面通常是单设备 single。RAID0/5/6/10 剖面需要按条带换算，工具会拒绝执行。

也可以用 `btrfs-map-logical -l ADDR -b LEN -o OUT DEV` 做单点核对，但它会写文件，只能写到 /tmp。

## 6. 校验和树：逐块证实

开启了数据校验和的共享（CoW 共享），每个 4K 数据块都在 tree 7 里存有 CRC32C：key 为 (EXTENT_CSUM_OBJECTID=-10, 128, 起始逻辑地址)，数据是连续的 4 字节 csum 数组。旧 extent 仍被引用，它的 csum 记录也就还在。所以：

- 对 exact 段的每个整 4K 块计算 CRC32C，与记录比对。一致就说明读回的正是加密前的数据，这是最强的证据。
- 单个 csum 项可达约 16KB，**必须用 TREE_SEARCH_V2 配大缓冲区**，V1 的 4KB 缓冲装不下时会返回 0 项，看起来像"没有记录"。
- 自检：当前仍被引用的旧块，其 csum 必须一致（工具里的 `self_ok`）。如果自检失败，说明 csum 算法或查询有问题，不能据此下结论。
- 被释放的 extent 的 csum 会被删除，所以推测段无法用这个方法证实。

## 7. 分类判定细节（c3r_btrfs.py 的 plan_file）

1. 识别尾部：最后 588 字节中，[580:588] 的 u64 等于文件大小减 588，就认定是尾部。会话标记 [568:572] 每个受害者都不同，只做记录。
2. 公式区间（已知模式）：
   - 0x24：[0, N)；
   - 0x26：[0, min(N, 1MiB))；
   - 0x25 且参数 0x0a：W = 4·⌊N/100⌋，gap = ⌊(N−3W)/2⌋，区间为 [0,W)、[W+gap, 2W+gap)、[2(W+gap), 3W+2gap)。
   - 其他模式（例如 0x25 + 0x14）没有公式，改写范围完全由新 extent 推出。
3. 改写范围 = 新 extent 覆盖处 ∪ 公式区间中仍由旧 extent 映射的部分（后者属于原地覆盖，标为 lost）。
4. 新 extent 覆盖的每个字节：落在某个旧 extent 的覆盖区间内就是 exact；否则按前一个、后一个旧 extent 的 delta 外推（infer）；两侧都没有旧 extent 时为 no_candidate。
5. 边界自校验：新 extent 是按 4K 对齐写入的，公式区间之外、但落在新 extent 内的那几 KB 是**加密器顺带写回的明文**，它们必须与旧 extent 同位置的字节完全相同。加密区内再抽 64 字节，旧数据必须与当前密文**不同**。任何一项失败，状态都标为 boundary_mismatch。

## 8. 何时救不回（如实告知用户）

- 1MiB 以下整文件加密的小文件、数据库文件：旧 extent 已释放。数据块组几乎写满时，空闲空间很快会被复用。
- NoCOW 共享中晚于最后一次快照写入的文件：原地覆盖。不过大文件只缺约 12%，其余 88% 还在原处（视频可能部分可播）。
- 没有快照、关闭了校验和、又启用了透明压缩等少见组合：需要个案分析。
