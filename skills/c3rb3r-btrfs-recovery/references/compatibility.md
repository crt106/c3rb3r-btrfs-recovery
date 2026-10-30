# 设备兼容性与定制引导

**第一条规矩：在任何设备上，先跑 `c3r_btrfs.py preflight <某个加密文件>`。** 它会逐项检查，并对每个 FAIL 或 WARN 给出处理建议。只有出现 "全部关键检查通过" 之后，才进入 gens 和 survey。本文按 preflight 的检查项和常见设备说明怎么处理。

## 目录
1. 已验证环境
2. preflight 各项失败的处理
3. 按设备类型的定制引导
4. 没有 Python 3 怎么办
5. 拆盘到 Linux 电脑离线处理（通用兜底方案）
6. 改脚本时必须保留的自检

## 1. 已验证环境

| 项 | 值 |
|---|---|
| 设备 | 群晖 DSM 7.2.1-69057（第三方引导，SA6400 型号） |
| 内核 / btrfs-progs | DSM 自带；dump-tree 子命令可用，也自带 btrfs-debug-tree 与 btrfs-map-logical |
| Python | DSM 自带 /usr/bin/python3 3.8.15 |
| 卷 | SHR，`/dev/mapper/cachedev_0`，DATA 剖面 single，sectorsize 4096，crc32c |
| 本地端 | Windows 11 + Git Bash + Python 3.13；也适用于 Linux / macOS |

其他环境在理论上兼容，但必须以 preflight 的结果为准。

## 2. preflight 各项失败的处理

| 检查项 | 失败表现 | 原因与处理 |
|---|---|---|
| python | 版本低于 3.6 或找不到命令 | 见第 4 节 |
| root | euid ≠ 0 | 用 `sudo -S -p '' sh -s` 运行作业；群晖默认禁止 root 用密码登录，用管理员账号登录后 sudo |
| filesystem | 不是 btrfs | ext4（群晖老卷、多数威联通 QNAP 卷）：**本方法不适用**，没有 CoW 就没有旧数据，只能找其他副本。ZFS（TrueNAS 等）：见 3.5。路径写错：确认用的是 `/volume1` 这类数据卷挂载点 |
| filesystem | 路径显示成 `C:/Program Files/Git/volume1/...` | Windows Git Bash 改写了参数。新版 mkjob 会自动还原，也可以设置 `MSYS_NO_PATHCONV=1` |
| superblock | 64KiB 处没有 `_BHRfS_M` | 设备选错了。用 `cat /proc/mounts` 找 /volume1 对应的设备；群晖常见 `/dev/mapper/cachedev_N`（有无 SSD 缓存都有）、`/dev/vgN/volume_N`、`/dev/mdN`。加密卷先解锁，用解锁后的映射设备 |
| superblock | sectorsize ≠ 4096 | 工具会按实际值处理；先用已知原件验证一个文件 |
| csum | xxhash64 或未知算法 | 恢复照常进行，但不能逐块证实；用解码和已知原件对照代替。如果需要，可以补一个 xxhash64 实现 |
| dump_tree | 两种命令都没有 | 安装 btrfs-progs（群晖自带）；也可以在别的 Linux 机器上对同一块设备运行 `btrfs inspect-internal dump-tree -t 3 DEV > chunk.txt`，再改脚本读取这个文件（parse_chunks 只需要这段文本） |
| chunk_map | 没解析到 DATA chunk | btrfs-progs 输出格式不同。打开 dump-tree 原文，看 CHUNK_ITEM 块里 length、type、stripe 0 的写法，相应修改 `parse_chunks` 中的正则。改完必须让 end_to_end_read 通过 |
| chunk_map | RAID0/5/6/10 剖面 | Btrfs 原生多盘 RAID 需要按条带换算。群晖的 SHR/RAID 是 mdraid，Btrfs 层是 single，不会遇到这种情况。真遇到时，用 `btrfs-map-logical` 逐段取数代替 Volume.read，或扩展条带换算 |
| chunk_map | 多设备 | 原生多设备 Btrfs：需要按 stripe 的 devid 打开对应设备。`btrfs fi show` 可以看到 devid 和设备路径的对应关系 |
| tree_search | EPERM | 不是 root |
| tree_search | ENOTTY | 不是 btrfs 文件，或内核太旧。V2 不可用时工具会自动退回 V1：extent 查询不受影响，但 csum 大项可能查不到 |
| end_to_end_read | 不一致 | **到此为止，不要继续。** 地址映射错了：设备、条带或多设备问题。修好之前导出的一切都不可信 |
| map_logical_crosscheck | 不一致 | 同上，以 btrfs-map-logical 的结果为准排查 |
| csum_selfcheck | 不一致 | csum 查询或算法有误，csum 的结论不能用；恢复本身仍可继续，但要靠解码验证 |
| csum_lookup | 没有记录 | 正常现象：NoCOW 或 nodatasum 共享没有校验和 |
| footer | 不符合 588 字节结构 | 可能是别的家族、别的版本，或者文件被截断。`tail -c 600 文件 \| hexdump -C` 后对照 c3rb3r-format.md。如果尾部长度不同但同样是原地改写，可以在 parse_footer 里改长度和偏移，其余原理照样适用 |
| compression | 透明压缩 | 压缩 extent 内是 zlib、lzo 或 zstd 数据（每段最多 128KiB）。需要按 EXTENT_DATA 的 compression 字段整段读出并解压，再按 ram_bytes 和 offset 截取。本工具未实现，可以按这个思路扩展 |

## 3. 按设备类型的定制引导

### 3.1 群晖 DSM 7.x（白群晖、黑群晖）

- 打开 SSH：控制面板 → 终端机和 SNMP；用管理员账号登录后 sudo。
- 卷设备通常是 `/dev/mapper/cachedev_0`；Python 3 是系统自带的（7.0 以上）。
- **每个共享文件夹都是一个子卷**。用 `env` 查看各子卷的 lastsnap；`/volume1/@sharesnap/*.meta` 的日期可以帮助判断曾经做快照的时间。
- 共享是否开启数据校验和，可以在 控制面板 → 共享文件夹 → 编辑 → 高级 里看到。勾选的是 CoW，没勾的是 NoCOW。
- homes、photo 等由系统自动创建的共享，默认是 CoW。
- 恢复期间暂停 Synology Photos 索引、Surveillance 录像、Download Station、Cloud Sync、Drive，以减少写入。

### 3.2 群晖 DSM 6.x

- DSM 6.2 往往只自带 Python 2.7，**本工具需要 Python 3**，见第 4 节。
- 老内核通常支持 TREE_SEARCH_V2（3.16 以上），preflight 会自动判断。
- btrfs-progs 版本较旧，一般只有 `btrfs-debug-tree`；工具会自动尝试。

### 3.3 其他用 Btrfs 的 NAS 或系统（OpenMediaVault、Unraid 的 btrfs 池、Rockstor、自建 Linux）

- 原理完全相同，只是没有"共享 = 子卷"的约定，也可能根本没有子卷。用 `btrfs subvolume list <挂载点>` 查看。
- 原生多盘 Btrfs RAID 比较常见，注意 chunk_map 的检查结果，见第 2 节。
- 透明压缩（`compress=zstd`）在这些系统上更常见，注意 compression 警告。

### 3.4 威联通 QNAP

- 多数 QNAP 卷是 ext4 加 LVM，部分新机型是 ZFS（QuTS hero）。ext4 不适用本方法；ZFS 见下节。

### 3.5 ZFS（TrueNAS、QuTS hero）

- ZFS 也是写时复制，被覆盖的块在没有快照时会被释放。不过 ZFS 的旧块可能保留在最近的事务组（TXG）里：可以用 `zdb` 查看，用只读方式导入较早的 TXG（`zpool import -o readonly=on -T <txg>`）做回滚式恢复。这和本工具是完全不同的工具链，而且时效性很强（TXG 会被不断覆盖）。如果有快照，直接从快照恢复即可。
- 本 skill 的脚本不适用于 ZFS，只能参考其中"保全、验证、报告"的流程。

## 4. 没有 Python 3 怎么办

按推荐程度排序：

1. **便携 Python 放进 /tmp**：从 python-build-standalone 下载对应架构（x86_64 或 aarch64）的 `install_only` 包，解压到 `/tmp/py`（tmpfs 在内存里，不写数据卷），然后用 `/tmp/py/bin/python3 c3r_btrfs.py ...` 运行。用 `uname -m` 查看架构，`df /tmp` 确认 tmpfs 空间足够（大约需要 100MB）。
2. 群晖套件中心安装 Python 3：会往数据卷写入几十 MB。这不会影响被引用的旧 extent，但会占用少量空闲空间。可以接受，但不是首选。
3. 拆盘到 Linux 电脑离线处理，见第 5 节。

## 5. 拆盘到 Linux 电脑离线处理（通用兜底方案）

适用场景：NAS 环境太老或太受限、怀疑 NAS 系统仍被入侵者控制，或者想彻底避免在原系统上操作。

1. NAS 关机，**记下盘位顺序**，把所有硬盘接到一台 Linux 电脑上（Ubuntu Live USB 即可），不要初始化任何磁盘。
2. 只读组装：
   ```
   mdadm --assemble --scan --readonly
   vgchange -ay                        # SHR 会用到 LVM
   ```
   群晖的数据卷通常是 `/dev/vgX/volume_Y` 或 `/dev/mdN`。加密卷需要先 `cryptsetup open --readonly`。
3. 只读挂载，避免日志回放写盘：
   ```
   mount -o ro,rescue=nologreplay /dev/vg1000/lv /mnt   # 老内核用 ro,nologreplay
   ```
   群晖的 Btrfs 带有私有扩展，普通内核有时挂载失败。此时要么换一个内核版本较新的发行版再试，要么回到 NAS 上处理。
4. 在 `/mnt` 上运行同样的 `c3r_btrfs.py preflight /mnt/...`，后续步骤完全一样，只是不需要 ssh，结果直接写到本地另一块盘。

## 6. 改脚本时必须保留的自检

不同设备可能需要修改脚本（正则、尾部格式、条带换算、压缩）。修改之后，下面几项必须仍然成立，否则不能开始批量导出：

1. preflight 的 `end_to_end_read` 显示 ==（地址映射正确）。
2. 用一个已知原件验证：`extract` 导出的结果和原件 SHA-256 一致。
3. 开启校验和的共享上，`csum` 的 `self_ok` 大于 0 且 `bad` = 0。
4. 普查中 `boundary_mismatch` 只占极少数（第一个案例约万分之一）。如果比例很高，说明 G 值或映射有问题。
