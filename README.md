# c3rb3r-btrfs-recovery

**没有密钥，也能从 Btrfs 旧数据块中找回被 C3RB3R（`.L0CK3D`）勒索加密的群晖 NAS 文件。**

这是一个 AI Agent Skill，可用于 Claude Code、Codex、Cursor 等支持 `SKILL.md` 的 agent。它把一次真实恢复的完整流程、只读工具和验证方法整理成通用指南，帮助同一批受害者自救。

> English: Agent skill for keyless recovery of Synology / Btrfs files encrypted by the C3RB3R (Cerber-like, `.L0CK3D`, `read-me3.txt`) ransomware. C3RB3R overwrites files in place; on Btrfs copy-on-write volumes the original plaintext survives in "bookend" extents that are still referenced by the unencrypted parts of each file. The skill maps every rewritten byte back to the old extent via the extent tree, reads it from the block device read-only, and proves the result block-by-block against Btrfs data checksums.

---

## ⚠️ 先看这里：加密进程还在运行吗？

如果事发不久，NAS **没有重启**，加密进程（例如 `/usr/bin/libgld -n 308`，程序文件已从磁盘删除）**可能还活着**。这时请立即：

1. **`kill -STOP <pid>` 冻结它。不要 kill，不要重启。**
2. 按下面两个仓库的方法，从进程内存里取出会话主密钥。这样可以**解开全部文件**，收益远大于本仓库的方法：
   - **[soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue)**：DSM 勒索证据保全、从 RAM 恢复密钥、复制解密
   - **[Benjamin-zlt/c3rb3r-baremetal-rescue](https://github.com/Benjamin-zlt/c3rb3r-baremetal-rescue)**：冻结加密器、导出进程内存、提取会话密钥、解密全部文件（第二个独立受害者的完整解密案例；讨论见 [soimy/c3rb3r-rescue#7](https://github.com/soimy/c3rb3r-rescue/issues/7)）

**加密进程已经退出**（重启过，或事发已十几小时）时，内存里基本找不到密钥了。本 skill 记录了一次穷尽式的内存扫描，结果为零。此时请走本仓库的 Btrfs 路线。

## 原理（一句话）

C3RB3R 只**原地改写**文件的几段：小文件整体加密，1–5MB 加密前 1MiB，大文件加密头、中、尾三段共约 12%。Btrfs 写时复制会把改写的内容写到新位置，而**原 extent 只要还被文件中没被加密的部分引用，就整块保留在盘上**。所以只需按 extent 树把被改写的字节映射回旧 extent，就能拿回原始字节；在开启了数据校验和的共享上，还能用 Btrfs 自带的 CRC32C 逐块证实。

NoCOW 共享（DSM 里没勾"数据校验和"的共享）也不一定没救：**数据只要早于该子卷最后一次快照（即使快照后来删了），覆盖时仍会走写时复制**。

## 第一个案例的效果

| 范围 | 结果 |
|---|---|
| homes、photo 等 CoW 共享 | **35,445 个文件 / 229.9GB** 经 SHA 核对和完整解码验证 |
| 精确恢复部分的校验和抽检 | 约 20 万个 4K 块，与 Btrfs CRC32C **全部一致** |
| NoCOW 共享中快照前写入的数据 | 又找回约 **6,100 个文件 / 约 346GB**（另有约 3,800 个文件本地已有原件） |
| 救不回的部分 | 1MiB 以下整文件加密的小文件、数据库文件、NoCOW 共享中快照后写入的文件 |

## 安装

使用 [skills CLI](https://github.com/vercel-labs/skills)：

```bash
# 安装到当前项目
npx skills add crt106/c3rb3r-btrfs-recovery

# 全局安装，或指定 agent
npx skills add crt106/c3rb3r-btrfs-recovery -g
npx skills add crt106/c3rb3r-btrfs-recovery -a claude-code
```

手动安装：把 `skills/c3rb3r-btrfs-recovery/` 整个目录复制到 agent 的 skills 目录，例如 Claude Code 的 `~/.claude/skills/`。

## 使用

装好后，直接对 agent 描述你的情况即可，例如：

> 我的群晖 NAS 昨晚被勒索了，文件都变成了 .L0CK3D，没有快照也没有备份，帮我看看能不能恢复。NAS 地址 192.168.x.x，管理员账号 xxx。

agent 会按 skill 的流程执行：先判断还能不能从内存拿密钥，然后依次做环境自检、确定攻击代数 G_ATTACK、用已知原件做单文件验证、全量普查、流式导出、多重验证，最后出报告。

也可以不借助 agent，自己运行脚本：

```bash
cd skills/c3rb3r-btrfs-recovery/scripts
# 1. 自检（在任何设备上都先跑这一步）
python mkjob.py -- preflight /volume1/某个文件.jpg.L0CK3D > job.sh
{ printf '%s\n' "$SUDO_PW"; cat job.sh; } | ssh admin@NAS "sudo -S -p '' sh -s"
# 2. 确定 G_ATTACK -> 3. 普查 -> 4. 导出与验证：见 SKILL.md
```

| 脚本 | 运行位置 | 作用 |
|---|---|---|
| `c3r_btrfs.py` | NAS（root，Python 3.6+ 标准库，只读） | `preflight`、`env`、`gens`、`survey`、`extract`、`patch`、`csum`、`plan` |
| `c3r_carve.py` | NAS（root，Python 3.6+ 标准库，只读） | 空闲空间雕刻，找回整体加密的小文件：`freemap`、`scan`、`extract` |
| `mkjob.py` | 本地 | 把工具和路径列表打包，经 SSH 标准输入交给 NAS 执行，不在数据卷上落文件 |
| `c3r_local.py` | 本地 | 解包 tar 流、多进程解码验证、对照已知原件、挑选最佳候选、打补丁换候选并可回退、统计 |

## 安全原则

- **不要删除、覆盖任何 `.L0CK3D` 文件，也不要清空回收站。** 旧数据块正是靠密文文件"拽着"才没被回收。
- 不要做 defrag、balance、`btrfs check --repair`，不要运行来源不明的"解密器"，不要付赎金。
- 所有 NAS 端操作都是只读的：只做 ioctl 查询、读文件、读块设备，结果写到 NAS 以外的盘。
- 报告里要把"精确恢复并经校验和证实""推测后解码通过""失败"分开写。

## 兼容性

已在群晖 DSM 7.2.1（SHR，`cachedev`，Python 3.8）上真机验证。其他环境请先跑 `preflight`：它会逐项给出 OK、WARN 或 FAIL 和处理建议。DSM 6、OMV、Unraid、没有 Python 3 的设备、拆盘到 Linux 电脑离线处理等情况，见 [`references/compatibility.md`](skills/c3rb3r-btrfs-recovery/references/compatibility.md)。不适用于 ext4（多数 QNAP 卷、群晖老卷），ZFS 需要另一套工具链。

欢迎提交 issue，附上 `preflight` 的输出，帮助完善对更多设备的支持。

## 目录

```
skills/c3rb3r-btrfs-recovery/
├── SKILL.md                     # agent 执行流程
├── scripts/
│   ├── c3r_btrfs.py             # NAS 端只读工具
│   ├── c3r_carve.py             # NAS 端只读的空闲空间雕刻
│   ├── mkjob.py                 # 作业打包
│   └── c3r_local.py             # 本地解包、验证、统计
└── references/
    ├── principles.md            # Btrfs 原理：bookend extent、lastsnap、extent 树、csum 树
    ├── c3rb3r-format.md         # 尾部格式、加密模式、密钥路线
    ├── compatibility.md         # 各设备的定制引导与报错处理
    ├── transport.md             # 数据传输方法与各平台的坑
    ├── free-space-carving.md    # 空闲空间雕刻：适用条件、候选判定、原件核对、结果汇总
    ├── pitfalls.md              # 实战踩过的坑
    └── report-template.md       # 恢复报告模板
```

测试（不需要 NAS）：在仓库根目录运行 `python3 -m unittest`。

## 相关项目

- [soimy/c3rb3r-rescue](https://github.com/soimy/c3rb3r-rescue)：证据保全、RAM 密钥恢复、复制解密
- [Benjamin-zlt/c3rb3r-baremetal-rescue](https://github.com/Benjamin-zlt/c3rb3r-baremetal-rescue)：在物理机 DSM 上冻结加密器、取出会话密钥、全量解密
- 讨论：[soimy/c3rb3r-rescue#7](https://github.com/soimy/c3rb3r-rescue/issues/7)

本仓库补的是**加密进程已经退出、拿不到密钥**时的路线。三者可以组合使用：先尝试拿密钥，拿不到再走 Btrfs 旧数据块。

## 免责声明

本项目按"现状"提供，只用于恢复你自己有权处置的数据。工具本身只读，但任何恢复操作都有风险：请先保全证据，先用已知原件做小样本验证，再批量操作。作者不对数据损失承担责任。

## License

MIT
