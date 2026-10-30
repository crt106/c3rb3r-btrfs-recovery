# 在 NAS 上执行与传回数据

## 基本模式：脚本走 stdin，数据走 stdout

NAS 上不落任何脚本文件，作业中的临时文件只放在 `/tmp`，退出时删除。输出是 gzip、tar 等二进制流，直接重定向到本地文件或通过管道交给本地程序。

```bash
# 1) 生成作业（本地）
python scripts/mkjob.py -- env /volume1 > job.sh
python scripts/mkjob.py --list paths.txt -- extract @LIST --g 4842040 > job.sh

# 2a) 普通用户 + sudo 需要密码：第一行喂给 sudo -S，其余交给 sh -s
{ printf '%s\n' "$SUDO_PW"; cat job.sh; } | ssh -o ServerAliveInterval=30 USER@NAS "sudo -S -p '' sh -s" > out.bin

# 2b) root 能直接登录，或 sudo 免密
cat job.sh | ssh root@NAS "sh -s" > out.bin

# 3) 导出时边传边解包，不落中间 tar 文件
{ printf '%s\n' "$SUDO_PW"; cat job.sh; } | ssh USER@NAS "sudo -S -p '' sh -s" | python scripts/c3r_local.py extract - OUT_DIR
```

DSM 的 SSH 需要先在"控制面板 → 终端机和 SNMP"里开启，而且只有管理员组成员能登录。群晖默认禁止 root 用密码登录，常见做法是用管理员账号登录后 `sudo`。

### 密码怎么传

- 交互运行时直接输入即可。
- 需要自动化（例如由 AI agent 执行）时，用 `SSH_ASKPASS` 配合 `SSH_ASKPASS_REQUIRE=force`（OpenSSH 8.4 以上）。askpass 程序从环境变量读取密码，不要把密码写进任何文件或日志。
- 也可以在 NAS 上临时放一个公钥，事后删除。

## 各平台注意事项

- **Windows PowerShell 的管道会改写二进制数据（编码转换），绝对不要用它传 tar 或 gzip。** 改用 Git Bash、WSL，或者在 cmd 里用 `>` 直接重定向到文件。
- 在 Windows 上生成作业脚本必须保证 LF 换行。`mkjob.py` 已按字节输出，自己写脚本时要注意。
- Windows Git Bash 会把以 `/` 开头的参数（如 `/volume1/...`）改写成 `C:/Program Files/Git/...`：`mkjob.py` 会自动还原；自己写命令时设 `MSYS_NO_PATHCONV=1`。
- Windows 的 Git Bash 中，`tar` 遇到 `C:` 开头的路径会误认为远程主机，需要加 `--force-local`；也可以直接用 `c3r_local.py extract` 解包。
- Python 的 `-I` 隔离模式会忽略 `PYTHONIOENCODING`；在 Windows 中文控制台下打印特殊字符时，要用 `python -X utf8`。

## 不要这样做

- **不要把大段脚本或长路径列表放进 ssh 的命令行参数**：超过约 100KB 会被 sshd 或 sudo 直接断开（Connection reset）。
- **不要用 paramiko 等纯 Python SSH 库传几十 GB 的数据**：第一个案例中传到约 100MB 就停住了。原生 OpenSSH 能稳定达到 150MB/s 以上。
- **不要把输出写到 NAS 数据卷**：那会占用可能还存着旧数据的空闲空间。

## 吞吐与耗时

- 实际速度通常受 NAS 机械盘随机读和本地目标盘写入限制，在 50–80MB/s 左右。300GB 大约要 1–2 小时。
- 写入前先测目标盘：`dd if=/dev/zero of=目标/test bs=1M count=200`。近满的 QLC 或无缓存 SATA SSD 可能低到不足 1MB/s。
- 本地验证（完整解码）是 CPU 密集型任务，要多进程并行，并且和下一批导出同时进行，避免串行等待。
- 估算空间时注意：exact 文件导出为原大小；推测文件可能有 prev、next 两个候选，空间翻倍。
