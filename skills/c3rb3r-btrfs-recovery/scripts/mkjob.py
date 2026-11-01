#!/usr/bin/env python3
"""生成一个通过 stdin 交给 NAS `sh -s` 执行的作业脚本：内嵌 c3r_btrfs.py（及可选路径列表），只在 /tmp 落临时文件并在结束时删除。

用法（输出到 stdout）：
  python mkjob.py [--tool carve] [--list paths.txt] -- <c3r_btrfs.py 或 c3r_carve.py 的参数...>
例：
  python mkjob.py -- env /volume1 > job.sh
  python mkjob.py --list hard.txt -- extract @LIST --g 4842040 > job.sh     # @LIST 会替换为 NAS 上的列表路径
  python mkjob.py --tool carve -- freemap --mount /volume1 > job.sh         # 空闲空间雕刻（同时内嵌 c3r_btrfs.py）
  python mkjob.py --tool carve --list targets.tsv -- scan --targets @LIST > job.sh
然后：
  { printf '%s\\n' "$SUDO_PW"; cat job.sh; } | ssh USER@NAS "sudo -S -p '' sh -s" > out.bin
（root 直接登录或 sudo 免密时去掉 printf 那一行，并把远端命令改成 "sh -s"）
"""
import argparse
import base64
import os
import re
import shlex
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    argv = sys.argv[1:]
    if '--' not in argv:
        sys.exit(__doc__)
    i = argv.index('--')
    ap = argparse.ArgumentParser()
    ap.add_argument('--list')
    ap.add_argument('--tool', choices=['btrfs', 'carve'], default='btrfs',
                    help='carve：运行 c3r_carve.py（空闲空间雕刻），c3r_btrfs.py 作为依赖一并内嵌')
    opts = ap.parse_args(argv[:i])
    tool_args = argv[i + 1:]
    tool = base64.b64encode(open(os.path.join(HERE, 'c3r_btrfs.py'), 'rb').read()).decode()
    lines = ['set -e', 'T=$(mktemp -d /tmp/c3r.XXXXXX)', "trap 'rm -rf \"$T\"' EXIT",
             "base64 -d > \"$T/c3r_btrfs.py\" <<'__C3R_TOOL__'", tool, '__C3R_TOOL__']
    if opts.tool == 'carve':
        carve = base64.b64encode(open(os.path.join(HERE, 'c3r_carve.py'), 'rb').read()).decode()
        lines += ["base64 -d > \"$T/c3r_carve.py\" <<'__C3R_CARVE__'", carve, '__C3R_CARVE__']
    if opts.list:
        lst = base64.b64encode(open(opts.list, 'rb').read()).decode()
        lines += ["base64 -d > \"$T/list.txt\" <<'__C3R_LIST__'", lst, '__C3R_LIST__']
    quoted = []
    for i, a in enumerate(tool_args):
        # Windows Git Bash(MSYS) 会把 /volume1/... 改写成 C:/Program Files/Git/volume1/...，这里还原
        m = re.match(r'^[A-Za-z]:[/\\](?:Program Files[/\\])?Git([/\\].*)$', a)
        if m:
            a = m.group(1).replace('\\', '/')
            tool_args[i] = a
            sys.stderr.write('注意：参数被 MSYS 路径转换改写，已还原为 %s（可设 MSYS_NO_PATHCONV=1 避免）\n' % a)
    # c3r_btrfs.py 用 @文件 表示路径列表；c3r_carve.py 的 --targets/--picks 直接取文件路径
    lst = '"$T/list.txt"' if opts.tool == 'carve' else '"@$T/list.txt"'
    for a in tool_args:
        quoted.append(lst if a == '@LIST' else shlex.quote(a))
    lines.append('python3 "$T/%s" ' % ('c3r_carve.py' if opts.tool == 'carve' else 'c3r_btrfs.py') + ' '.join(quoted))
    # 按字节写出：Windows 文本模式会把换行写成 CRLF，远端 sh 会解析失败
    sys.stdout.buffer.write(('\n'.join(lines) + '\n').encode())


if __name__ == '__main__':
    main()
