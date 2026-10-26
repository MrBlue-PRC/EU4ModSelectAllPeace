#!/usr/bin/env python3
# SelectAllPeace 工坊发布同步：仓库 → 游戏 mod 目录（单向）
#
# 仓库的 SelectAllPeace/ 是唯一事实源（含 localisation_src 开发资料）；
# 游戏 Documents 下的 mod 目录保持干净（工坊上传/游戏加载内容）。
# 本脚本只同步工坊需要的部分：descriptor.mod / common / localisation / thumbnail.png，
# 会删除目标目录中多余的旧文件（镜像语义）。
#
# 用法:
#   python tools/sync_mod.py            # 自动探测 Documents mod 目录
#   python tools/sync_mod.py <mod目录>  # 指定目标（如 E:\\...\\mod\\SelectAllPeace）
import os
import shutil
import sys

INCLUDE = ["descriptor.mod", "common", "localisation", "thumbnail.png"]


def detect_mod_dir():
    home = os.path.expanduser("~")
    cand = os.path.join(home, "Documents", "Paradox Interactive",
                        "Europa Universalis IV", "mod", "SelectAllPeace")
    if os.path.isdir(os.path.dirname(cand)):
        return cand
    return None


def main():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = os.path.join(repo, "SelectAllPeace")
    dst = sys.argv[1] if len(sys.argv) > 1 else detect_mod_dir()
    if not os.path.isdir(src):
        sys.exit(f"[ERR] 找不到源目录: {src}")
    if not dst:
        sys.exit("[ERR] 未探测到 Documents mod 目录，请作为参数传入目标 SelectAllPeace 目录")
    os.makedirs(dst, exist_ok=True)

    # 镜像：先清掉目标里的旧内容（只动本脚本管辖的范围）
    for name in os.listdir(dst):
        p = os.path.join(dst, name)
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.remove(p)

    n = 0
    for item in INCLUDE:
        s = os.path.join(src, item)
        if not os.path.exists(s):
            print(f"[跳过] 源中不存在: {item}")
            continue
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            shutil.copytree(s, d)
        else:
            shutil.copy2(s, d)
        n += 1
        print(f"[同步] {item}")
    print(f"完成: {n} 项 -> {dst}")


if __name__ == "__main__":
    main()
