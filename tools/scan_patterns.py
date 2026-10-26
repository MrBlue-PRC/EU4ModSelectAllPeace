# SelectAll 特征码静态验证工具 v3
# 用法: python scan_patterns.py <eu4.exe路径>
# 对 .text 段扫描 dllmain.cpp InstallAll() 里的 6 个特征码（支持 ? 通配），
# 报告命中地址与唯一性（与运行时 FindPattern 同语义），
# 并检查 IAT 是否仍从 user32.dll 导入 PeekMessageW（热键钩子依赖）。
# v3: 通配感知匹配；文档地址基线 = 1.37.5（旧 1.37.0 地址见交接文档第 4 节）。
import hashlib, struct, sys, datetime

PATTERNS = {
    "ctor(条目UI构造)": "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 48 89 4C 24 08 55 48 8D 6C 24 A9 48 81 EC 90 00 00 00 49 8B D9 49 8B F0 48",
    "dtor(条目UI析构)": ("48 89 5C 24 08 57 48 83 EC 20 48 8D 05 ? ? ? ? 8B DA 48 89 01 48 8B F9"
                   " 48 8D 05 ? ? ? ? 48 89 41 38 48 8D 05 ? ? ? ? 48 89 41 68"
                   " E8 ? ? ? ? F6 C3 01 74 ? BA E0 00 00 00 48 8B CF E8 ? ? ? ?"
                   " 48 8B 5C 24 30 48 8B C7 48 83 C4 20 5F C3"),
    "canAdd(规则校验)": "48 89 5C 24 10 48 89 74 24 18 55 57 41 54 41 56 41 57 48 8B EC 48 81 EC 80 00 00 00 45 0F B6 F9",
    "add(加入条款)":    "48 89 6C 24 18 48 89 74 24 20 48 89 54 24 10 57 48 83 EC 30 41 0F B6 E9",
    "refresh(刷新界面)":"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 40 48 8B F1 B9 48 00 00 00 B8",
    "remove(移除条款)": "48 89 54 24 10 53 55 56 57 48 83 EC 48 41 0F B6 F1 48 8B EA C6 42 20 00",
}

# 1.37.5 基线地址（VA，映像基址 0x140000000；1.37.0 旧地址见交接文档）
DOC_VA = {
    "ctor(条目UI构造)": 0x1413124F0,
    "dtor(条目UI析构)": 0x141306750,
    "canAdd(规则校验)": 0x14097A1C0,
    "add(加入条款)":    0x14097A790,
    "refresh(刷新界面)":0x141309120,
    "remove(移除条款)": 0x14097A8D0,
}

# 布局敏感片段（1.37.0/1.37.5 均已验证）
LAYOUT_PROBES = [
    ("refresh扩展(布局偏移 0x48/0x208/0x660)",
     "B9 48 00 00 00 B8 08 02 00 00 80 BE 60 06 00 00 00 0F 44 C8 48 03 CE"),
    ("点击函数扩展(布局偏移 0x48/0x208/0x660)",
     "BF 48 00 00 00 B9 08 02 00 00 80 B8 60 06 00 00 00 0F 44 F9 48 03 F8"),
]

def parse_pattern(s):
    pat, wild = [], []
    for tok in s.split():
        if '?' in tok:
            pat.append(0); wild.append(True)
        else:
            pat.append(int(tok, 16)); wild.append(False)
    return pat, wild

def find_all(data, pat, wild, lo, hi, limit=8):
    """在 [lo,hi) 内找所有匹配（锚定最长非通配段），返回起始偏移列表。"""
    n = len(pat)
    best_len, best_off, run = 0, 0, 0
    for i in range(n + 1):
        if i < n and not wild[i]:
            run += 1
        else:
            if run > best_len:
                best_len, best_off = run, i - run
            run = 0
    if best_len < 2:
        raise RuntimeError("锚太短，拒绝扫描")
    anchor = bytes(pat[best_off:best_off + best_len])
    hits, start = [], lo
    while True:
        i = data.find(anchor, start, hi)
        if i < 0:
            break
        b = i - best_off
        if b >= lo and b + n <= hi:
            if all(wild[k] or data[b + k] == pat[k] for k in range(n)):
                hits.append(b)
                if len(hits) >= limit:
                    break
        start = i + 1
    return hits

def main(path):
    data = open(path, 'rb').read()
    print(f"文件: {path}")
    print(f"md5: {hashlib.md5(data).hexdigest()}  size: {len(data):#x}")

    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    machine = struct.unpack_from('<H', data, e_lfanew + 4)[0]
    nsec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    ts = struct.unpack_from('<I', data, e_lfanew + 8)[0]
    optsz = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from('<H', data, opt)[0]
    imagebase = struct.unpack_from('<Q', data, opt + 24)[0] if magic == 0x20b else \
                struct.unpack_from('<I', data, opt + 28)[0]
    print(f"x64={machine==0x8664} 节区数={nsec} 链接时间={datetime.datetime.utcfromtimestamp(ts)} UTC 基址={imagebase:#x}")

    sec_off = opt + optsz
    sections = []
    text = None
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o:o+8].rstrip(b'\0').decode(errors='replace')
        vsize, va, rsize, raw = struct.unpack_from('<IIII', data, o + 8)
        sections.append((name, va, vsize, raw, rsize))
        if name == '.text':
            text = (va, vsize, raw, rsize)
    tva, tvsize, traw, trsize = text
    tlo, thi = traw, traw + trsize
    print(f".text: VA={imagebase+tva:#x} 文件范围=[{tlo:#x},{thi:#x})")

    def off2va(off):
        return imagebase + tva + (off - traw)

    print("\n=== 特征码扫描（应各自唯一命中） ===")
    ok = True
    for k, s in PATTERNS.items():
        pat, wild = parse_pattern(s)
        hits = find_all(data, pat, wild, tlo, thi)
        vas = [off2va(h) for h in hits]
        doc = DOC_VA[k]
        if len(vas) == 1:
            extra = "=基线地址" if vas[0] == doc else f"(基线{doc:#x}, 偏移{vas[0]-doc:+#x})"
            print(f"[OK ] {k}: 唯一命中 VA={vas[0]:#x} {extra}")
        elif len(vas) == 0:
            print(f"[失配] {k}: .text 内无命中  <-- 需重新逆向")
            ok = False
        else:
            print(f"[多命中] {k}: {len(vas)} 处 {[hex(v) for v in vas[:4]]}  <-- FindPattern 取第一个，需人工确认")
            ok = False

    print("\n=== 布局敏感片段 ===")
    for k, s in LAYOUT_PROBES:
        pat, wild = parse_pattern(s)
        hits = find_all(data, pat, wild, tlo, thi)
        if len(hits) == 1:
            print(f"[OK ] {k}: 唯一命中 VA={off2va(hits[0]):#x}")
        else:
            print(f"[注意] {k}: 命中 {len(hits)} 处 {[hex(off2va(h)) for h in hits[:4]]}  <-- 布局可能变化")

    # IAT 检查：user32.dll 的 PeekMessageW（热键钩子依赖）
    print("\n=== IAT 导入检查 ===")
    imp_rva = struct.unpack_from('<I', data, opt + 112 + 8)[0]  # DataDirectory[1] = IMPORT
    found = False
    if imp_rva:
        def rva2off(rva):
            for name, va, vsize, raw, rsize in sections:
                if va <= rva < va + max(vsize, rsize):
                    return raw + (rva - va)
            return None
        off = rva2off(imp_rva)
        while off:
            oft_rva, _ts, _fc, name_rva, ft_rva = struct.unpack_from('<IIIII', data, off)
            if name_rva == 0 and ft_rva == 0:
                break
            noff = rva2off(name_rva)
            dll = data[noff:data.index(b'\0', noff)].decode(errors='replace') if noff else '?'
            if dll.lower() == 'user32.dll':
                toff, idx = rva2off(oft_rva or ft_rva), 0
                while True:
                    v = struct.unpack_from('<Q', data, toff)[0]
                    if v == 0:
                        break
                    if not (v >> 63):
                        ho = rva2off(v & 0x7FFFFFFF)
                        if ho:
                            fname = data[ho+2:data.index(b'\0', ho+2)].decode(errors='replace')
                            if fname == 'PeekMessageW':
                                print(f"PeekMessageW: 已导入，IAT 槽位 VA={imagebase+ft_rva+idx*8:#x}  OK")
                                found = True
                    toff += 8; idx += 1
            off += 20
    if not found:
        print("PeekMessageW: user32.dll 未导入该函数!  <-- IAT 钩子会失败")
        ok = False

    print("\n结论: " + ("6 特征码全部唯一命中 + IAT 正常 —— 插件静态需求满足" if ok else "存在失配项，见上 <--"))

if __name__ == '__main__':
    main(sys.argv[1])
