# -*- coding: utf-8 -*-
r"""
EU4 双字节补丁(EU4dll)本地化转码器 —— MakeQinGreatAgain mod 专用
================================================================

编码方案（经 278 万字符单元的官方汉化 Mod 语料逆向验证）：

1. 游戏本地化 yml 是「UTF-8 壳 + CP1252 字节流 + 3 字节汉字单元」三层结构：
   - 文件为 UTF-8-BOM 编码，但值里的非 ASCII 字符其实是 CP1252 字节的
     UTF-8 再编码（如 c5 92 = U+0152 = CP1252 字节 0x8C）。
   - 每个汉字/全角字符表示为 3 字节单元：[引导字节][lo][hi]
     * 引导字节 = 0x10 | 标志位（仅 0x10~0x13 四种）
     * Unicode 码点 = (hi << 8) | lo   （小端序）
     * 标志位 & 1：lo 为回避字节，真实 lo = 存储 lo - 0x0E
     * 标志位 & 2：hi 为回避字节，真实 hi = 存储 hi + 0x09
   - 回避原因：原始字节若为 0x00/0x0A/0x0D/0x22(")/0x5C(\) 及部分
     解析敏感字节（空格、{}[]、§、#、$ 等），会破坏 yml/游戏文本解析。

2. 脚本文件（decisions/missions 等里的 define_ruler 名字）使用同一种
   3 字节单元，但直接是裸 CP1252 字节流（外面没有 UTF-8 壳）。

用法：
  python mqga_convert.py decode <游戏yml> <可读UTF-8输出>     # 游戏格式 -> 可读
  python mqga_convert.py encode <可读UTF-8> <游戏yml输出>     # 可读 -> 游戏格式
  python mqga_convert.py verify <游戏yml>                     # 往返一致性校验
  python mqga_convert.py decode-raw <脚本txt> <输出>          # 裸流脚本 -> 可读
  python mqga_convert.py encode-raw <可读txt> <输出>          # 可读 -> 裸流脚本
"""

import sys

# CP1252 定义区（0x80-0x9F 中已定义的 27 个字符）：字节 <-> Unicode
CP1252_TO_CP = {0x80:0x20AC,0x82:0x201A,0x83:0x0192,0x84:0x201E,0x85:0x2026,
                0x86:0x2020,0x87:0x2021,0x88:0x02C6,0x89:0x2030,0x8A:0x0160,
                0x8B:0x2039,0x8C:0x0152,0x8E:0x017D,0x91:0x2018,0x92:0x2019,
                0x93:0x201C,0x94:0x201D,0x95:0x2022,0x96:0x2013,0x97:0x2014,
                0x98:0x02DC,0x99:0x2122,0x9A:0x0161,0x9B:0x203A,0x9C:0x0153,
                0x9E:0x017E,0x9F:0x0178}
CP_TO_1252 = {v: k for k, v in CP1252_TO_CP.items()}

# 编码（可读->游戏）时需要回避的原始字节：
#   由本 mod 现有文件逆向推导（Paratranz 转码器规则，569 个去重字符零冲突）：
#   lo 位回避：NUL/CR/LF、空格、! " $ ; = @ \ ] _ { } ~ £ ¤ § ½
#   hi 位回避：空格、[ \ ] _ { } ~ €
#   注：工坊官方汉化语料的回避集略大（多含 # / : [ ），两边解码规则相同。
FORBID_LO = {0x00, 0x0A, 0x0D, 0x20, 0x21, 0x22, 0x24, 0x3B, 0x3D, 0x40,
             0x5C, 0x5D, 0x5F, 0x7B, 0x7D, 0x7E, 0xA3, 0xA4, 0xA7, 0xBD}
FORBID_HI = {0x20, 0x5B, 0x5C, 0x5D, 0x5F, 0x7B, 0x7E, 0x80}


# ---------- 字节流层 ----------

def yml_bytes_to_stream(data: bytes) -> bytes:
    """游戏 yml 文件字节(UTF-8 壳) -> CP1252 字节流"""
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    text = data.decode('utf-8', errors='replace')
    out = bytearray()
    for ch in text:
        cp = ord(ch)
        if cp in CP_TO_1252:            # CP1252 定义区 -> 原字节
            out.append(CP_TO_1252[cp])
        elif cp < 0x100:                # Latin-1 区(含未定义空洞) -> 原字节
            out.append(cp)
        else:                           # 不应出现：真实多字节字符
            out.append(0x3F)
    return bytes(out)


def stream_to_yml_bytes(stream: bytes) -> bytes:
    """CP1252 字节流 -> 游戏 yml 文件字节(UTF-8 壳)"""
    out = []
    for b in stream:
        if b in CP1252_TO_CP:
            out.append(chr(CP1252_TO_CP[b]))
        else:
            out.append(chr(b))
    return b'\xef\xbb\xbf' + ''.join(out).encode('utf-8')


# ---------- 单元编解码 ----------

def decode_units(stream: bytes) -> str:
    """字节流 -> 可读文本（3 字节单元还原为字符）"""
    out = []
    i, n = 0, len(stream)
    while i < n:
        b = stream[i]
        if 0x10 <= b <= 0x13 and i + 2 < n:
            flags = b & 0x03
            lo = stream[i+1]
            hi = stream[i+2]
            if flags & 1:
                lo = (lo - 0x0E) & 0xFF
            if flags & 2:
                hi = (hi + 0x09) & 0xFF
            out.append(chr((hi << 8) | lo))
            i += 3
        else:
            out.append(chr(b))
            i += 1
    return ''.join(out)


def encode_units(text: str) -> bytes:
    """可读文本 -> 字节流（字符转 3 字节单元）

    规则（与原 Paratranz 转码器一致）：码点 < 0x100 的字符（ASCII、
    § · é 等 Latin-1）保持字面单字节；码点 >= 0x100 的字符（汉字、
    全角、弯引号“”、破折号——等）一律编为 3 字节单元。
    """
    out = bytearray()
    for ch in text:
        cp = ord(ch)
        if cp < 0x100:                # 字面字节(yml结构、换行、§色彩码等)
            out.append(cp)
        elif cp > 0xFFFF:
            raise ValueError('码点 U+%04X 超出双字节单元范围' % cp)
        else:
            lo, hi = cp & 0xFF, cp >> 8
            flags = 0
            if lo in FORBID_LO:
                lo = (lo + 0x0E) & 0xFF
                flags |= 1
            if hi in FORBID_HI:
                hi = (hi - 0x09) & 0xFF
                flags |= 2
            out.append(0x10 | flags)
            out.append(lo)
            out.append(hi)
    return bytes(out)


# ---------- 文件级操作 ----------

def decode_yml(in_path, out_path):
    stream = yml_bytes_to_stream(open(in_path, 'rb').read())
    text = decode_units(stream)
    with open(out_path, 'wb') as f:
        f.write(b'\xef\xbb\xbf' + text.encode('utf-8'))


def encode_yml(in_path, out_path):
    data = open(in_path, 'rb').read()
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    text = data.decode('utf-8')
    stream = encode_units(text)
    with open(out_path, 'wb') as f:
        f.write(stream_to_yml_bytes(stream))


def verify_yml(path):
    """往返校验：原文 -> 可读 -> 重编码，字节流必须完全一致"""
    data = open(path, 'rb').read()
    orig_stream = yml_bytes_to_stream(data)
    text = decode_units(orig_stream)
    re_stream = stream_to_yml_bytes(encode_units(text))
    ok = re_stream == data
    n_units = sum(1 for c in text if ord(c) > 0xFF)
    print('%-60s %s （%d 个双字节字符）' % (
        path, '一致 PASS' if ok else '不一致 FAIL', n_units))
    if not ok:
        a, b = data, re_stream
        for i in range(min(len(a), len(b))):
            if a[i] != b[i]:
                print('  首个差异 @0x%X: 原 %02X -> 现 %02X' % (i, a[i], b[i]))
                break
    return ok


def _char_to_byte(ch):
    """文本字符 -> CP1252 字节（用于解析单元载荷）"""
    cp = ord(ch)
    if cp in CP_TO_1252:
        return CP_TO_1252[cp]
    return cp if cp < 0x100 else None


def decode_raw_text(text: str) -> str:
    """脚本文件文本 -> 可读文本（文本级单元解析，注释等其余字符原样保留）。

    脚本文件与 yml 同构（UTF-8 壳 + 单元），但注释是纯 UTF-8 中文，
    故按字符流解析：引导字符 U+0010-U+0013 + 两个可映射字节 = 一个单元。
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        cp = ord(ch)
        if 0x10 <= cp <= 0x13 and i + 2 < n:
            lo = _char_to_byte(text[i+1])
            hi = _char_to_byte(text[i+2])
            if lo is not None and hi is not None:
                flags = cp & 0x03
                if flags & 1:
                    lo = (lo - 0x0E) & 0xFF
                if flags & 2:
                    hi = (hi + 0x09) & 0xFF
                out.append(chr((hi << 8) | lo))
                i += 3
                continue
        out.append(ch)
        i += 1
    return ''.join(out)


def _byte_to_char(b):
    """CP1252 字节 -> 文本字符（UTF-8 壳）"""
    return chr(CP1252_TO_CP[b]) if b in CP1252_TO_CP else chr(b)


def encode_raw_text(text: str) -> str:
    """可读文本 -> 脚本文件文本。

    仅对「双引号字符串内」的 >=0x100 字符转单元；引号外与 # 注释
    （含行中注释）原样保留——脚本文件的注释本来就是纯 UTF-8 中文。
    """
    out = []
    in_string = False
    in_comment = False

    def enc_char(cp):
        lo, hi = cp & 0xFF, cp >> 8
        flags = 0
        if lo in FORBID_LO:
            lo = (lo + 0x0E) & 0xFF
            flags |= 1
        if hi in FORBID_HI:
            hi = (hi - 0x09) & 0xFF
            flags |= 2
        out.append(chr(0x10 | flags))
        out.append(_byte_to_char(lo))
        out.append(_byte_to_char(hi))

    for ch in text:
        cp = ord(ch)
        if in_comment:
            out.append(ch)
            if ch == '\n':
                in_comment = False
            continue
        if ch == '#':
            in_comment = True
            in_string = False
            out.append(ch)
            continue
        if ch == '"':
            in_string = not in_string
            out.append(ch)
            continue
        if in_string and cp >= 0x100:
            enc_char(cp)
        else:
            out.append(ch)
    return ''.join(out)


def _read_utf8(path):
    data = open(path, 'rb').read()
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    return data.decode('utf-8')


def decode_raw(in_path, out_path):
    text = decode_raw_text(_read_utf8(in_path))
    with open(out_path, 'wb') as f:
        f.write(b'\xef\xbb\xbf' + text.encode('utf-8'))


def encode_raw(in_path, out_path):
    with open(out_path, 'wb') as f:
        f.write(encode_raw_text(_read_utf8(in_path)).encode('utf-8'))


def verify_raw(path):
    """脚本文件往返校验：解码 -> 重编码，须与原文件逐字节一致"""
    orig = open(path, 'rb').read()
    re_data = encode_raw_text(decode_raw_text(_read_utf8(path))).encode('utf-8')
    if orig.startswith(b'\xef\xbb\xbf'):
        re_data = b'\xef\xbb\xbf' + re_data
    ok = re_data == orig
    print('%-60s %s' % (path, '一致 PASS' if ok else '不一致 FAIL'))
    if not ok:
        for i in range(min(len(orig), len(re_data))):
            if orig[i] != re_data[i]:
                print('  首个差异 @0x%X: 原 %02X -> 现 %02X' % (i, orig[i], re_data[i]))
                break
    return ok


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'decode' and len(sys.argv) == 4:
        decode_yml(sys.argv[2], sys.argv[3])
    elif cmd == 'encode' and len(sys.argv) == 4:
        encode_yml(sys.argv[2], sys.argv[3])
    elif cmd == 'verify' and len(sys.argv) >= 3:
        ok = all(verify_yml(p) for p in sys.argv[2:])
        sys.exit(0 if ok else 1)
    elif cmd == 'decode-raw' and len(sys.argv) == 4:
        decode_raw(sys.argv[2], sys.argv[3])
    elif cmd == 'encode-raw' and len(sys.argv) == 4:
        encode_raw(sys.argv[2], sys.argv[3])
    elif cmd == 'verify-raw' and len(sys.argv) >= 3:
        ok = all(verify_raw(p) for p in sys.argv[2:])
        sys.exit(0 if ok else 1)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == '__main__':
    main()
