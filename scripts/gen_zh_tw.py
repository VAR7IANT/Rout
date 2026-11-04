#!/usr/bin/env python3
"""Regenerate internal/rout/messages_zh_tw.json (Traditional Chinese, Taiwan) from the
Simplified Chinese catalog keys in internal/rout/messages.json.

Developer tool only (not used at build or run time). Requires OpenCC:
    python3 -m venv /tmp/occ && /tmp/occ/bin/pip install opencc
    /tmp/occ/bin/python scripts/gen_zh_tw.py
Entries listed in OVERRIDES win over the automatic conversion.
"""
import json
import os
import re
import sys

import opencc

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "internal", "rout", "messages.json")
OUT = os.path.join(ROOT, "internal", "rout", "messages_zh_tw.json")
HAN = re.compile(r"[㐀-鿿]")

# Terms where the phrase converter picks a reading that does not fit a server tool.
OVERRIDES = {
    "後臺": "背景",
    "釋出": "發布",
    "型別": "類型",
    "證書": "憑證",
    "協議": "協定",
    "對映": "映射",
    "自籤": "自簽",
    "籤發": "簽發",
    "籤名": "簽名",
    "引數": "參數",
    "天后": "天後",
}
# Single-character fallback corrections (used only for text outside the catalog).
CHAR_OVERRIDES = {"签": "簽"}
# "端口" becomes the IT term 埠; Taiwan interfaces write 連接埠.
PORT = re.compile(r"(?<!接)埠")

def main() -> int:
    conv = opencc.OpenCC("s2twp")
    chars_conv = opencc.OpenCC("s2t")
    with open(SRC, encoding="utf-8") as f:
        keys = list(json.load(f))
    out, chars = {}, {}
    for k in keys:
        if not HAN.search(k) or k.startswith("请选择语言 /"):
            continue  # the bilingual language prompt is shown verbatim
        v = conv.convert(k)
        for a, b in OVERRIDES.items():
            v = v.replace(a, b)
        v = PORT.sub("連接埠", v)
        out[k] = v
        for c in k:
            if HAN.match(c):
                t = chars_conv.convert(c)
                if t != c:
                    chars[c] = t
    # A character the phrase converter deliberately kept somewhere is ambiguous (游/遊,
    # 后/後, ...): converting it blindly in the fallback would be wrong, so drop it.
    for c in list(chars):
        if any(c in v for v in out.values()):
            del chars[c]
    chars.update(CHAR_OVERRIDES)
    data = {"messages": out, "chars": dict(sorted(chars.items()))}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=0, sort_keys=False)
        f.write("\n")
    print(f"{len(out)} messages, {len(chars)} characters -> {OUT}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
