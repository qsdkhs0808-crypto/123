#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import hashlib, json, struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PK_PATH = ROOT / "rdb" / "ScreenLayout.rdb"
CE_PATH = ROOT / "rdb" / "ce" / "ScreenLayout.rdb"
OUT_DIR = ROOT / "dist"
TARGETS = [
    (0x5320BAFB, 0x531DD20B, "3ba570@498f#51", 103, 15, 5291),
    (0xAA8BBC8B, 0xAA8B51E2, "3bef00@7d824#51", 104, 16, 10779),
    (0xBF735461, 0xBF728D66, "43c730@456d9#51", 104, 16, 12045),
    (0xCCE75262, 0xCCE4E2D6, "4dbe10@1ae8#51", 103, 15, 12904),
]
ROOT_ID = 0x8C759C7F
ROOT_DECL = 2259136
EXPECTED_COUNT = 16233

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def parse_rdb(data: bytes, label: str) -> dict:
    if len(data) < 32 or data[:8] != b"_DRK0000":
        raise ValueError(f"{label}: invalid RDB magic")
    hs, unk, count, ih = struct.unpack_from("<4I", data, 8)
    if hs < 24 or hs > len(data):
        raise ValueError(f"{label}: invalid header size {hs}")
    recs, pos = [], hs
    for idx in range(count):
        if pos + 56 > len(data) or data[pos:pos+8] != b"IDRK0000":
            raise ValueError(f"{label}: invalid record header at index {idx}, offset {pos:#x}")
        size, loc_size, decl = struct.unpack_from("<3Q", data, pos+8)
        u20, rid, th, flags, u30, u34 = struct.unpack_from("<6I", data, pos+32)
        if size < 56 or loc_size > size-56:
            raise ValueError(f"{label}: bad size/loc_size at {idx}")
        aligned = (size+3)&~3
        if pos+aligned > len(data):
            raise ValueError(f"{label}: aligned record out of bounds at {idx}")
        meta_size = size-56-loc_size
        meta = data[pos+56:pos+56+meta_size]
        loc_bytes = data[pos+size-loc_size:pos+size] if loc_size else b""
        if loc_bytes and not loc_bytes.endswith(b"\0"):
            raise ValueError(f"{label}: location missing NUL at {idx}")
        loc = loc_bytes[:-1].decode("ascii") if loc_bytes else ""
        recs.append({
            "idx":idx,"offset":pos,"size":size,"aligned":aligned,
            "loc_size":loc_size,"decl":decl,"meta_size":meta_size,"meta":meta,
            "loc_bytes":loc_bytes,"loc":loc,"u20":u20,"rid":rid,"th":th,
            "flags":flags,"u30":u30,"u34":u34,
            "raw":data[pos:pos+size],"pad":data[pos+size:pos+aligned],
        })
        pos += aligned
    if pos != len(data):
        raise ValueError(f"{label}: trailing data or invalid count, parsed={pos}, total={len(data)}")
    roots = [r for r in recs if r["rid"] == ih]
    if len(roots) != 1:
        raise ValueError(f"{label}: expected one root by index_hash, found {len(roots)}")
    ids = [r["rid"] for r in recs]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{label}: duplicate IDs")
    root = roots[0]
    return {"size":len(data),"hs":hs,"unk":unk,"count":count,"ih":ih,
            "header":data[:hs],"records":recs,"root":root,
            "normal":[r for r in recs if r["idx"] != root["idx"]]}

def build_target(ce_rec: dict, rid: int, expected_loc: str) -> dict:
    if not ce_rec["loc"].endswith("#d2f"):
        raise ValueError(f"CE target {rid:08x}: source suffix not #d2f: {ce_rec['loc']}")
    loc = ce_rec["loc"][:-4] + "#51"
    if loc != expected_loc:
        raise ValueError(f"target {rid:08x}: location {loc} != {expected_loc}")
    loc_b = loc.encode("ascii") + b"\0"
    meta = ce_rec["meta"]
    loc_size = len(loc_b)
    size = 56 + len(meta) + loc_size
    aligned = (size+3)&~3
    hdr = struct.pack("<3Q6I", size, loc_size, ce_rec["decl"],
                      ce_rec["u20"], rid, ce_rec["th"], ce_rec["flags"],
                      ce_rec["u30"], ce_rec["u34"])
    raw = b"IDRK0000" + hdr + meta + loc_b
    return {"idx":-1,"size":size,"aligned":aligned,"loc_size":loc_size,
            "decl":ce_rec["decl"],"meta_size":len(meta),"meta":meta,
            "loc":loc,"loc_bytes":loc_b,"u20":ce_rec["u20"],"rid":rid,
            "th":ce_rec["th"],"flags":ce_rec["flags"],"u30":ce_rec["u30"],
            "u34":ce_rec["u34"],"raw":raw,"pad":b"\0"*(aligned-size),"inserted":True}

def main():
    pk_bytes, ce_bytes = PK_PATH.read_bytes(), CE_PATH.read_bytes()
    pk, ce = parse_rdb(pk_bytes, "PK"), parse_rdb(ce_bytes, "CE")
    if pk["ih"] != ROOT_ID or pk["root"]["decl"] != ROOT_DECL:
        raise ValueError("PK root identity/declared value differs from established baseline")
    pk_ids = {r["rid"] for r in pk["records"]}
    pk_normal = {r["rid"]:r for r in pk["normal"]}
    ce_map = {r["rid"]:r for r in ce["records"]}
    insert_after, new_recs = {}, {}
    for rid, anchor, loc, size, loc_size, idx in TARGETS:
        if rid in pk_ids or rid not in ce_map or anchor not in pk_normal:
            raise ValueError(f"missing/duplicate target or anchor for {rid:08x}")
        if ce_map[rid]["meta_size"] != 32:
            raise ValueError(f"unexpected CE metadata length for {rid:08x}")
        nr = build_target(ce_map[rid], rid, loc)
        if nr["size"] != size or nr["loc_size"] != loc_size:
            raise ValueError(f"target record size mismatch for {rid:08x}")
        insert_after[anchor] = rid
        new_recs[rid] = nr

    candidate_recs, actual_idxs = [], {}
    for r in pk["normal"]:
        candidate_recs.append(r)
        if r["rid"] in insert_after:
            rid = insert_after[r["rid"]]
            actual_idxs[rid] = len(candidate_recs)
            candidate_recs.append(new_recs[rid])
    candidate_recs.append(pk["root"])
    if len(candidate_recs) != EXPECTED_COUNT:
        raise ValueError(f"candidate count {len(candidate_recs)} != {EXPECTED_COUNT}")
    for rid, anchor, loc, size, loc_size, idx in TARGETS:
        if actual_idxs.get(rid) != idx:
            raise ValueError(f"index mismatch {rid:08x}: {actual_idxs.get(rid)} != {idx}")
    if candidate_recs[-1]["rid"] != pk["ih"]:
        raise ValueError("PK root not last")

    # Preserve every original header byte; update only the count word at [16:20].
    header = bytearray(pk["header"])
    struct.pack_into("<I", header, 16, len(candidate_recs))
    if header[:16] != pk["header"][:16] or header[20:] != pk["header"][20:]:
        raise ValueError("header bytes other than record count changed")

    out = bytearray(header)
    for r in candidate_recs:
        out.extend(r["raw"])
        out.extend(r["pad"])
    candidate = bytes(out)
    if len(candidate) != len(pk_bytes)+416:
        raise ValueError(f"unexpected candidate file size: {len(candidate)}")

    check = parse_rdb(candidate, "candidate roundtrip")
    if check["count"] != EXPECTED_COUNT or check["unk"] != pk["unk"]:
        raise ValueError("candidate header values mismatch")
    if check["header"][:16] != pk["header"][:16] or check["header"][20:] != pk["header"][20:]:
        raise ValueError("candidate header not preserved")
    if check["root"]["raw"] != pk["root"]["raw"] or check["root"]["decl"] != ROOT_DECL:
        raise ValueError("root record not preserved")

    old_map = {r["rid"]:r for r in pk["records"]}
    new_map = {r["rid"]:r for r in check["records"]}
    if len(old_map) != len(pk["records"]) or any(
        rid not in new_map or new_map[rid]["raw"] != r["raw"]
        for rid,r in old_map.items()
    ):
        raise ValueError("one or more original PK records changed or are missing")

    for rid, anchor, loc, size, loc_size, idx in TARGETS:
        r = new_map[rid]
        if (r["loc"],r["size"],r["loc_size"],r["idx"]) != (loc,size,loc_size,idx):
            raise ValueError(f"inserted target check failed: {rid:08x}")
        if r["meta"] != ce_map[rid]["meta"] or r["decl"] != ce_map[rid]["decl"]:
            raise ValueError(f"target CE metadata/decl mismatch: {rid:08x}")
        if any(r["pad"]):
            raise ValueError(f"nonzero target padding: {rid:08x}")

    ce_ids = [r["rid"] for r in ce["normal"]]
    cand_ids = [r["rid"] for r in check["normal"]]
    common = set(ce_ids) & set(cand_ids)
    if [x for x in ce_ids if x in common] != [x for x in cand_ids if x in common]:
        raise ValueError("relative order mismatch for shared CE/candidate IDs")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = OUT_DIR / "ScreenLayout.rdb"
    out_file.write_bytes(candidate)
    result = {
        "result":"PASS","runtime_game_test":"NOT_TESTED",
        "pk_size":len(pk_bytes),"ce_size":len(ce_bytes),"candidate_size":len(candidate),
        "pk_sha256":sha256(pk_bytes),"ce_sha256":sha256(ce_bytes),
        "candidate_sha256":sha256(candidate),
        "pk_header_unknown":pk["unk"],"candidate_header_unknown":check["unk"],
        "pk_header_count":pk["count"],"candidate_header_count":check["count"],
        "original_pk_records":len(old_map),"original_pk_raw_mismatches":0,
        "shared_ce_candidate_ids":len(common),"shared_relative_order":"PASS",
        "root_id":f"0x{ROOT_ID:08x}","root_declared_size":check["root"]["decl"],
        "root_raw_preserved":True,"bin81_modified":False,
        "targets":[{"id":f"0x{rid:08x}","index":new_map[rid]["idx"],
                    "location":new_map[rid]["loc"],"record_size":new_map[rid]["size"],
                    "location_size":new_map[rid]["loc_size"],"declared_size":new_map[rid]["decl"]}
                   for rid,*_ in TARGETS]
    }
    (OUT_DIR/"validation.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    (OUT_DIR/"SHA256.txt").write_text(f"{sha256(candidate)}  ScreenLayout.rdb\n",encoding="utf-8")
    lines = ["# ScreenLayout.rdb candidate build report","",
             f"- Result: {result['result']}",
             f"- Candidate size: {len(candidate):,} bytes",
             f"- Candidate SHA-256: {sha256(candidate)}",
             f"- Original PK records preserved byte-for-byte: {len(old_map):,}/{len(old_map):,}",
             "- Original PK raw-record mismatches: 0",
             f"- Shared CE/candidate Resource IDs order: PASS ({len(common):,})",
             f"- Root raw record preserved: YES (declared {ROOT_DECL:,})",
             "- Header: all original bytes preserved except record_count [16:20]",
             "- BIN81: not modified; the four existing BIN81 resources are referenced",
             "- Game runtime test: NOT_TESTED","",
             "| Resource ID | Index | Location | Record size | Location size |",
             "|---|---:|---|---:|---:|"]
    for row in result["targets"]:
        lines.append(f"| {row['id']} | {row['index']} | {row['location']} | {row['record_size']} | {row['location_size']} |")
    (OUT_DIR/"BUILD_REPORT.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(json.dumps(result,indent=2))

if __name__ == "__main__":
    main()
