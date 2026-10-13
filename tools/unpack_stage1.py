#!/usr/bin/env python3
"""Static aPLib-compatible recovery of ScreenWings 2.16.1430 .boot -> schiffer.
No sample code is executed. Only stage-one restoration; Themida may remain.
"""
import argparse, collections, hashlib, json, pathlib, struct

SOURCE_SHA = "481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214"
STAGE1_SHA = "2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420"

def unpack(data, start, end, expected):
    raw = memoryview(data)[start:end]
    pos = tag = bitcount = 0
    result = bytearray()
    stats = collections.Counter()
    max_offset = 0
    def byte():
        nonlocal pos
        if pos >= len(raw): raise ValueError("Truncated aPLib input")
        value = raw[pos]; pos += 1
        return value
    def bit():
        nonlocal tag, bitcount
        if not bitcount:
            tag = byte(); bitcount = 8
        bitcount -= 1
        value = (tag >> 7) & 1
        tag = (tag << 1) & 255
        return value
    def gamma():
        value = 1
        while True:
            value = value * 2 + bit()
            if value > expected * 2: raise ValueError("Invalid gamma")
            if not bit(): return value
    def copy(offset, count):
        nonlocal max_offset
        if offset <= 0 or offset > len(result):
            raise ValueError(f"Invalid reference {offset} at result {len(result)}")
        if len(result) + count > expected: raise ValueError("Output overflow")
        max_offset = max(max_offset, offset)
        if count:
            pattern = result[-offset:]
            result.extend((pattern * ((count + offset - 1) // offset))[:count])
    result.append(byte())
    previous = -1
    last_was_match = False
    for _ in range(20000000):
        if bit():
            if bit():
                if bit():
                    offset = 0
                    for i in range(4): offset = (offset << 1) + bit()
                    if offset: copy(offset, 1)
                    else: result.append(0)
                    last_was_match = False
                    stats["single"] += 1
                else:
                    offset = byte()
                    count = 2 + (offset & 1)
                    offset >>= 1
                    if not offset:
                        stats["terminator"] += 1
                        break
                    copy(offset, count)
                    previous = offset
                    last_was_match = True
                    stats["short"] += 1
            else:
                code = gamma()
                if not last_was_match and code == 2:
                    offset, count = previous, gamma()
                    stats["reuse"] += 1
                else:
                    code -= 2 if last_was_match else 3
                    offset = (code << 8) + byte()
                    count = gamma()
                    if offset >= 32000: count += 1
                    if offset >= 1280: count += 1
                    if offset < 128: count += 2
                    stats["long"] += 1
                copy(offset, count)
                previous = offset
                last_was_match = True
        else:
            result.append(byte())
            last_was_match = False
            stats["literal"] += 1
        if len(result) > expected: raise ValueError("Output overflow")
    else:
        raise ValueError("No terminator")
    if len(result) != expected: raise ValueError(f"Wrong result size {len(result)}")
    return bytes(result), pos, dict(stats), max_offset

def main():
    a = argparse.ArgumentParser()
    a.add_argument("sample", type=pathlib.Path)
    a.add_argument("--out", type=pathlib.Path, default=pathlib.Path("analysis/stage1"))
    args = a.parse_args()
    sample = args.sample.read_bytes()
    sha = hashlib.sha256(sample).hexdigest()
    if sha != SOURCE_SHA: raise ValueError(f"Specimen SHA mismatch: {sha}")
    pe = struct.unpack_from("<I", sample, 0x3c)[0]
    if sample[pe:pe+4] != b"PE\0\0": raise ValueError("Not PE")
    opt = pe + 24
    n = struct.unpack_from("<H", sample, pe+6)[0]
    hdr = opt + struct.unpack_from("<H", sample, pe+20)[0]
    sections = {}
    for i in range(n):
        h = hdr + 40*i
        key = sample[h:h+8].split(b"\0")[0].decode("latin1")
        vs, va, sz, raw = struct.unpack_from("<IIII", sample, h+8)
        sections[key] = {"hdr":h, "vs":vs, "rva":va, "size":sz, "raw":raw}
    sch, boot = sections["schiffer"], sections[".boot"]
    if sch["vs"] != 0x672000 or sch["size"] or boot["rva"] != 0x704000:
        raise ValueError("Unexpected packed layout")
    if struct.unpack_from("<I", sample, opt+16)[0] != 0x704108:
        raise ValueError("Unexpected entry point")
    start = boot["raw"] + 0x29f
    end = boot["raw"] + boot["size"]
    restored, used, counts, maxref = unpack(sample, start, end, sch["vs"])
    restored_sha = hashlib.sha256(restored).hexdigest()
    if restored_sha != STAGE1_SHA:
        raise ValueError(f"Restored hash mismatch: {restored_sha}")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "schiffer_stage1.bin").write_bytes(restored)
    # Analysis-only PE, packed stub retained; never execute this reconstruction.
    modified = bytearray(sample[:boot["raw"]] + restored + sample[boot["raw"]:])
    struct.pack_into("<I", modified, sch["hdr"]+16, len(restored))
    struct.pack_into("<I", modified, sch["hdr"]+20, boot["raw"])
    struct.pack_into("<I", modified, boot["hdr"]+20, boot["raw"]+len(restored))
    cert_field = opt + 96 + 4*8
    cert_off = struct.unpack_from("<I", sample, cert_field)[0]
    if cert_off:
        struct.pack_into("<I", modified, cert_field, cert_off+len(restored))
    entry_rva = sch["rva"] + 0x27709a
    struct.pack_into("<I", modified, opt+16, entry_rva)
    struct.pack_into("<I", modified, opt+64, 0)
    (args.out / "ScreenWings_stage1_for_Ghidra_DO_NOT_RUN.exe").write_bytes(modified)
    report = dict(source_sha256=sha, stage1_sha256=restored_sha,
                  stage1_bytes=len(restored), packed_entry="0xB04108",
                  decompressed_entry_va=hex(0x400000+entry_rva),
                  decompressed_entry_rva=hex(entry_rva),
                  compressed_input_offset=hex(start),
                  compressed_bytes_consumed=used,
                  compressed_bytes_remaining=end-start-used,
                  max_backref=maxref, commands=counts,
                  limitation="Stage 1 only; still protected by Themida/WinLicense; not original source code")
    (args.out / "report.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
