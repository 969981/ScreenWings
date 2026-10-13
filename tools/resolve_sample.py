#!/usr/bin/env python3
"""Retrieve *data only*, never execute it. Verify the exact ScreenWings specimen SHA256.
Accept a local EXE, an HTTPS EXE, or a ZIP containing exactly the expected EXE.
"""
import argparse, hashlib, io, pathlib, urllib.request, zipfile

EXPECTED="481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214"
MAX_BYTES=100*1024*1024
# No implicit remote URL: the historical vendor endpoint returned a non-EXE/non-ZIP
# response in GitHub Actions run #4, so choosing it without consent is unreliable.

def extract(b):
    if b[:2] == b"MZ":
        return b
    if b[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(b)) as z:
            candidates=[]
            for f in z.infolist():
                if f.is_dir() or f.file_size>MAX_BYTES or not f.filename.lower().endswith(".exe"):
                    continue
                exe=z.read(f)
                if hashlib.sha256(exe).hexdigest()==EXPECTED:
                    candidates.append(exe)
            if len(candidates)!=1:
                raise ValueError(f"ZIP has {len(candidates)} EXEs matching expected checksum")
            return candidates[0]
    raise ValueError("Download is neither a PE EXE nor a ZIP containing one")

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--sample",type=pathlib.Path,default=pathlib.Path("samples/ScreenWings.exe"))
    a.add_argument("--url",default=None)
    args=a.parse_args()
    if args.sample.exists():
        data=args.sample.read_bytes()
    else:
        if not args.url: raise ValueError("No original specimen present. Add samples/ScreenWings.exe or pass --url HTTPS_DIRECT_DOWNLOAD (checksum verified).")
        if not args.url.startswith("https://"): raise ValueError("Only HTTPS URL permitted")
        req=urllib.request.Request(args.url,headers={"User-Agent":"ScreenWings-research/1.0"})
        with urllib.request.urlopen(req,timeout=60) as response:
            data=response.read(MAX_BYTES+1)
        if len(data)>MAX_BYTES: raise ValueError("Oversized download")
        data=extract(data)
    actual=hashlib.sha256(data).hexdigest()
    if actual!=EXPECTED:
        raise ValueError(f"SHA256 mismatch! Expected {EXPECTED}, got {actual}; source changed")
    args.sample.parent.mkdir(parents=True,exist_ok=True)
    args.sample.write_bytes(data)
    print(f"VERIFIED {args.sample}, {len(data)} bytes, SHA256={actual}")

if __name__=="__main__":
    main()
