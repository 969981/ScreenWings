#!/usr/bin/env python3
"""Compare read-only before/after Win32 HWND-affinity JSONL snapshots."""
import argparse,json,pathlib
def read(path):
    rows=[json.loads(line) for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    return {row["hwnd"]:row for row in rows}
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("off");ap.add_argument("on");ap.add_argument("--json",action="store_true")
    a=ap.parse_args();before=read(a.off);after=read(a.on);events=[]
    fields=("pid","window_class","rect","visible","extended_style","affinity","affinity_name","affinity_error")
    for hwnd in sorted(set(before)|set(after)):
        old=before.get(hwnd);new=after.get(hwnd)
        if old is None:events.append(dict(change="window_created",hwnd=hwnd,after=new));continue
        if new is None:events.append(dict(change="window_removed",hwnd=hwnd,before=old));continue
        delta={key:dict(before=old.get(key),after=new.get(key)) for key in fields if old.get(key)!=new.get(key)}
        if delta:events.append(dict(change="window_modified",hwnd=hwnd,changes=delta))
    if a.json:print(json.dumps(events,ensure_ascii=False,indent=2))
    else:
        for event in events:
            print(event["change"],event["hwnd"])
            for k,v in event.get("changes",{}).items():print(" ",k,":",v["before"],"->",v["after"])
        print("Changes:",len(events))
if __name__=="__main__":main()
