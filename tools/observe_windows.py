#!/usr/bin/env python3
"""Read-only Win32 top-level window / display-affinity survey. Windows only.
Run this in a disposable VM with ScreenWings off, then on, preserving JSONL.
No process memory writes, API hooks, or application launches.
"""
import argparse, ctypes as C, datetime as dt, json, sys
from ctypes import wintypes as W
if sys.platform != "win32":
    raise SystemExit("This tool runs on Windows, not Linux/macOS.")
class RECT(C.Structure):
    _fields_=[(x,W.LONG) for x in ("left","top","right","bottom")]
u=C.WinDLL("user32",use_last_error=True)
def api(name,result,args):
    f=getattr(u,name);f.restype=result;f.argtypes=args;return f
getpid=api("GetWindowThreadProcessId",W.DWORD,[W.HWND,C.POINTER(W.DWORD)])
getrect=api("GetWindowRect",W.BOOL,[W.HWND,C.POINTER(RECT)])
getaff=api("GetWindowDisplayAffinity",W.BOOL,[W.HWND,C.POINTER(W.DWORD)])
getclass=api("GetClassNameW",C.c_int,[W.HWND,W.LPWSTR,C.c_int])
gettitle=api("GetWindowTextW",C.c_int,[W.HWND,W.LPWSTR,C.c_int])
isvisible=api("IsWindowVisible",W.BOOL,[W.HWND])
getstyle=api("GetWindowLongW",W.LONG,[W.HWND,C.c_int])
CB=C.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
enumerate_windows=api("EnumWindows",W.BOOL,[CB,W.LPARAM])
names={0:"WDA_NONE",1:"WDA_MONITOR",17:"WDA_EXCLUDEFROMCAPTURE"}
def inspect(h):
    pid=W.DWORD();getpid(h,C.byref(pid))
    r=RECT();ok=bool(getrect(h,C.byref(r)))
    cls=C.create_unicode_buffer(260);getclass(h,cls,len(cls))
    title=C.create_unicode_buffer(512);gettitle(h,title,len(title))
    affinity=W.DWORD();C.set_last_error(0)
    affinity_ok=bool(getaff(h,C.byref(affinity)))
    err=C.get_last_error() if not affinity_ok else None
    ext=getstyle(h,-20)&0xffffffff
    return dict(utc=dt.datetime.now(dt.timezone.utc).isoformat(),hwnd=f"0x{int(h):x}",
        pid=pid.value,window_class=cls.value,title=title.value,
        visible=bool(isvisible(h)),rect=[r.left,r.top,r.right,r.bottom] if ok else None,
        extended_style=f"0x{ext:08x}",layered=bool(ext&0x80000),
        transparent=bool(ext&0x20),topmost_style=bool(ext&0x8),
        affinity=f"0x{affinity.value:x}" if affinity_ok else None,
        affinity_name=names.get(affinity.value,"UNKNOWN") if affinity_ok else None,
        affinity_error=err)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--pid",type=int,help="Only inspect this process ID")
    p.add_argument("--all",action="store_true",help="Include hidden windows")
    p.add_argument("--output",default="-",help="JSONL pathname or '-' for stdout")
    a=p.parse_args();rows=[]
    @CB
    def cb(h,_):
        v=inspect(h)
        if (not a.pid or v["pid"]==a.pid) and (a.all or v["visible"]):
            rows.append(v)
        return True
    if not enumerate_windows(cb,0):
        raise OSError(C.get_last_error(),"EnumWindows failed")
    data="".join(json.dumps(row,ensure_ascii=False)+"\n" for row in rows)
    if a.output=="-":sys.stdout.write(data)
    else:
        with open(a.output,"w",encoding="utf-8") as f:f.write(data)
    print(f"Read-only survey: {len(rows)} windows",file=sys.stderr)
if __name__=="__main__":main()
