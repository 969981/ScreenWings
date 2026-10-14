#!/usr/bin/env python3
"""Triage WinDbg logs from make_p0_av_proof.py. Does NOT execute Windows.
Missing event/log means inconclusive and never implies absence of AV/SEH.
"""
import argparse,json,pathlib,re
MARKERS=re.compile(r'^\s*(P0_(?:FIRST_CHANCE_AV|SECOND_CHANCE_AV|HANDLER_HIT|[A-Z0-9_]+))\s*$',re.M)
EIP=re.compile(r'\beip\s*=\s*([0-9a-f\x60]{8,17})',re.I)
CODE=re.compile(r'\bExceptionCode\s*:\s*([0-9a-f]{8})',re.I)
ADDRESS=re.compile(r'\bExceptionAddress\s*:\s*([0-9a-f\x60]{8,17})',re.I)
FAULT=re.compile(r'(?:read from|write to|execute at) address\s+([0-9a-f\x60]{8,17})',re.I)

def numeric(s):
    return int(s.replace(chr(96),''),16) if s else None

def summarize(text,base):
    target=base+0x13D2EF
    matches=list(MARKERS.finditer(text))
    events=[]
    for i,m in enumerate(matches):
        end=matches[i+1].start() if i+1<len(matches) else len(text)
        chunk=text[m.end():end]
        def get(regex):
            match=regex.search(chunk)
            return numeric(match.group(1)) if match else None
        eip,code,address,fault=get(EIP),get(CODE),get(ADDRESS),get(FAULT)
        events.append({
            "marker":m.group(1),
            "eip":hex(eip) if eip is not None else None,
            "exception_code":hex(code) if code is not None else None,
            "exception_address":hex(address) if address is not None else None,
            "fault_access_address":hex(fault) if fault is not None else None,
            "eip_matches_model_cutoff":eip==target if eip is not None else None,
            "invalid_exception_chain_reported":"invalid exception stack" in chunk.lower(),
            "log_evidence_excerpt":chunk[:1500]})
    first=[x for x in events if x["marker"]=="P0_FIRST_CHANCE_AV" and x["exception_code"]=="0xc0000005"]
    matching=[x for x in first if x["eip_matches_model_cutoff"] or x["exception_address"]==hex(target)]
    second=[x for x in events if x["marker"]=="P0_SECOND_CHANCE_AV" and x["exception_code"]=="0xc0000005"]
    handlers=[x for x in events if x["marker"]=="P0_HANDLER_HIT"]
    return {
        "type":"WINDBG_LOG_TRIAGE_NOT_A_NATIVE_EXECUTION",
        "runtime_imagebase_supplied":hex(base),
        "expected_model_cutoff_runtime_va":hex(target),
        "has_event_markers":bool(matches),
        "first_chance_access_violations":len(first),
        "at_model_cutoff_first_chance_count":len(matching),
        "second_chance_access_violations":len(second),
        "labeled_handler_hits":len(handlers),
        "supports_native_first_chance_at_model_cutoff":bool(matching),
        "supports_observed_handler_entry":bool(handlers),
        "proves_handler_caught_this_exact_fault":False,
        "proof_gap":"Correlate same thread's SEH chain/handler entry and show actual recovery EIP. No second chance alone is insufficient.",
        "no_event_warning":"No P0 event markers: no runtime path conclusions possible." if not matches else None,
        "events":events}

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("windbg_log",type=pathlib.Path)
    p.add_argument("--runtime-base",required=True,type=lambda s:int(s,0))
    p.add_argument("--out",type=pathlib.Path)
    a=p.parse_args()
    if not a.windbg_log.exists():raise SystemExit("Missing WinDbg log: native evidence has not been collected")
    report=summarize(a.windbg_log.read_text(encoding="utf-8-sig",errors="replace"),a.runtime_base)
    result=json.dumps(report,ensure_ascii=False,indent=2)+"\n"
    if a.out:a.out.write_text(result,encoding="utf-8")
    else:print(result,end="")
