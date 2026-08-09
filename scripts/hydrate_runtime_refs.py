#!/usr/bin/env python3
"""Extend KeyMint DT_NEEDED closure with exact stock init-time references."""
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess
from collections import deque
from pathlib import Path

POINTER=b"version https://git-lfs.github.com/spec/v1"
TERMS=("keymint","keymaster","gatekeeper","trustonic","mobicore","mcdriver","mcregistry","tee-service","kmsetkey","secureclock","sharedsecret","weaver")
ROOTS=("vendor/bin","vendor/lib64","vendor/lib","vendor/etc/init","odm/bin","odm/lib64","odm/lib","odm/etc/init","system_ext/bin","system_ext/lib64","system_ext/lib","product/bin","product/lib64","product/lib","system/system/bin","system/system/lib64","system/system/lib")
PLATFORM={"ld-android.so","libandroidicu.so","libbase.so","libbinder.so","libbinder_ndk.so","libc++.so","libc.so","libcgrouprc.so","libcrypto.so","libcutils.so","libdl.so","libhardware.so","libhidlbase.so","libjsoncpp.so","liblog.so","libm.so","libprocessgroup.so","libprotobuf-cpp-lite.so","libselinux.so","libutils.so","libz.so"}

def pointer(p:Path)->bool:
    try:return p.read_bytes()[:80].startswith(POINTER)
    except OSError:return False

def cmd(a:list[str],cwd:Path,data:bytes|None=None):
    env=os.environ.copy();env["GIT_LFS_SKIP_SMUDGE"]="0"
    return subprocess.run(a,cwd=cwd,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,env=env)

def materialize(root:Path,rel:str,index:set[str])->Path|None:
    rel=rel.replace("\\","/").lstrip("/");p=root/rel
    if rel not in index and not p.is_file():return None
    p.parent.mkdir(parents=True,exist_ok=True)
    if p.is_file() and not pointer(p):return p
    if (root/".git").is_dir() and shutil.which("git"):
        cmd(["git","lfs","pull","--include="+rel,"--exclude="],root)
        if p.is_file() and not pointer(p):return p
        shown=cmd(["git","show","HEAD:"+rel],root)
        if shown.returncode==0 and shown.stdout:
            data=shown.stdout
            if data[:80].startswith(POINTER):
                smudged=cmd(["git","lfs","smudge"],root,data)
                if smudged.returncode==0 and smudged.stdout and not smudged.stdout[:80].startswith(POINTER):data=smudged.stdout
            p.write_bytes(data)
    return p if p.is_file() and not pointer(p) else None

def candidates(runtime:str,index:set[str])->list[str]:
    runtime=runtime.strip().strip('"\'').rstrip("\\")
    if not runtime.startswith("/"):return []
    raw=runtime.lstrip("/");out=[]
    seeds=["system/"+raw,raw] if raw.startswith("system/") else [raw]
    suffix="/".join(Path(raw).parts[-3:]);name=Path(raw).name
    for x in seeds+sorted(x for x in index if x.endswith("/"+suffix))+sorted(x for x in index if Path(x).name==name):
        if x in index and x not in out:out.append(x)
    return out

def needed(p:Path)->list[str]:
    if pointer(p) or not shutil.which("readelf"):return []
    r=subprocess.run(["readelf","-d",str(p)],text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    return sorted(set(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]",r.stdout))) if r.returncode==0 else []

def runtime_target_kind(rel:str)->str:
    low=rel.lower()
    if low.endswith(".drbin") or "/mcregistry/" in low:return "trustonic-runtime-artifact"
    if low.endswith(".rc"):return "security-init-runtime"
    if "/bin/" in f"/{low}/":return "security-runtime-service"
    if low.endswith(".so"):return "runtime-dt-needed"
    return "security-runtime-reference"

def parse_rc(text:str):
    required:set[str]=set();optional:set[str]=set();services:set[str]=set();directories:set[str]=set()
    for line in text.splitlines():
        s=line.strip()
        if not s or s.startswith("#"):continue
        m=re.match(r"service\s+\S+\s+(/[^\s\\]+)",s)
        if m:services.add(m.group(1));required.add(m.group(1))
        m=re.match(r"import\s+(/[^\s\\]+)",s)
        if m:required.add(m.group(1))
        m=re.search(r"(?:^|\s)--\s+(/[^\s\\]+)",s)
        if m:required.add(m.group(1))
    for m in re.finditer(r"(?m)(?:^|\s)-r\s+(/[^\s\\]+)",text):
        v=m.group(1);(optional if v.startswith("/apex/") else required).add(v)
    for m in re.finditer(r"(?:^|\s)--P1\s+(/[^\s\\]+)",text):directories.add(m.group(1))
    return required,optional,services,directories

def collect(root:Path,report_path:Path)->dict:
    report=json.loads(report_path.read_text());idx=root/".treeforge-index.txt"
    index=set(idx.read_text(errors="replace").splitlines()) if idx.is_file() else {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and "/.git/" not in f"/{p}/"}
    files={str(x["path"]):dict(x) for x in report.get("copy_files",[]) if x.get("path")}
    rc={p for p in files if p.endswith(".rc")}
    for prefix in ("vendor/etc/init","odm/etc/init","system_ext/etc/init","product/etc/init"):
        base=root/prefix
        if base.is_dir():
            for p in base.rglob("*.rc"):
                text="" if pointer(p) else p.read_text(errors="replace")
                if any(t in (p.name+"\n"+text).lower() for t in TERMS):rc.add(p.relative_to(root).as_posix())
    required:set[str]=set();optional:set[str]=set();services:set[str]=set();directories:set[str]=set();scanned:set[str]=set();q=deque(sorted(rc))
    while q:
        rel=q.popleft()
        if rel in scanned:continue
        p=materialize(root,rel,index)
        if not p:required.add("/"+rel);continue
        scanned.add(rel);files.setdefault(rel,{"path":rel,"role":runtime_target_kind(rel)})
        a,b,c,d=parse_rc(p.read_text(errors="replace"));required|=a;optional|=b;services|=c;directories|=d
        for x in sorted(a|b):
            if x.endswith(".rc"):
                choices=candidates(x,index)
                if choices and choices[0] not in scanned:q.append(choices[0])
    resolved={};unresolved=set();optional_unresolved=set()
    for runtime,is_optional in [(x,False) for x in sorted(required)]+[(x,True) for x in sorted(optional)]:
        chosen=None
        for rel in candidates(runtime,index):
            if materialize(root,rel,index):chosen=rel;break
        if chosen:
            resolved[runtime]=chosen;files.setdefault(chosen,{"path":chosen,"role":runtime_target_kind(chosen)})
        elif is_optional:optional_unresolved.add(runtime)
        else:unresolved.add(runtime)
    all_paths=[]
    for prefix in ROOTS:
        base=root/prefix
        if base.is_dir():all_paths += [p.relative_to(root).as_posix() for p in base.rglob("*") if p.is_file()]
    libs={}
    for rel in all_paths:
        if rel.endswith(".so"):libs.setdefault(Path(rel).name,[]).append(rel)
    dependencies={str(k):list(v) for k,v in report.get("dependencies",{}).items()};unresolved_libs=set(report.get("unresolved_vendor_libraries",[]));queue=deque(sorted(r for r in files if r.endswith(".so") or "/bin/" in f"/{r}/"));parsed=set(dependencies)
    while queue:
        rel=queue.popleft()
        if rel in parsed:continue
        p=materialize(root,rel,index)
        if not p:unresolved.add("/"+rel);continue
        parsed.add(rel);dependencies[rel]=needed(p)
        origin64="/lib64/" in f"/{rel}/"
        for lib in dependencies[rel]:
            choices=libs.get(lib,[])
            if not choices:
                if lib not in PLATFORM:unresolved_libs.add(lib)
                continue
            choices.sort(key=lambda x:(x.split('/',1)[0]!=rel.split('/',1)[0],("/lib64/" in f"/{x}/")!=origin64,x));chosen=choices[0]
            p2=materialize(root,chosen,index)
            if not p2:unresolved_libs.add(lib);continue
            if chosen not in files:files[chosen]={"path":chosen,"role":runtime_target_kind(chosen)};queue.append(chosen)
    pointers=sorted(r for r in files if not (root/r).is_file() or pointer(root/r));unresolved_libs|={"runtime-path:"+x for x in unresolved}
    copy=[]
    for rel in sorted(files):
        p=root/rel
        if p.is_file() and not pointer(p):
            item=dict(files[rel]);item.update(path=rel,bytes=p.stat().st_size);copy.append(item)
    report.update(schema_version=2,strategy="stock-keymint-readelf-and-init-runtime-closure",copy_files=copy,dependencies=dependencies,unresolved_vendor_libraries=sorted(unresolved_libs),lfs_pointers=pointers,closure_count=len(copy),runtime_references={"security_init_rc":sorted(scanned),"required":sorted(required),"resolved":resolved,"unresolved":sorted(unresolved),"optional_unresolved":sorted(optional_unresolved),"service_binaries":sorted(services),"required_directories":sorted(directories),"registry_artifacts":sorted(x for x in resolved if x.endswith(".drbin") or "/mcRegistry/" in x)})
    report_path.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n");return report

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--dump",required=True);ap.add_argument("--report",required=True);a=ap.parse_args();r=collect(Path(a.dump).resolve(),Path(a.report).resolve());refs=r["runtime_references"]
    print(f">> security init rc: {len(refs['security_init_rc'])}");print(f">> security runtime refs: {len(refs['resolved'])} resolved");print(f">> crypto closure after runtime refs: {len(r['copy_files'])}")
    if refs["optional_unresolved"]:print("::warning::optional APEX security artifacts unavailable: "+", ".join(refs["optional_unresolved"]))
    failures=list(refs["unresolved"])+list(r.get("lfs_pointers",[]))
    if failures:print("::error::required security runtime references are incomplete: "+", ".join(failures));return 2
    if r.get("unresolved_vendor_libraries"):print("::error::runtime security libraries are unresolved: "+", ".join(r["unresolved_vendor_libraries"]));return 2
    return 0
if __name__=="__main__":raise SystemExit(main())
