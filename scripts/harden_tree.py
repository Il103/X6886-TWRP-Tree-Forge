#!/usr/bin/env python3
"""Apply and audit X6886 TWRP 14.1 hardening from fresh A16 evidence only."""
from __future__ import annotations
import argparse,hashlib,json,re,shutil
from pathlib import Path
from typing import Any

def load(p:Path)->dict[str,Any]:return json.loads(p.read_text())
def save(p:Path,v:Any):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,indent=2,sort_keys=True)+"\n")
def digest(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
def unique(xs):return list(dict.fromkeys(x for x in xs if x))
def modules(p:Path):return unique(Path(x.strip()).name for x in p.read_text(errors="replace").splitlines() if x.strip() and not x.lstrip().startswith("#"))
def target(rel:str)->str:
    rel=rel.replace("\\","/").lstrip("/")
    if rel.startswith("system/system/"):rel=rel[len("system/"):]
    return "recovery/root/"+rel
def runtime(rel:str)->str:
    rel=rel.replace("\\","/").lstrip("/")
    if rel.startswith("system/system/"):rel=rel[len("system/"):]
    return "/"+rel
def copy(src:Path,dst:Path):dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst)
def record(prov:dict,dump:Path,src:Path,dst:str):
    items=prov.setdefault("copied_from_android16_dump",[]);items[:]=[x for x in items if x.get("to")!=dst];items.append({"from":src.relative_to(dump).as_posix(),"to":dst})
def module_source(dump:Path,facts:dict)->Path|None:
    m=facts.get("kernel",{}).get("modules",{});preferred=m.get("recovery_load_file")
    if preferred and (dump/preferred).is_file():return dump/preferred
    found=[dump/x.get("path","") for x in m.get("load_files",[]) if Path(str(x.get("path",""))).name=="modules.load.recovery" and (dump/x.get("path","")).is_file()]
    return sorted(found,key=lambda p:("vendor_boot/ramdisk" not in p.as_posix(),p.as_posix()))[0] if found else None
def security_rc(facts:dict)->list[str]:
    paths=unique(str(x.get("path","")) for x in facts.get("crypto",{}).get("copy_files",[]) if str(x.get("path","")).endswith(".rc") and "/etc/init/" in str(x.get("path","")))
    def rank(p):
        x=p.lower()
        return (0 if x.endswith("/trustonic.rc") or "mobicore" in x or "mcdriver" in x else 1 if "tee" in x else 2 if "keymint" in x or "keymaster" in x else 3 if "gatekeeper" in x else 4,p)
    return sorted(paths,key=rank)
def android_fstab(text:str)->bool:
    return any(len(x.split())>=5 and x.split()[1].startswith("/") and "logical" in x.split()[4].lower() for x in text.splitlines() if x.strip() and not x.lstrip().startswith("#"))

def apply(dump:Path,facts_path:Path,tree:Path)->dict:
    facts=load(facts_path);prov_path=tree/"_provenance/copied-files.json";prov=load(prov_path)
    platform=str(facts.get("identity",{}).get("platform",{}).get("value","mt6789"));src=module_source(dump,facts)
    if not src:raise RuntimeError("fresh dump has no recovery module load file")
    names=modules(src)
    if not names:raise RuntimeError("stock recovery module order is empty")
    module_dst="prebuilt/modules/modules.load.recovery";copy(src,tree/module_dst);record(prov,dump,src,module_dst)
    board_path=tree/"BoardConfig.mk";board=board_path.read_text()
    board=re.sub(r"(?m)^\s*TW_LOAD_VENDOR_(?:BOOT_)?MODULES(?:_EXCLUDE_GKI)?\s*:?=.*(?:\n|$)","",board)
    block="# Exact fresh Android 16 modules.load.recovery; enables official TWRP 14.1 loader.\nTW_LOAD_VENDOR_MODULES := \""+" ".join(names)+"\"\nTW_LOAD_VENDOR_MODULES_EXCLUDE_GKI := true\nTW_LOAD_VENDOR_BOOT_MODULES := true\n"
    marker="# KeyMint/Gatekeeper services and DT_NEEDED closure are copied from stock A16."
    board=board.replace(marker,block+"\n"+marker,1) if marker in board else board.rstrip()+"\n\n"+block
    board_path.write_text(board.rstrip()+"\n")
    state={"schema_version":1,"source_android":16,"recovery_base":"twrp-14.1","old_tree_used":False,"module_load":{"source":src.relative_to(dump).as_posix(),"target":module_dst,"sha256":digest(src),"count":len(names),"modules":names},"official_twrp_module_loader":{"commit":"426b747737e7ce9e9e17da5b4d2ba883f296aec7","rule":"TW_LOAD_VENDOR_MODULES must be non-empty"}}
    selected=facts.get("partitions",{}).get("selected_fstab")
    if selected and (dump/selected).is_file() and android_fstab((dump/selected).read_text(errors="replace")):
        dst="recovery/root/system/etc/recovery.fstab";copy(dump/selected,tree/dst);record(prov,dump,dump/selected,dst);state["recovery_fstab"]={"source":selected,"target":dst,"sha256":digest(dump/selected),"mode":"exact-stock-android-fs-mgr"}
    recovery=dump/"vendor_boot/recovery_ramdisk";platform_root=dump/"vendor_boot/ramdisk";stock_rc=[]
    for kind,root in (("recovery",recovery),("platform",platform_root)):
        if not root.is_dir():continue
        for source in sorted(root.rglob("*.rc")):
            name=source.name
            if kind=="platform" and not (name.startswith("init.recovery.") or name.startswith("init."+platform) or name.startswith("ueventd."+platform) or (name=="ueventd.rc" and not (tree/"recovery/root/ueventd.rc").exists())):continue
            dst=(Path("recovery/root")/source.relative_to(root)).as_posix();out=tree/dst
            if kind=="platform" and out.is_file() and out.read_bytes()!=source.read_bytes():continue
            copy(source,out);record(prov,dump,source,dst);stock_rc.append({"source":source.relative_to(dump).as_posix(),"target":dst})
    state["stock_runtime_rc"]=stock_rc
    fstabs=[p for p in platform_root.rglob("fstab*") if p.is_file()] if platform_root.is_dir() else []
    fstabs.sort(key=lambda p:(p.name!="fstab."+platform,"first_stage_ramdisk" not in p.as_posix(),p.as_posix()))
    if fstabs:
        source=fstabs[0];dst="recovery/root/first_stage_ramdisk/"+source.name;copy(source,tree/dst);record(prov,dump,source,dst);state["first_stage_fstab"]={"source":source.relative_to(dump).as_posix(),"target":dst,"sha256":digest(source)}
    imports=[runtime(x) for x in security_rc(facts)];project=tree/"recovery/root/init.recovery.project.rc";project.parent.mkdir(parents=True,exist_ok=True);project.write_text("# Generated import bridge from exact Android 16 stock security rc files.\n"+"".join("import "+x+"\n" for x in imports))
    line="import /init.recovery.project.rc";init_files=sorted((tree/"recovery/root").glob("init.recovery."+platform+"*.rc"));reach=[p for p in init_files if line in p.read_text(errors="replace")]
    if not reach and init_files:
        p=init_files[0];dst=p.relative_to(tree).as_posix();backup=tree/"_provenance"/("stock-"+p.name);backup.write_bytes(p.read_bytes());prov["copied_from_android16_dump"]=[x for x in prov.get("copied_from_android16_dump",[]) if x.get("to")!=dst];p.write_text(p.read_text(errors="replace").rstrip()+"\n\n"+line+"\n");reach=[p];prov.setdefault("generated_from_stock",[]).append({"source_backup":backup.relative_to(tree).as_posix(),"target":dst,"change":"added project rc import"})
    if not reach:raise RuntimeError("stock recovery init cannot reach init.recovery.project.rc")
    state["security_init_bridge"]={"target":project.relative_to(tree).as_posix(),"imports":imports,"imported_by":[p.relative_to(tree).as_posix() for p in reach]}
    prop=tree/"system.prop";text=prop.read_text(errors="replace") if prop.is_file() else "";carried={}
    for key,item in sorted(facts.get("security_properties",{}).items()):
        value=str(item.get("value","")) if isinstance(item,dict) else str(item)
        if value and not re.search(r"(?m)^"+re.escape(key)+r"=",text):text=text.rstrip()+"\n"+key+"="+value+"\n";carried[key]=value
    prop.write_text(text.rstrip()+"\n");state["security_properties"]=carried
    prov.setdefault("generated_hardening",[]).append({"target":"BoardConfig.mk","source":state["module_load"]["source"],"change":"enabled exact stock recovery module order"});prov["recovery14_hardening"]={"old_tree_used":False,"state":"_provenance/recovery14-hardening.json"};save(prov_path,prov);save(tree/"_provenance/recovery14-hardening.json",state)
    print(f">> preserved stock recovery module list: {len(names)} entries");print(f">> security init imports: {len(imports)}");print(">> applied TWRP 14.1 boot/decryption hardening");return state

class Audit:
 def __init__(self,dump:Path,facts:dict,tree:Path):self.dump=dump;self.facts=facts;self.tree=tree;self.checks=[]
 def add(self,i,s,m,e="",w=1):self.checks.append({"id":i,"status":s,"message":m,"evidence":e,"weight":w})
 def req(self,c,i,m,e="",w=1):self.add(i,"PASS" if c else "FAIL",m,e,w)
 def warn(self,c,i,a,b,e=""):self.add(i,"PASS" if c else "WARN",a if c else b,e,0)
 def run(self):
  state=load(self.tree/"_provenance/recovery14-hardening.json");ms=state.get("module_load",{});src=self.dump/str(ms.get("source",""));dst=self.tree/str(ms.get("target",""));exact=src.is_file() and dst.is_file() and digest(src)==digest(dst);self.req(exact,"stock-modules-load-byte-exact","Stock modules.load.recovery is byte-exact",str(ms.get("source","")),5)
  expected=modules(src) if src.is_file() else [];board=(self.tree/"BoardConfig.mk").read_text(errors="replace");m=re.search(r'(?m)^TW_LOAD_VENDOR_MODULES\s*:=\s*"([^"]+)"',board);configured=m.group(1).split() if m else [];self.req(bool(configured) and configured==expected,"twrp-module-loader-exact-order","TW_LOAD_VENDOR_MODULES exactly follows stock recovery order",f"expected={len(expected)} configured={len(configured)}",5);self.req("TW_LOAD_VENDOR_BOOT_MODULES := true" in board,"twrp-vendor-boot-module-loader","TWRP searches vendor_boot modules","BoardConfig.mk",4)
  prebuilt={p.name for p in (self.tree/"prebuilt/modules").rglob("*.ko")};dump_names={p.name for root in (self.dump/"vendor_boot/ramdisk/lib/modules",self.dump/"vendor_boot/recovery_ramdisk/lib/modules",self.dump/"vendor_dlkm/lib/modules",self.dump/"odm_dlkm/lib/modules",self.dump/"system_dlkm/lib/modules") if root.is_dir() for p in root.rglob("*.ko")};unknown=[x for x in expected if x not in prebuilt and x not in dump_names];self.req(bool(expected) and not unknown,"stock-module-membership","Every module is in vendor_boot or stock dlkm",", ".join(unknown),5)
  for label,terms in {"display":("x6886","mediatek_drm","panel"),"storage":("ufs","mmc"),"tee-rpmb":("mcdrv","rpmb","tee"),"usb":("musb","usb")}.items():
   matches=[x for x in expected if any(t in x.lower() for t in terms)];self.req(bool(matches),"boot-modules-"+label,"Stock recovery order includes "+label,", ".join(matches[:8]),3)
  touch=[x for x in expected if any(t in x.lower() for t in ("touch","tpd","goodix","focal","novatek","ilitek","fts","chipone"))];self.warn(bool(touch),"boot-modules-touch","Stock recovery order includes touch modules","No touch-named module found; verify built-in touch",", ".join(touch[:8]))
  bridge=state.get("security_init_bridge",{});project=self.tree/str(bridge.get("target",""));pt=project.read_text(errors="replace") if project.is_file() else "";imports=[runtime(x) for x in security_rc(self.facts)];missing=[x for x in imports if "import "+x not in pt];self.req(project.is_file() and not missing,"security-init-import-bridge","Recovery imports every stock security rc",", ".join(missing),5);reachable=[self.tree/x for x in bridge.get("imported_by",[])];self.req(bool(reachable) and all(p.is_file() and "import /init.recovery.project.rc" in p.read_text(errors="replace") for p in reachable),"security-bridge-reachable","Stock recovery init reaches project rc",", ".join(str(p) for p in reachable),5)
  names=set();bins=set()
  for rel in security_rc(self.facts):
   p=self.tree/target(rel)
   if p.is_file():
    for line in p.read_text(errors="replace").splitlines():
     x=re.match(r"\s*service\s+(\S+)\s+(/[^\s\\]+)",line)
     if x:names.add(x.group(1));bins.add(x.group(2))
  missing_bins=[x for x in sorted(bins) if not (self.tree/target(x)).is_file()];self.req(bool(bins) and not missing_bins,"security-service-binaries","Every imported stock security executable is packaged",", ".join(missing_bins),5);service=" ".join(names).lower()
  for label,terms in {"keymint":("keymint","keymaster"),"gatekeeper":("gatekeeper",),"trustonic":("mobicore","trustonic","tee-service")}.items():self.req(any(x in service for x in terms),"security-service-"+label,"Imported init defines stock "+label,service,4)
  refs=self.facts.get("crypto",{}).get("runtime_references",{});resolved=refs.get("resolved",{});missing_refs=[f"{a}->{b}" for a,b in resolved.items() if not (self.tree/target(str(b))).is_file()];self.req(bool(resolved) and not missing_refs,"security-runtime-references","Trustonic helpers and registry blobs are packaged",", ".join(missing_refs),5);self.req(not refs.get("unresolved"),"security-runtime-no-unresolved","No required runtime path is unresolved",", ".join(refs.get("unresolved",[])),5);self.warn(not refs.get("optional_unresolved"),"security-runtime-optional-apex","Optional APEX TAs found","Optional media/DRM APEX TA absent; KeyMint path complete",", ".join(refs.get("optional_unresolved",[])))
  fp=self.tree/"recovery/root/system/etc/recovery.fstab";ft=fp.read_text(errors="replace") if fp.is_file() else "";lines=[x.strip() for x in ft.splitlines() if x.strip() and not x.lstrip().startswith("#")];styles=set();triples=[]
  for line in lines:
   x=line.split()
   if len(x)>=5 and x[1].startswith("/"):styles.add("android");triples.append((x[0],x[1],x[2]))
   elif len(x)>=3 and x[0].startswith("/"):styles.add("recovery");triples.append((x[2],x[0],x[1]))
  self.req(styles=={"android"},"fstab-single-syntax","Recovery fstab uses one stock fs_mgr syntax",", ".join(styles),5);self.req("flags=" not in ft,"fstab-no-mixed-flags","No TWRP flags line is mixed into fs_mgr fstab","recovery.fstab",4);self.req("logical" in ft and "slotselect" in ft,"fstab-logical-ab","Fstab has logical/A-B flags","recovery.fstab",5);self.req("/data" in ft and "fileencryption=" in ft and "keydirectory=" in ft,"fstab-data-encryption","Fstab preserves FBE and metadata-key flags","recovery.fstab",5)
  mounts={x[1].rstrip("/") or "/" for x in triples};unmounted=[d for d in refs.get("required_directories",[]) if not any(d==m or d.startswith(m.rstrip("/")+"/") for m in mounts if m!="/")];self.req(not unmounted,"fstab-security-persistent-storage","Fstab mounts Trustonic persistent storage",", ".join(unmounted),5);dupes=sorted({x for x in triples if triples.count(x)>1});self.req(not dupes,"fstab-no-exact-duplicates","Fstab has no exact duplicate rows",", ".join("|".join(x) for x in dupes),3)
  first=list((self.tree/"recovery/root/first_stage_ramdisk").glob("fstab*"));self.req(bool(first) and any("logical" in p.read_text(errors="replace") for p in first),"fstab-first-stage-stock","Separate stock first-stage fstab is packaged",", ".join(p.name for p in first),5)
  prov=load(self.tree/"_provenance/copied-files.json");bad=[]
  for x in prov.get("copied_from_android16_dump",[]):
   a=self.dump/str(x.get("from",""));b=self.tree/str(x.get("to",""))
   if not a.is_file() or not b.is_file() or digest(a)!=digest(b):bad.append(str(x.get("to","")))
  self.req(not bad,"all-copied-files-byte-exact","All provenance-tracked A16 files are byte-exact",", ".join(bad),5)
  for i,msg in (("runtime-build","Compile twrp-14.1 vendorbootimage"),("runtime-boot","Boot X6886 past TWRP splash"),("runtime-modules","Verify display, touch, UFS, USB and TEE modules"),("runtime-keymint","Confirm Trustonic KeyMint/Gatekeeper registration"),("runtime-decryption","Unlock Android 16 /data and verify contents")):self.add(i,"RUNTIME",msg,"real build/device logs required",0)
  failures=[x for x in self.checks if x["status"]=="FAIL"];passes=[x for x in self.checks if x["status"]=="PASS"];total=sum(x["weight"] for x in self.checks if x["status"] in ("PASS","FAIL"));score=round(100*sum(x["weight"] for x in passes)/total) if total else 0
  return {"schema_version":1,"readiness":"RECOVERY14_STATIC_COMPLETE" if not failures else "NEEDS_DATA","booted":False,"decryption_proven":False,"score":score,"summary":{s.lower():sum(x["status"]==s for x in self.checks) for s in ("PASS","WARN","FAIL","RUNTIME")},"checks":self.checks}

def md(r):
 icons={"PASS":"✅","WARN":"⚠️","FAIL":"❌","RUNTIME":"🧪"};lines=["# X6886 TWRP 14.1 static audit","",f"**Readiness:** `{r['readiness']}`  ",f"**Score:** `{r['score']}/100`  ","**Built/booted/decrypted:** `not yet proven`","","> Static completeness is not runtime proof.","","| State | Check | Result | Evidence |","|---|---|---|---|"]
 for x in r["checks"]:lines.append(f"| {icons[x['status']]} {x['status']} | `{x['id']}` | {str(x['message']).replace('|','\\|')} | {str(x.get('evidence','')).replace('|','\\|').replace(chr(10),'<br>')} |")
 return "\n".join(lines)+"\n"
def main()->int:
 ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True);a=sp.add_parser("apply");u=sp.add_parser("audit")
 for p in (a,u):p.add_argument("--dump",required=True);p.add_argument("--facts",required=True);p.add_argument("--tree",required=True)
 u.add_argument("--json",required=True);u.add_argument("--markdown",required=True);u.add_argument("--strict",action="store_true");x=ap.parse_args();dump=Path(x.dump).resolve();facts=Path(x.facts).resolve();tree=Path(x.tree).resolve()
 if x.cmd=="apply":apply(dump,facts,tree);return 0
 result=Audit(dump,load(facts),tree).run();save(Path(x.json).resolve(),result);Path(x.markdown).resolve().write_text(md(result));print(f">> recovery14 readiness: {result['readiness']}");print(f">> recovery14 score: {result['score']}/100");print(">> recovery14 checks: "+" ".join(f"{k}={v}" for k,v in result["summary"].items()));return 3 if x.strict and result["readiness"]!="RECOVERY14_STATIC_COMPLETE" else 0
if __name__=="__main__":raise SystemExit(main())
