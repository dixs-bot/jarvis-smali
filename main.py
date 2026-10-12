#!/usr/bin/env python3
"""SMALI JARVIS v0.7.0: read-only Android/framework audit."""
import argparse, hashlib, json, os, platform, shutil, subprocess, sys, time, zipfile
from pathlib import Path
VERSION = "0.7.0"
DEFAULT_PATHS = [
 "/system/framework/services.jar",
 "/system/framework/oat/arm64/services.art",
 "/system/framework/oat/arm64/services.odex",
 "/system/framework/oat/arm64/services.vdex",
]
TOOLS = ["getprop","su","java","python","python3","baksmali","smali","jadx","dexdump","zip","unzip","adb"]
def run(args):
 try:
  p=subprocess.run(args,capture_output=True,text=True,timeout=5)
  return {"rc":p.returncode,"out":p.stdout.strip(),"err":p.stderr.strip()}
 except Exception as e: return {"rc":None,"out":"","err":str(e)}
def prop(key):
 r=run(["getprop",key]); return r["out"] or None
def sig(head):
 if head.startswith(b"dex\\n"): return "DEX_MAGIC"
 if head.startswith(b"PK\\x03\\x04"): return "ZIP/JAR_MAGIC"
 if head.startswith(b"vdex"): return "VDEX_MAGIC_PREFIX; format compatibility not proven"
 if head.startswith(b"\\x7fELF"): return "ELF_MAGIC"
 if head.startswith(b"art\\n"): return "ART_MAGIC_PREFIX; format compatibility not proven"
 if not head: return "EMPTY_FILE"
 return "UNKNOWN_SIGNATURE"
def inspect(path):
 p=Path(os.path.expanduser(path))
 d={"path":str(p),"exists":p.exists(),"status":"NOT_FOUND"}
 if not p.exists(): return d
 try:
  st=p.stat(); head=p.read_bytes()[:32] if p.is_file() else b""
  d.update(status="READ_ONLY_INSPECTED",is_file=p.is_file(),size_bytes=st.st_size,
    modified_epoch=int(st.st_mtime),first_32_bytes_hex=head.hex(" "),signature_hint=sig(head))
  if p.is_file():
   h=hashlib.sha256()
   with p.open("rb") as f:
    for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
   d["sha256"]=h.hexdigest()
  if p.suffix.lower()==".jar" and p.is_file():
   try:
    with zipfile.ZipFile(p) as z: names=z.namelist()
    dex=[n for n in names if n=="classes.dex" or (n.startswith("classes") and n.endswith(".dex"))]
    d.update(jar_status="DEX_PRESENT" if dex else "NO_DEX_ENTRY",jar_entries_count=len(names),
      jar_has_dex=bool(dex),dex_entries=dex,jar_entries_sample=names[:20])
   except Exception as e: d.update(jar_status="NOT_A_READABLE_ZIP",jar_error=str(e))
 except Exception as e: d.update(status="READ_ERROR",error=str(e))
 return d
def report(paths):
 keys=["ro.build.version.release","ro.build.version.sdk","ro.product.model","ro.product.manufacturer","ro.product.cpu.abi","ro.build.fingerprint"]
 android={k:prop(k) for k in keys}
 du=shutil.disk_usage(str(Path.home()))
 return {"tool":"SMALI JARVIS","version":VERSION,"timestamp_local":time.strftime("%Y-%m-%dT%H:%M:%S%z"),
 "host":{"system":platform.system(),"release":platform.release(),"machine":platform.machine(),"python":sys.version.split()[0]},
 "android":android,"android_property_interface":"AVAILABLE" if any(android.values()) else "NOT_DETECTED",
 "tools":{x:shutil.which(x) for x in TOOLS},"storage_home":{"total_bytes":du.total,"free_bytes":du.free},
 "framework_artifacts":[inspect(x) for x in paths],
 "safety":"Read-only only. No framework writes, patching, module installation, or reboot.",
 "notes":["Signatures are hints, not proof of validity or compatibility.",
 "A JAR without classes.dex may be manifest-only; no DEX is fabricated.",
 "No patch or Magisk ZIP is produced by this audit release."]}
def show(r):
 print("\nSMALI JARVIS v"+VERSION+" — READ-ONLY AUDIT")
 print("="*52)
 print("Host: {system} {machine} | Python {python}".format(**r["host"]))
 print("Android properties:",r["android_property_interface"])
 for k,v in r["android"].items(): print(" ",k,":",v or "NOT_AVAILABLE")
 print("\nTOOLS")
 for k,v in r["tools"].items(): print(" ",f"{k:10}",v or "NOT_FOUND")
 print("\nFRAMEWORK ARTIFACTS")
 for x in r["framework_artifacts"]:
  print(" ",f"[{x['status']}]",x["path"])
  if "size_bytes" in x:
   print("    size:",x["size_bytes"],"| signature:",x.get("signature_hint"))
   print("    sha256:",x.get("sha256"))
   if "jar_status" in x: print("    JAR:",x["jar_status"],"| has_dex:",x.get("jar_has_dex"))
 print("\nSafety: no system changes made. This is not a patcher.")
def main():
 ap=argparse.ArgumentParser(description="SMALI JARVIS read-only audit")
 ap.add_argument("--json",dest="json_path",help="save JSON report")
 ap.add_argument("--path",action="append",default=[],help="extra file to inspect (repeatable)")
 ap.add_argument("--no-framework",action="store_true",help="only inspect environment")
 ap.add_argument("--version",action="version",version="SMALI JARVIS "+VERSION)
 a=ap.parse_args()
 paths=[] if a.no_framework else list(DEFAULT_PATHS)
 paths.extend(a.path)
 r=report(paths); show(r)
 if a.json_path:
  out=Path(os.path.expanduser(a.json_path)); out.parent.mkdir(parents=True,exist_ok=True)
  out.write_text(json.dumps(r,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
  print("\nJSON report saved:",out)
if __name__=="__main__": main()
