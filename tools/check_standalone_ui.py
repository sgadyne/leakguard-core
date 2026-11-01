#!/usr/bin/env python3
"""Owned synthetic real-backend browser acceptance; no native Mac certification."""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys,time,uuid,shutil,os
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from check_desktop_runtime import DesktopChild
from check_product_journey import BuddyClient
def main():
 p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);p.add_argument("--python",type=Path,required=True);p.add_argument("--gitleaks",type=Path,required=True);p.add_argument("--modules",type=Path,required=True);p.add_argument("--browser",type=Path,required=True);p.add_argument("--libraries",required=True);p.add_argument("--receipt",type=Path,required=True);args=p.parse_args()
 work=args.work.absolute()
 if work.exists():raise SystemExit("new-owned-work-required")
 work.mkdir(parents=True,mode=0o700)
 state=work/"state";state.mkdir(mode=0o700)
 from leakguard_host.protection import defaults
 protection=defaults();protection["automatic_this_mac"]=False
 (state/"protection-settings.json").write_text(json.dumps(protection))
 config=work/"config.json";config.write_text(json.dumps({"worker_policy":"supervised-alpha","gitleaks_executable":str(args.gitleaks.absolute()),"scan_workers":2,"max_file_bytes":20971520}))
 source=work/"synthetic-source";source.mkdir()
 (source/"operator.env").write_text('corpPassword="profile-synthetic-positive-139"\nteamToken="profile-synthetic-session-271"\n'+"".join('corpPassword="profile-synthetic-positive-%03d"\n'%i for i in range(104)))
 (source/"negative.env").write_text('myCorpPasswordSuffix="profile-synthetic-negative-911"\ncorpPassword=$ENV_REFERENCE\n')
 obs="Synthetic scan phrase "+uuid.uuid4().hex;vault="Synthetic vault phrase "+uuid.uuid4().hex
 result={"source_commit":subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),"scope":"real authenticated loopback backend + Chromium; synthetic owned profile; supervised-alpha Linux policy; no Mac native certification","automatic_local_discovery":False,"source_dirty":bool(subprocess.check_output(["git","status","--porcelain"],cwd=ROOT,text=True)),"phases":[],"passed":False}
 child=None
 try:
  for phase in ["initial","reopen"]:
   child=DesktopChild(args.python.absolute(),state,config,work)
   ready=child.next()
   if ready.get("type")!="ready":raise RuntimeError("backend-not-ready")
   client=BuddyClient(ready["origin"],timeout=20);client.exchange(child.command("bootstrap")["token"])
   if phase=="initial":
    assert client.request("POST","/api/observations/create",{"passphrase":obs})[0]==201
    assert client.request("POST","/api/observations/lock",{})[0]==200
   configuration={"phase":phase,"origin":ready["origin"],"token":child.command("bootstrap")["token"],"observationPhrase":obs,"vaultPhrase":vault,"source":str(source),"screenshotDir":str(work/"screenshots"),"modules":str(args.modules.absolute()),"executable":str(args.browser.absolute()),"libraries":args.libraries}
   run=subprocess.run(["node",str(ROOT/"tools/check_standalone_ui.mjs")],input=json.dumps(configuration),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=220)
   try:receipt=json.loads(run.stdout)
   except ValueError:receipt={"passed":False,"failure":"browser-output-invalid","stderr_tail":run.stderr[-4000:]}
   result["phases"].append(receipt)
   assert child.stop(),"owned-backend-shutdown-failed"
   child=None
   if run.returncode or not receipt.get("passed"):break
  result["passed"]=len(result["phases"])==2 and all(r["passed"] for r in result["phases"])
 finally:
  result["owned_backend_stopped"]=child.stop() if child else True
  result["built_static_hashes"]={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/"apps/buddy-ui/dist").glob("*") if p.is_file()}
  args.receipt.parent.mkdir(parents=True,exist_ok=True);args.receipt.write_text(json.dumps(result,indent=2))
  print(json.dumps(result,indent=2))
 return 0 if result["passed"] else 1
if __name__=="__main__":raise SystemExit(main())
