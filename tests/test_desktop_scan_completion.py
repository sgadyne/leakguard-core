"""The native one-file exception cannot turn unrelated or incomplete work clean."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.parse import parse_qs,urlsplit

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("desktop_journey_completion",ROOT/"tools/check_product_journey.py")
journey=importlib.util.module_from_spec(spec);spec.loader.exec_module(journey)


class ScanCompletionTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory();self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name).resolve();self.file=self.root/"synthetic.txt"
        self.file.write_text('password="synthetic-fixture-only"')
        self.digest=journey._synthetic_file_digest(self.file)
        self.job={"id":"job","source_id":"source","state":"completed","coverage":"incomplete",
                  "inventory_counts":{"enumerated":1,"inspected":1},"inventory_complete":True,
                  "inventory_generation":7,"files_scanned":1,"pending_files":0,
                  "pending_directories":0,"omission_count":0,"last_error":None}
        self.source={"id":"source","root":str(self.root),"kind":"local",
                     "managed_inventory":True,"enabled":True}
        self.finding={"id":"finding","rule":"literal-password","source_id":"source",
                      "source":{"path":str(self.file)},"state":"active",
                      "last_verified":"2026-11-02T01:00:00+00:00"}
    def complete(self,job=None,source=None):
        return journey._managed_fixture_completion(
            self.job if job is None else job,self.source if source is None else source,
            source_id="source",job_id="job",fixture=self.file,digest=self.digest)
    def test_rightful_scoped_completion_retains_incomplete_coverage_label(self):
        result=self.complete()
        self.assertTrue(result["verified"])
        self.assertEqual(result["claim"],"explicit-synthetic-file-only")
        self.assertEqual(result["coverage_label"],"incomplete")
    def test_pending_failure_omission_and_unexpected_counts_fail(self):
        states=("pending","changed","enumerating","inspection-error","inaccessible","unsupported",
                "inspected-with-omissions","excluded","alias","protected","remote-only","not-seen")
        for state in states:
            with self.subTest(state=state):
                job=deepcopy(self.job);job["inventory_counts"][state]=1
                with self.assertRaises(journey.JourneyFailure):self.complete(job)
        for counts in (None,{},{"unrelated":1},{"inspected":1},{"enumerated":1},
                       {"enumerated":1,"inspected":2},{"enumerated":1,"inspected":True},
                       {"enumerated":1.0,"inspected":1},{"enumerated":1,"inspected":"1"},
                       {"enumerated":1,"inspected":1,"pending":None},
                       {"enumerated":1,"inspected":1,"unknown-state":0},
                       {"enumerated":-1,"inspected":1}):
            with self.subTest(counts=counts):
                job=deepcopy(self.job);job["inventory_counts"]=counts
                with self.assertRaises(journey.JourneyFailure):self.complete(job)
    def test_job_identity_state_and_unknown_fields_fail(self):
        invalid={"id":("other",None),"source_id":("other",None),"state":("running","failed","backoff","paused","cancelled"),
                 "coverage":("unknown",None),"inventory_complete":(False,None),
                 "inventory_generation":(None,False,0,-1,"7"),"files_scanned":(None,False,0,"1"),
                 "pending_files":(None,False,1),"pending_directories":(None,False,1),
                 "omission_count":(None,False,1),"last_error":("scan-failed",)}
        for key,values in invalid.items():
            for value in values:
                with self.subTest(key=key,value=value):
                    job=deepcopy(self.job);job[key]=value
                    with self.assertRaises(journey.JourneyFailure):self.complete(job)
        for key in ("inventory_counts","pending_files","pending_directories","omission_count","last_error"):
            with self.subTest(missing=key):
                job=deepcopy(self.job);del job[key]
                with self.assertRaises(journey.JourneyFailure):self.complete(job)
    def test_wrong_or_unmanaged_source_and_changed_fixture_fail(self):
        for key,value in (("id","other"),("root",str(self.root/"other")),("kind","ssh"),
                          ("managed_inventory",False),("enabled",False)):
            source=deepcopy(self.source);source[key]=value
            with self.subTest(key=key):
                with self.assertRaises(journey.JourneyFailure):self.complete(source=source)
        self.file.write_text("changed synthetic content")
        with self.assertRaises(journey.JourneyFailure):self.complete()
        self.file.write_text('password="synthetic-fixture-only"')
        (self.root/"old-pending.txt").write_text("old work")
        with self.assertRaises(journey.JourneyFailure):self.complete()
    def client(self,finding=None,job=None,cycle=False):
        test=self
        class Client:
            def __init__(self):self.queries=[]
            def request(self,method,path,body=None):
                if method=="POST" and path=="/api/scans":return 202,{"id":"job"},b""
                if path=="/api/jobs":return 200,[test.job if job is None else job],b""
                if path=="/api/sources":return 200,[test.source],b""
                if method=="POST":return 200,{"state":"reviewed"},b""
                query=parse_qs(urlsplit(path).query);self.queries.append(query)
                if "cursor" not in query:return 200,{"findings":[],"next_cursor":"opaque/+cursor=="},b""
                if cycle:return 200,{"findings":[],"next_cursor":"opaque/+cursor=="},b""
                row=deepcopy(test.finding if finding is None else finding)
                if "annotation" in query:row["annotation"]={"state":"reviewed"}
                return 200,{"findings":[row],"next_cursor":None},b""
        return Client()
    def run_scan(self,client,managed=True):
        return journey._run_scan(client,"source","literal-password",1,{}, {},
                                 **({"managed_fixture":self.file} if managed else {}))
    def test_exact_sparse_cursors_and_original_annotation_check(self):
        client=self.client()
        self.assertEqual(self.run_scan(client)[0],"finding")
        self.assertEqual([q.get("cursor") for q in client.queries],
                         [None,["opaque/+cursor=="],None,["opaque/+cursor=="]])
    def test_unrelated_or_incomplete_finding_cannot_satisfy_fixture(self):
        for key,value in (("source_id","other"),("source",{"path":str(self.root/"unrelated.txt")}),
                          ("state","unknown"),("last_verified",None),("rule","unrelated")):
            finding=deepcopy(self.finding);finding[key]=value
            with self.subTest(key=key):
                with self.assertRaises(journey.JourneyFailure):self.run_scan(self.client(finding))
        with self.assertRaisesRegex(journey.JourneyFailure,"findings-cursor-invalid"):
            self.run_scan(self.client(cycle=True))
    def test_native_scope_settings_preserve_preferences_and_verify_disable(self):
        original={"automatic_this_mac":True,"schedule":{"interval_seconds":3600},"new_content":"inspect"}
        class SettingsClient:
            def __init__(self,keep_enabled=False):
                self.protection=deepcopy(original);self.calls=[];self.keep_enabled=keep_enabled
            def request(self,method,path,body=None):
                self.calls.append((method,path,body))
                if method=="POST":
                    self.protection=body["protection"]
                    if self.keep_enabled:self.protection["automatic_this_mac"]=True
                return 200,{"protection":deepcopy(self.protection)},b""
        client=SettingsClient();journey._disable_automatic_discovery(client)
        self.assertEqual(client.protection,{**original,"automatic_this_mac":False})
        self.assertEqual([m for m,_,_ in client.calls],["GET","POST","GET"])
        with self.assertRaisesRegex(journey.JourneyFailure,"synthetic-scope-not-isolated"):
            journey._disable_automatic_discovery(SettingsClient(keep_enabled=True))

    def test_ordinary_cli_path_keeps_strict_coverage_requirement(self):
        with self.assertRaisesRegex(journey.JourneyFailure,"scan-incomplete"):
            self.run_scan(self.client(),managed=False)
        job=deepcopy(self.job);job["coverage"]="complete"
        self.assertEqual(self.run_scan(self.client(job=job),managed=False)[0],"finding")


if __name__=="__main__":unittest.main()
