#!/usr/bin/env python3
"""Reproduce the pinned, offline DVWA reference scan; never starts DVWA."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request
import zipfile
from collections import Counter

COMMIT = "a1978a2fed195acd093010af6395f86a281537ca"
ARCHIVE_SHA256 = "4bd1cb5dda6bdb889055bf0bcdbaf8fd9562ac358bb61918f3c0cb5199a76258"
ARCHIVE_URL = "https://codeload.github.com/digininja/DVWA/zip/" + COMMIT
BINARY_HASHES = {
 "429635d2fcbf8c15772add018aebc4b48314bb143eb3306ea06810a82b2c936c",
 "0716865ea63bf6a610b01582410a5ac59688d6ce8588a2351612d9f890e0b01a",
 "ae89d751dce7f808a855f5a4a6c6418c3ef15851fcd844d76d6c74dbd55e7bab",
 "6732f5a9549ab5080382d15cfdb8c160b139648e56e46727406db366210bed92",
 "bb7af3859278099e2f92df3fa4f77b968d29ec8b2d0059930c01e584922f8a6c",
 "5eb0adc9f355037f1d5475b3b57f1893359ab09c28ad86fee27d49e2615f1725",
}
def digest(data):
 return hashlib.sha256(data).hexdigest()
def tree_digest(root):
 h=hashlib.sha256()
 for p in sorted(root.rglob("*")):
  if p.is_file():
   h.update(p.relative_to(root).as_posix().encode()+b"\0"+hashlib.sha256(p.read_bytes()).digest())
 return h.hexdigest()
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--observer",type=Path,required=True,help="verified published v0.8.2 binary")
 parser.add_argument("--work-dir",type=Path,required=True,help="local evidence directory outside the Community repository")
 parser.add_argument("--fetch",action="store_true",help="allow downloading the pinned public source archive before the offline scan")
 args=parser.parse_args()
 repo=Path(__file__).resolve().parents[1]
 work=args.work_dir.resolve();binary=args.observer.resolve()
 if work.is_relative_to(repo):
  parser.error("--work-dir must be outside the Community repository")
 tool_hash=digest(binary.read_bytes())
 if tool_hash not in BINARY_HASHES:
  parser.error("binary checksum does not match a published v0.8.2 release asset")
 work.mkdir(parents=True,exist_ok=True)
 archive=work/"DVWA-source.zip"
 if not archive.exists():
  if not args.fetch:parser.error("source archive missing; rerun with --fetch to permit the download")
  archive.write_bytes(urllib.request.urlopen(ARCHIVE_URL,timeout=90).read())
 data=archive.read_bytes()
 if digest(data)!=ARCHIVE_SHA256:
  parser.error("source archive checksum mismatch; do not reuse unverified benchmark inputs")
 source=work/("DVWA-"+COMMIT)
 # Extract only on the first run. Verify every archive member on subsequent runs.
 with zipfile.ZipFile(io.BytesIO(data)) as z:
  members=[x for x in z.infolist() if not x.is_dir()]
  for item in z.infolist():
   target=(work/item.filename).resolve()
   if not target.is_relative_to(work):raise ValueError("unsafe archive path")
  if not source.exists():z.extractall(work)
  for item in members:
   p=work/item.filename
   if not p.is_file() or digest(p.read_bytes())!=digest(z.read(item)):
    raise ValueError("source snapshot changed: "+item.filename)
  expected={item.filename.split("/",1)[1] for item in members}
  if {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}!=expected:
   raise ValueError("unexpected files in source snapshot")
 results=work/"results";results.mkdir(exist_ok=True)
 command=[str(binary),"analyze",str(source),"--assert-offline","--json",str(results/"raw.json"),"--out",str(results/"raw.html"),"--attest",str(results/"attestation.json")]
 result=subprocess.run(command,capture_output=True,text=True,encoding="utf-8",errors="replace")
 (results/"scan.log").write_text(result.stdout+result.stderr,encoding="utf-8")
 if result.returncode:raise RuntimeError("scan failed; inspect results/scan.log")
 if "Offline mode: no network I/O." not in result.stdout:raise RuntimeError("offline enforcement banner missing")
 raw=json.loads((results/"raw.json").read_text(encoding="utf-8-sig"))
 attestation=json.loads((results/"attestation.json").read_text(encoding="utf-8-sig"))
 assert attestation["offline_asserted"] is True and attestation["version"]=="0.8.2"
 assert [(e["name"],e["status"]) for e in attestation["engines"]]==[("builtin","completed")]
 # Publish classification/location data, not code snippets or absolute paths.
 fields=("rule","severity","category","title","file","line","cwe","owasp")
 findings=[{key:f.get(key,"") for key in fields} for f in raw["findings"]]
 for f in findings:
  f["file"]=f["file"].replace("\\","/")
  if Path(f["file"]).is_absolute() or re.match(r"^[A-Za-z]:",f["file"]):raise ValueError("absolute finding path")
 findings.sort(key=lambda f:(f["file"],f["line"],f["rule"]))
 normalized=json.dumps(findings,indent=2,ensure_ascii=False)+"\n"
 (results/"findings.json").write_text(normalized,encoding="utf-8",newline="\n")
 counts=Counter(f["rule"] for f in findings)
 source_count=re.search(r"Static analysis: (\d+) issue\(s\) in (\d+) source file",result.stdout)
 summary={
  "project":"DVWA","source_commit":COMMIT,"archive_url":ARCHIVE_URL,
  "archive_sha256":ARCHIVE_SHA256,"source_tree_sha256":tree_digest(source),
  "observer_version":"0.8.2","observer_binary_sha256":tool_hash,
  "scan_mode":"--assert-offline; built-in engine only; default exclusions",
  "generated_at_utc":attestation["generated_at"],
  "git_provenance":"archive scan; source pinned and hash-checked separately; no Git working tree",
  "finding_count":len(findings),"source_files_analyzed":int(source_count[2]) if source_count else None,
  "by_rule":dict(sorted(counts.items())),"by_severity":dict(sorted(Counter(f["severity"] for f in findings).items())),
  "security_score":raw["security_score"],"code_health_score":raw["code_health_score"],
  "scoring_model":raw["scoring_model"],
  "normalized_findings_sha256":digest(normalized.encode()),
  "limits":"Finding counts are not verified vulnerabilities. No recall or overall false-positive rate is measured."
 }
 (results/"summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8",newline="\n")
 print(json.dumps(summary,indent=2))
if __name__=="__main__":
 main()
