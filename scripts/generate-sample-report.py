#!/usr/bin/env python3
"""Render the public first-party demo and remove local workstation paths."""
import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import quote,unquote

SOURCE_REF="4a9c0eed5610fbdc939087010982bf7061498204"
FIXTURE_TREE_SHA256="43a79a668995af00ba9ba1f72ee22e2912021e8f47b018bdcbb8ce80f1f1dce4"
BASE="https://github.com/sanks205/getobserver/blob/"+SOURCE_REF+"/examples/php-demo/"
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--observer",type=Path,required=True,help="Community CLI built from this checkout")
 args=parser.parse_args()
 root=Path(__file__).resolve().parents[1];source=(root/"examples/php-demo").resolve()
 binary=args.observer.resolve()
 version=subprocess.check_output([str(binary),"version"],text=True).strip()
 if version!="observer 0.8.2":raise ValueError("expected a v0.8.2 Community source build")
 with tempfile.TemporaryDirectory(prefix="observer-public-sample-") as tmp:
  report=Path(tmp)/"report.html";data=Path(tmp)/"report.json"
  command=[str(binary),"analyze",str(source),"--assert-offline","--guidance","--out",str(report),"--json",str(data)]
  result=subprocess.run(command,capture_output=True,text=True,encoding="utf-8",errors="replace")
  if result.returncode:raise RuntimeError(result.stderr)
  assert "Offline mode: no network I/O." in result.stdout
  text=report.read_text(encoding="utf-8-sig")
  normalized=str(source).replace("\\","/")
  def source_link(match):
   path=unquote(html.unescape(match[1])).replace("\\","/")
   path,_,line=path.rpartition(":")
   if not path.lower().startswith(normalized.lower()+"/") or not line.isdigit():
    raise ValueError("unexpected editor link")
   relative=path[len(normalized)+1:]
   return 'href="'+html.escape(BASE+quote(relative,safe="/")+"#L"+line,quote=True)+'"'
  text=re.sub(r'href="vscode://file/([^"]+)"',source_link,text)
  text=text.replace('title="Open in VS Code"','title="View public demo source on GitHub"')
  text=text.replace("opens in VS Code","opens the public demo source on GitHub")
  text=text.replace("Location links use the <code>vscode://</code> scheme and require VS Code.","Location links open the public demo source on GitHub.")
  for private in [str(source),normalized,str(root),str(root).replace("\\","/")]:
   text=text.replace(html.escape(private),"examples/php-demo")
   text=text.replace(private,"examples/php-demo")
  banner='<aside style="padding:12px 18px;border:1px solid #2bb6c9;margin:12px;background:#172331;color:#f0f6fc">Public demo of intentionally insecure first-party fixtures. This is not a client audit or benchmark. Local paths were removed and source links point to the public fixture snapshot. <a style="color:#6ee7f5" href="https://github.com/sanks205/getobserver/blob/main/docs/SAMPLE-REPORT.md">How this sample was made</a></aside>'
  text=text.replace("<body>","<body>\n"+banner,1)
  assert not re.search(r"vscode:|[A-Za-z]:[\\/]+(?:projects|Users)|/Users/|/home/",text)
  assert "Standards-aligned" not in text
  # The fake demonstration token must not appear unredacted in the public report.
  for p in source.rglob("*"):
   if p.is_file():
    for token in re.findall(r"sk_live_[A-Za-z0-9]+",p.read_text(encoding="utf-8",errors="replace")):
     assert token not in text,"unredacted fixture token"
  fixture_manifest=[{"path":p.relative_to(source).as_posix(),"sha256_lf":hashlib.sha256(p.read_bytes().replace(b"\r\n",b"\n")).hexdigest()} for p in sorted(source.rglob("*")) if p.is_file()]
  fixture_digest=hashlib.sha256(json.dumps(fixture_manifest,sort_keys=True,separators=(",",":")).encode()).hexdigest()
  if fixture_digest!=FIXTURE_TREE_SHA256:
   raise ValueError("demo fixtures changed; update the pinned public source reference and canonical fixture digest before publishing")
  text="\n".join(line.rstrip() for line in text.splitlines())+"\n"
  output=root/"docs/sample-report.html"
  output.write_text(text,encoding="utf-8",newline="\n")
  raw=json.loads(data.read_text(encoding="utf-8-sig"))
  metadata={
   "kind":"synthetic first-party demonstration; not benchmark",
   "observer_version":"0.8.2","renderer":"post-release Community source build; updated rating wording and purchase URL",
   "renderer_binary_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
   "fixture_source_commit":SOURCE_REF,"fixture_tree_sha256_lf":fixture_digest,"command":"observer analyze ./examples/php-demo --assert-offline --guidance --out report.html --json report.json",
   "findings":raw["summary"]["total"],"by_severity":{k:raw["summary"][k] for k in ("critical","high","medium","low")},
   "publication_changes":["public-demo banner","absolute path removal","editor links replaced by pinned GitHub source links"],
   "fixture_files":[{"path":p.relative_to(source).as_posix(),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(source.rglob("*")) if p.is_file()]
  }
  (root/"docs/sample-report-provenance.json").write_text(json.dumps(metadata,indent=2)+"\n",encoding="utf-8",newline="\n")
  print("Wrote sanitized sample report and provenance:",raw["summary"]["total"],"findings")
if __name__=="__main__":
 main()
