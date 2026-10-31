#!/usr/bin/env python3
"""Prepare separate Homebrew/Scoop repositories locally; does not publish them."""
import argparse
import json
from pathlib import Path
import shutil

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--out",type=Path,required=True,help="destination outside the Community checkout")
 args=p.parse_args()
 root=Path(__file__).resolve().parents[1];out=args.out.resolve()
 if out.is_relative_to(root):p.error("destination must be outside the Community checkout")
 scoop=json.loads((root/"packaging/scoop/observer.json").read_text(encoding="utf-8-sig"))
 version=(root/"VERSION").read_text(encoding="utf-8-sig").strip()
 if scoop["version"]!=version:raise ValueError("package and source version mismatch")
 brew=(root/"packaging/homebrew/observer.rb").read_text(encoding="utf-8-sig")
 if 'version "'+version+'"' not in brew:raise ValueError("Homebrew version mismatch")
 for name,rel,source in [
  ("homebrew-observer","Formula/observer.rb","packaging/homebrew/observer.rb"),
  ("scoop-observer","bucket/observer.json","packaging/scoop/observer.json")
 ]:
  dest=out/name;target=dest/rel;target.parent.mkdir(parents=True,exist_ok=True)
  shutil.copy2(root/source,target);shutil.copy2(root/"LICENSE",dest/"LICENSE")
  if name=="homebrew-observer":
   commands="brew tap sanks205/observer\nbrew install sanks205/observer/observer\nobserver version\nbrew test sanks205/observer/observer"
  else:
   commands="scoop bucket add observer https://github.com/sanks205/scoop-observer\nscoop install observer/observer\nobserver version"
  text="# Observer "+("Homebrew Tap" if name=="homebrew-observer" else "Scoop Bucket")+"\n\nRelease: "+version+". Definitions use release-specific SHA-256 checksums.\n\n## Installation\n\nAfter this repository is published and verified:\n\n~~~sh\n"+commands+"\n~~~\n\n## Maintainers\n\nPublish this directory as the corresponding separate GitHub repository. Test installation on supported operating systems before advertising availability. Update version, download URLs, and hashes together from the exact final release artifacts. Never reuse an old checksum after rebuilding or signing a binary.\n\nCommunity source: https://github.com/sanks205/getobserver\n"
  (dest/"README.md").write_text(text,encoding="utf-8",newline="\n")
  print("Prepared (not published):",dest)
if __name__=="__main__":
 main()
