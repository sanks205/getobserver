class Observer < Formula
  desc "Offline CLI that scans a codebase for security, runtime & production-health issues - one HTML report, single binary, no setup."
  homepage "https://github.com/sanks205/getobserver"
  version "0.8.2"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.2/observer_darwin_arm64"
      sha256 "0716865ea63bf6a610b01582410a5ac59688d6ce8588a2351612d9f890e0b01a"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.2/observer_darwin_amd64"
      sha256 "429635d2fcbf8c15772add018aebc4b48314bb143eb3306ea06810a82b2c936c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.2/observer_linux_arm64"
      sha256 "6732f5a9549ab5080382d15cfdb8c160b139648e56e46727406db366210bed92"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.2/observer_linux_amd64"
      sha256 "ae89d751dce7f808a855f5a4a6c6418c3ef15851fcd844d76d6c74dbd55e7bab"
    end
  end

  def install
    bin.install Dir["observer_*"].first => "observer"
  end

  test do
    assert_match "observer", shell_output("#{bin}/observer version")
  end
end
