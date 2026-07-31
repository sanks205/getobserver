class Observer < Formula
  desc "Offline CLI that scans a codebase for security, runtime & production-health issues - one HTML report, single binary, no setup."
  homepage "https://github.com/sanks205/getobserver"
  version "0.5.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.5.1/observer_darwin_arm64"
      sha256 "0271895a8da02153d0ed3e3066409f72899f26de93e7b682d1791e42846cd497"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.5.1/observer_darwin_amd64"
      sha256 "37c88433032a7b0cc44dd55163684f83d436ee568c725b2d622e8661e856c2ca"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.5.1/observer_linux_arm64"
      sha256 "2c417276b79b089b5fa8aaa977a44dd5462ddd61bbb44f917eee5d2aa575016b"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.5.1/observer_linux_amd64"
      sha256 "fb5a33b51e48905ad538015fe25738ab58aa05f57707c271d165ef2c613be5f9"
    end
  end

  def install
    bin.install Dir["observer_*"].first => "observer"
  end

  test do
    assert_match "observer", shell_output("#{bin}/observer version")
  end
end