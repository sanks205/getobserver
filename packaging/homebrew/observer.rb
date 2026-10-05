class Observer < Formula
  desc "Offline CLI that scans a codebase for security, runtime & production-health issues - one HTML report, single binary, no setup."
  homepage "https://github.com/sanks205/getobserver"
  version "0.8.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.0/observer_darwin_arm64"
      sha256 "862f7d88a563e00c1d1556e47f5d424348d2fd45f5ae889e1cc1446c564d247a"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.0/observer_darwin_amd64"
      sha256 "43ae3dc2eedf093e830adc591faa9a230148a0061d117d54af4bb35a6797644c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.0/observer_linux_arm64"
      sha256 "01e12d8abe45bbaf8eb9eeba5711d1882b2be2907c2f91ecd77669b4b624966c"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.0/observer_linux_amd64"
      sha256 "bf96d972820db65701d004c03c5be7791faa4eb7ab098bede95ed5bbc68ee0a8"
    end
  end

  def install
    bin.install Dir["observer_*"].first => "observer"
  end

  test do
    assert_match "observer", shell_output("#{bin}/observer version")
  end
end