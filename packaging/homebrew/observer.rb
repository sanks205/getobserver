class Observer < Formula
  desc "Offline CLI that scans a codebase for security, runtime & production-health issues - one HTML report, single binary, no setup."
  homepage "https://github.com/sanks205/getobserver"
  version "0.8.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.0/observer_darwin_arm64"
      sha256 "928d0ebe7f7aac50d60262bc60f7309d03d7c20fb1562b2296dfeccdc3474821"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.0/observer_darwin_amd64"
      sha256 "97b1f832d37b2b8cc8465d8f19c19a0ad7c04fba59a84232f508199e4001049b"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.0/observer_linux_arm64"
      sha256 "83596afd4b1b6b7b5209656b31d123fb1d381db6d499621b66c09bc2c568f576"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.0/observer_linux_amd64"
      sha256 "d8445757e4133a1e68790b2cc697647b39ef79986d9546adba34798021665ed4"
    end
  end

  def install
    bin.install Dir["observer_*"].first => "observer"
  end

  test do
    assert_match "observer", shell_output("#{bin}/observer version")
  end
end