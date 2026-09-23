class Observer < Formula
  desc "Offline CLI that scans a codebase for security, runtime & production-health issues - one HTML report, single binary, no setup."
  homepage "https://github.com/sanks205/getobserver"
  version "0.7.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.7.0/observer_darwin_arm64"
      sha256 "c8f6a8e48d60d771dec07d9975bb004ed3011082200c668cdb61538cf4e148d2"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.7.0/observer_darwin_amd64"
      sha256 "5a78309c1fe1ea623da44c236a6bf8491a09906a969c90cf53f189aba9a3b181"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.7.0/observer_linux_arm64"
      sha256 "94024e4511043f5fb52b592179605f84147f1194fc48d2434e7668bcd3d09386"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.7.0/observer_linux_amd64"
      sha256 "22f4e7fae584ce04397131b8ad16a78629db556b0125859532c2185c1e277733"
    end
  end

  def install
    bin.install Dir["observer_*"].first => "observer"
  end

  test do
    assert_match "observer", shell_output("#{bin}/observer version")
  end
end