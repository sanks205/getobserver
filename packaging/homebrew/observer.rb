class Observer < Formula
  desc "Offline CLI that scans a codebase for security, runtime & production-health issues - one HTML report, single binary, no setup."
  homepage "https://github.com/sanks205/getobserver"
  version "0.3.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.3.0/observer_darwin_arm64"
      sha256 "2b08bae50a201329e8cb9f03895563ec54ba2f0539858e47a1b241f4db98bc99"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.3.0/observer_darwin_amd64"
      sha256 "d7e48e53a0bb70cffb6d4b7289da1fb406ad71f2a6b3ac4167c7c0eb05dc0242"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.3.0/observer_linux_arm64"
      sha256 "bc9c0e04869afbeedd69b4b1784e29364c91f9a22e6111926fc47f7ec253b844"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.3.0/observer_linux_amd64"
      sha256 "a741d45b3565dd638c20e75b49756704ce848f4c8abd7f32c1d55874b48b215a"
    end
  end

  def install
    bin.install Dir["observer_*"].first => "observer"
  end

  test do
    assert_match "observer", shell_output("#{bin}/observer version")
  end
end