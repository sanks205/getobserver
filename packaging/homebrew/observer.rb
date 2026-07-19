class Observer < Formula
  desc "Offline CLI that scans a codebase for security, runtime & production-health issues - one HTML report, single binary, no setup."
  homepage "https://github.com/sanks205/getobserver"
  version "0.4.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.4.0/observer_darwin_arm64"
      sha256 "9f3df4f0a85e330321ce4b5be5bff3172cfcdfb359245e50119bea937ede2321"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.4.0/observer_darwin_amd64"
      sha256 "70c22116aab93db7fcc1b2fa52acafc2caa8e8e147be1f8e039b87629f468e0f"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.4.0/observer_linux_arm64"
      sha256 "ac67017f7dbf3bc210c8077a71a4807e254ebf9e68a0333877bd8e5dd726c81b"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.4.0/observer_linux_amd64"
      sha256 "73df6ae434134f7edd4dc132883ca7c599304078cee29d80a4c968e1be2dd076"
    end
  end

  def install
    bin.install Dir["observer_*"].first => "observer"
  end

  test do
    assert_match "observer", shell_output("#{bin}/observer version")
  end
end