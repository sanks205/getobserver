class Observer < Formula
  desc "Offline CLI that scans a codebase for security, runtime & production-health issues - one HTML report, single binary, no setup."
  homepage "https://github.com/sanks205/getobserver"
  version "0.5.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.5.0/observer_darwin_arm64"
      sha256 "9bccc2e5107d618d0bc1909c6eeaed8496194d0a6afed862717b206a769e4896"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.5.0/observer_darwin_amd64"
      sha256 "31e20223bae4b234d8be7e0972c630a8cf5b3510b88b00aae3cabe457a1748b1"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.5.0/observer_linux_arm64"
      sha256 "d98aa65945c42ed17880ba249f7ef1812c6f2ac25c5edd80640dc4f9e9b73605"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.5.0/observer_linux_amd64"
      sha256 "f0b28337ab4fd542ebe86436368f45c11b2987a5fa34e2f80964337fe59d080c"
    end
  end

  def install
    bin.install Dir["observer_*"].first => "observer"
  end

  test do
    assert_match "observer", shell_output("#{bin}/observer version")
  end
end