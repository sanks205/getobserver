class Observer < Formula
  desc "Offline CLI that scans a codebase for security, runtime & production-health issues - one HTML report, single binary, no setup."
  homepage "https://github.com/sanks205/getobserver"
  version "0.6.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.6.0/observer_darwin_arm64"
      sha256 "bd4ade0a3b28ee30f3de7ff5688c614c9a83bb0f882b5a412d7900e4fb0100e5"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.6.0/observer_darwin_amd64"
      sha256 "7b7b54c05245d93724bc810e922c1c2eab65e4e5b9367968ac03d22e34045452"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.6.0/observer_linux_arm64"
      sha256 "27ce1ad106fcd61681d0fa24cf33aebbbce2c242379c25414c488cc2f0253e82"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.6.0/observer_linux_amd64"
      sha256 "4435eaf4925f6c48c5c9136319b0842724ccc776791b465ff8bd0291ccb98177"
    end
  end

  def install
    bin.install Dir["observer_*"].first => "observer"
  end

  test do
    assert_match "observer", shell_output("#{bin}/observer version")
  end
end