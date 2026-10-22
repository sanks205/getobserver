class Observer < Formula
  desc "Offline CLI that scans a codebase for security, runtime & production-health issues - one HTML report, single binary, no setup."
  homepage "https://github.com/sanks205/getobserver"
  version "0.8.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.1/observer_darwin_arm64"
      sha256 "41991bbba615ba9318c143f0c0047e76515fc62deedf4d0ee76c4396c834cba7"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.1/observer_darwin_amd64"
      sha256 "8a27906e797c322b639c3b6490ea69f5ef29897def4e2ae3ec50be27ec7be6f4"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.1/observer_linux_arm64"
      sha256 "6cdf7db047bb138e28cc1e0a96acba56c4e153f45ab415530fa819df71179d18"
    end
    on_intel do
      url "https://github.com/sanks205/getobserver/releases/download/v0.8.1/observer_linux_amd64"
      sha256 "e7c63ef048c3c7c64ff11a5f1e16214a67e50a3be44c5c9e3d5ea1fd1b41bb6d"
    end
  end

  def install
    bin.install Dir["observer_*"].first => "observer"
  end

  test do
    assert_match "observer", shell_output("#{bin}/observer version")
  end
end