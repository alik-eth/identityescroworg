# Homebrew formula template for the zkqes CLI.
#
# This file is the canonical source for the formula that lives in the external
# Homebrew tap repo `alik-eth/homebrew-zkqes`. When that repo is first set up,
# copy this file to `Formula/zkqes.rb` in the tap repo. Subsequent updates are
# automated by the `update-tap` job in `.github/workflows/release-cli.yml`,
# which rewrites the `version` and the four `sha256` lines on each `cli-v*`
# tag push.
class Zkqes < Formula
  desc "zkqes CLI — generate proofs of verified Ukrainian identity"
  homepage "https://zkqes.org"
  version "0.1.0"
  license "GPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/alik-eth/zkqes/releases/download/cli-v#{version}/zkqes-darwin-arm64"
      sha256 "<fill on release>"
    end
    on_intel do
      url "https://github.com/alik-eth/zkqes/releases/download/cli-v#{version}/zkqes-darwin-x64"
      sha256 "<fill on release>"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/alik-eth/zkqes/releases/download/cli-v#{version}/zkqes-linux-x64"
      sha256 "<fill on release>"
    end
    on_arm do
      url "https://github.com/alik-eth/zkqes/releases/download/cli-v#{version}/zkqes-linux-arm64"
      sha256 "<fill on release>"
    end
  end

  def install
    binary_name =
      if OS.mac?
        Hardware::CPU.arm? ? "zkqes-darwin-arm64" : "zkqes-darwin-x64"
      else
        Hardware::CPU.arm? ? "zkqes-linux-arm64" : "zkqes-linux-x64"
      end
    bin.install binary_name => "zkqes"
  end

  test do
    system "#{bin}/zkqes", "version"
  end
end
