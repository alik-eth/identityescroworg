# Homebrew formula template for the QKB CLI.
#
# This file is the canonical source for the formula that lives in the external
# Homebrew tap repo `qkb-eth/homebrew-qkb`. When that repo is first set up,
# copy this file to `Formula/qkb.rb` in the tap repo. Subsequent updates are
# automated by the `update-tap` job in `.github/workflows/release-cli.yml`,
# which rewrites the `version` and the four `sha256` lines on each `cli-v*`
# tag push.
class Qkb < Formula
  desc "QKB CLI — generate proofs of verified Ukrainian identity"
  homepage "https://identityescrow.org"
  version "0.1.0"
  license "GPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/qkb-eth/identityescroworg/releases/download/cli-v#{version}/qkb-darwin-arm64"
      sha256 "<fill on release>"
    end
    on_intel do
      url "https://github.com/qkb-eth/identityescroworg/releases/download/cli-v#{version}/qkb-darwin-x64"
      sha256 "<fill on release>"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/qkb-eth/identityescroworg/releases/download/cli-v#{version}/qkb-linux-x64"
      sha256 "<fill on release>"
    end
    on_arm do
      url "https://github.com/qkb-eth/identityescroworg/releases/download/cli-v#{version}/qkb-linux-arm64"
      sha256 "<fill on release>"
    end
  end

  def install
    binary_name =
      if OS.mac?
        Hardware::CPU.arm? ? "qkb-darwin-arm64" : "qkb-darwin-x64"
      else
        Hardware::CPU.arm? ? "qkb-linux-arm64" : "qkb-linux-x64"
      end
    bin.install binary_name => "qkb"
  end

  test do
    system "#{bin}/qkb", "version"
  end
end
