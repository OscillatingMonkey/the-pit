# Homebrew formula for The Pit.
#
#   brew tap oscillatingmonkey/the-pit https://github.com/OscillatingMonkey/the-pit
#   brew install --HEAD the-pit
#
# Once a release is tagged, `scripts/release vX.Y.Z` fills in `url` and `sha256`
# so `brew install the-pit` (without --HEAD) works.
class ThePit < Formula
  desc "Encrypted local secrets vault with an integration rail (Fly, Vercel, GitHub, .env)"
  homepage "https://github.com/OscillatingMonkey/the-pit"
  license "MIT"
  head "https://github.com/OscillatingMonkey/the-pit.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  def caveats
    <<~EOS
      Create your vault and keep the agent running:
        pit init
        pit service install
    EOS
  end

  test do
    assert_match version.to_s.sub(/^HEAD-.*/, ""), shell_output("#{bin}/pit --version")
  end
end
