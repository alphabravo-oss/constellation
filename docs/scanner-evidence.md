# Image and package scan evidence

Image scans run Syft, Grype and Trivy. Syft collects packages and captures Go
function symbols (`SYFT_GOLANG_CAPTURE_SYMBOLS=all`). Grype's direct image scan
also captures symbols and uses the vulnerability database's package/symbol
qualifiers when available. Missing symbols remain unknown; their absence from an
inventory is not proof that a vulnerable function is absent from a binary.

A successful image engine result, including a clean result, replaces that same
engine's fallback package scan. Running the same engine again over a simplified
inventory can reintroduce module-wide matches after binary evidence narrowed the
result. This is not a vulnerability exclusion: the image engine's findings remain
intact, and findings from other engines are still aggregated.

If an image engine is absent or fails, its package matcher still runs when Syft
has supplied packages. Grype receives the original native Syft JSON when available,
preserving symbol tables, locations, distro metadata and relationships. If native
SBOM evidence is unavailable, it receives the existing conservative CycloneDX
package inventory. Trivy's fallback retains its supported CycloneDX input. Custom
matchers continue to run unless they explicitly opt into image-result replacement.

Host, platform and other package-only scans continue to run their package matchers;
they do not claim binary-level precision from package names and versions alone.
The scanner's optional govulncheck reachability analysis is a separate capability.

`Scan lease validation` includes the scanner regression suite and produces a
compiled `scanner.test` acceptance helper. `TestGoSymbolsActualTools` is opt-in:
set `CONSTELLATION_TEST_GO_SYMBOL_IMAGE` to an immutable, known-vulnerable Go image
and use the packaged Syft/Grype tools with a fixed, preloaded vulnerability DB. It
checks captured symbols, agreement between direct image and native-SBOM Grype
results, and the broader results of package-only matching. Live rollout validation
also checks engine completion, exact image identity, and authenticated private
registry scanning. A lower finding count alone is not acceptance evidence.

Grype's `constellation.2` build replaces the retired Docker module used for
local-image shell completion with the maintained Moby client. The scanner-tool
workflow validates both patched source behavior and the release-built executable.
`TestGrypeBinary` in `cmd/tools/scanner-tools` accepts
`CONSTELLATION_TEST_GRYPE_BINARY`, checks linked dependency metadata, and exercises
the real completion CLI against disposable daemon endpoints. It covers negotiated
and explicit API versions, tag filtering, and empty/error shell fallback.

On 2026-10-23, the Helm 157 scanner image
`ghcr.io/alphabravo-oss/constellation/scanner@sha256:4cd3d0bbb98cd0e04ea1216518f76454593b1306aaed4f0718a530ab8d2e79f0`
was verified to contain Grype `0.120.1-constellation.2`, Go `1.27.3`, and Moby client
`v0.6.0`, with no linked `github.com/docker/docker` module. All seven executable
checks passed twice on the extracted binary and twice inside that same image as
UID/GID `10001:10001`, with a read-only root, all capabilities dropped, no Docker
socket and external networking disabled. No cluster rollout was needed.

A separate direct Grype scan of that exact image returned zero matches using the
valid cached database built `2026-10-20T06:29:49Z`, with automatic DB updates
disabled and an empty explicit configuration. This result is scoped to that
engine and database snapshot; it is not a current multi-engine or signed-fixture
acceptance result.
