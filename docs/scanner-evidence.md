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
