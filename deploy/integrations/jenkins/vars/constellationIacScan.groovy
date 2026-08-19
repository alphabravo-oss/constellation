// Constellation IaC scan step.
//
// Usage:
//   constellationIacScan(path: '.', failOn: 'high')
def call(Map args = [:]) {
  String path   = args.path   ?: '.'
  String failOn = args.failOn ?: 'high'
  String sarif  = args.sarif  ?: 'constellation-iac.sarif'

  withCredentials([
    string(credentialsId: 'constellation-server', variable: 'CONSTELLATION_SERVER'),
    string(credentialsId: 'constellation-token',  variable: 'CONSTELLATION_TOKEN'),
  ]) {
    sh """
      set -o pipefail
      constellationctl iac-check '${path}' \\
        --fail-on ${failOn} \\
        --sarif   ${sarif} | tee constellation-iac.txt
    """
  }

  archiveArtifacts artifacts: "${sarif},constellation-iac.txt",
                   allowEmptyArchive: true,
                   fingerprint: true
}
