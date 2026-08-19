// Constellation image scan step.
//
// Usage in a Jenkinsfile:
//
//   @Library('constellation-ci') _
//   pipeline {
//     agent { docker { image 'constellation/cli:latest' } }
//     stages {
//       stage('Scan image') {
//         steps {
//           constellationScan(image: "my-app:${env.GIT_COMMIT}")
//         }
//       }
//     }
//   }
//
// Required Jenkins credentials (bind via withCredentials):
//   constellation-server   secretText
//   constellation-token    secretText
def call(Map args = [:]) {
  String image    = args.image    ?: error('constellationScan: image is required')
  String failOn   = args.failOn   ?: 'critical'
  String sarif    = args.sarif    ?: 'constellation.sarif'
  String jsonOut  = args.json     ?: 'constellation.json'
  boolean publish = args.publishSarif != false

  withCredentials([
    string(credentialsId: 'constellation-server', variable: 'CONSTELLATION_SERVER'),
    string(credentialsId: 'constellation-token',  variable: 'CONSTELLATION_TOKEN'),
  ]) {
    sh """
      set -o pipefail
      constellationctl image-check '${image}' \\
        --fail-on ${failOn} \\
        --sarif   ${sarif} \\
        --json    ${jsonOut} \\
        --quiet | tee constellation-scan.txt
    """
  }

  archiveArtifacts artifacts: "${sarif},${jsonOut},constellation-scan.txt",
                   allowEmptyArchive: true,
                   fingerprint: true

  if (publish && fileExists(sarif)) {
    // Plugin: warnings-ng. Skip silently if not installed.
    try {
      recordIssues tool: sarif(pattern: sarif, id: 'constellation-image',
                               name: 'Constellation image scan')
    } catch (NoSuchMethodError | MissingMethodException ignored) {
      echo "constellationScan: warnings-ng plugin not installed, skipping recordIssues"
    }
  }
}
