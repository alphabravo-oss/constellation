// Constellation SBOM generation step.
//
// Usage:
//   constellationSbom(image: "my-app:${env.GIT_COMMIT}")
//
// Outputs (archived):
//   constellation.spdx.json
//   constellation.cyclonedx.json
def call(Map args = [:]) {
  String image     = args.image     ?: error('constellationSbom: image is required')
  String spdx      = args.spdx      ?: 'constellation.spdx.json'
  String cyclonedx = args.cyclonedx ?: 'constellation.cyclonedx.json'

  withCredentials([
    string(credentialsId: 'constellation-server', variable: 'CONSTELLATION_SERVER'),
    string(credentialsId: 'constellation-token',  variable: 'CONSTELLATION_TOKEN'),
  ]) {
    sh """
      constellationctl image-check '${image}' \\
        --quiet \\
        --spdx      ${spdx} \\
        --cyclonedx ${cyclonedx}
    """
  }

  archiveArtifacts artifacts: "${spdx},${cyclonedx}",
                   allowEmptyArchive: false,
                   fingerprint: true
}
