# Thin fixture image: unchanged, qualified native DP and shared libraries.
ARG RUNTIME_IMAGE=constellation/runtime-agent:scope-20261017-6c4a1cc
FROM ${RUNTIME_IMAGE}
ARG PROOF_NONCE
LABEL constellation.flannel-proof="${PROOF_NONCE}"
COPY driver /usr/local/bin/flannel-policy-driver
COPY fixture /usr/local/bin/flannel-policy-fixture
ENTRYPOINT ["/usr/local/bin/flannel-policy-fixture"]
