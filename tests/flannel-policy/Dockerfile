# Thin fixture image: unchanged, qualified native DP and shared libraries.
ARG RUNTIME_IMAGE
FROM ${RUNTIME_IMAGE}
ARG PROOF_NONCE
LABEL constellation.flannel-proof="${PROOF_NONCE}"
COPY driver /usr/local/bin/flannel-policy-driver
COPY fixture /usr/local/bin/flannel-policy-fixture
ENTRYPOINT ["/usr/local/bin/flannel-policy-fixture"]
