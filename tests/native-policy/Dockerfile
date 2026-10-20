# Test-only build: compile vendored sources plus declared patches, expose local
# symbols in COPIED objects, and link a disposable policy-matcher entry point.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential binutils pkg-config ca-certificates \
    libpcap-dev libpcre2-dev libnetfilter-queue-dev libnfnetlink-dev \
    libmnl-dev libvectorscan-dev libjansson-dev libjemalloc-dev liburcu-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY third_party/neuvector/ /src/third_party/neuvector/
COPY tests/native-policy/ /src/tests/native-policy/
RUN find third_party/neuvector -type d \( -name .objs -o -name .deps \) -prune -exec rm -rf '{}' + \
    && rm -f third_party/neuvector/dp/dp \
    && find third_party/neuvector -type f -print0 | sort -z | xargs -0 sha256sum > /native-source.sha256 \
    && make -B -C third_party/neuvector/dp EXTRA_CFLAGS='-fno-inline -fno-ipa-cp -fno-ipa-sra -ffunction-sections -fdata-sections' \
    && mkdir /native-objects \
    && cp third_party/neuvector/dp/.objs/*.o /native-objects/ \
    && cp third_party/neuvector/dp/dpi/.objs/dpi.o /native-objects/ \
    && cp third_party/neuvector/dp/utils/.objs/utils.o /native-objects/ \
    && sha256sum /native-objects/*.o > /native-original-objects.sha256 \
    && objcopy --redefine-sym main=native_unused_main --globalize-symbol=dp_ep_match --globalize-symbol=dp_ep_hash /native-objects/main.o \
    && objcopy --globalize-symbol=dp_ctrl_cfg_policy --globalize-symbol=dp_ctrl_add_mac --globalize-symbol=dp_ctrl_enable_icmp_policy /native-objects/ctrl.o \
    && objcopy --globalize-symbol=_dpi_policy_lookup_by_key --globalize-symbol=dpi_policy_lookup_by_key /native-objects/dpi.o \
    && nm -g /native-objects/ctrl.o | grep ' T dp_ctrl_cfg_policy$' \
    && nm -g /native-objects/dpi.o | grep ' T _dpi_policy_lookup_by_key$' \
    && gcc -Wall -Wextra -Werror -Os -Ithird_party/neuvector/dp \
        -include third_party/neuvector/base.h -include third_party/neuvector/defs.h \
        tests/native-policy/matcher.c /native-objects/*.o -o /native-policy-matcher \
        -Wl,--gc-sections -lpcap -lpcre2-8 -ljansson -ljemalloc -pthread \
        -lurcu -lurcu-cds -lrt -lstdc++ -lm -lnetfilter_queue -lhs \
    && sha256sum /native-policy-matcher > /native-harness.sha256 \
    && bash tests/native-policy/connect-report-build.sh \
    && sha256sum tests/native-policy/matcher.c tests/native-policy/connect_report.c tests/native-policy/connect-report-build.sh tests/native-policy/Dockerfile tests/native-policy/run.sh > /native-harness-source.sha256
USER 65534:65534
ENTRYPOINT ["/native-policy-matcher"]
