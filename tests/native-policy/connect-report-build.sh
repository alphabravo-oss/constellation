#!/usr/bin/env bash
# Build actual connection-reporter regressions from the canonical native objects.
set -euo pipefail
cd /src
native_flags='-fno-inline -fno-ipa-cp -fno-ipa-sra -ffunction-sections -fdata-sections'
patch_file=/src/third_party/neuvector/local-patches/010-connection-lookup-application.patch
fixed_source="$(mktemp)"
cp third_party/neuvector/dp/ctrl.c "$fixed_source"
trap 'cp "$fixed_source" /src/third_party/neuvector/dp/ctrl.c; rm -f "$fixed_source"' EXIT
sha256sum third_party/neuvector/dp/ctrl.c > /native-connect-fixed-source.sha256
compile_entrypoint() {
    local variant="$1"
    local directory="/native-connect-${variant}-objects"
    objcopy --globalize-symbol=conn4_match --globalize-symbol=conn4_hash "$directory/ctrl.o"
    objcopy --globalize-symbol=g_start_time --globalize-symbol=g_seconds "$directory/pkt.o"
    gcc -Wall -Wextra -Werror -Os -Ithird_party/neuvector/dp \
        -include third_party/neuvector/base.h -include third_party/neuvector/defs.h \
        tests/native-policy/connect_report.c "$directory"/*.o \
        -o "/native-connect-report-${variant}" -Wl,--gc-sections \
        -lpcap -lpcre2-8 -ljansson -ljemalloc -pthread -lurcu -lurcu-cds \
        -lrt -lstdc++ -lm -lnetfilter_queue -lhs
    sha256sum "$directory"/*.o > "/native-connect-${variant}-objects.sha256"
}
for variant in standard unpatched pattern; do
    mkdir "/native-connect-${variant}-objects"
    cp /native-objects/*.o "/native-connect-${variant}-objects/"
done
# The normal compiler-flags binary runs the real fixed reporter.
compile_entrypoint standard
# Initialize otherwise indeterminate automatic values only for deterministic
# negative control. The same pattern flags also build the positive comparator.
(cd third_party/neuvector && patch -R -p1 --batch --fuzz=0 --no-backup-if-mismatch --silent < "$patch_file")
sha256sum third_party/neuvector/dp/ctrl.c > /native-connect-unpatched-source.sha256
make -B -C third_party/neuvector/dp .objs/ctrl.o \
    EXTRA_CFLAGS="$native_flags -ftrivial-auto-var-init=pattern"
cp third_party/neuvector/dp/.objs/ctrl.o /native-connect-unpatched-objects/ctrl.o
compile_entrypoint unpatched
cp "$fixed_source" third_party/neuvector/dp/ctrl.c
make -B -C third_party/neuvector/dp .objs/ctrl.o \
    EXTRA_CFLAGS="$native_flags -ftrivial-auto-var-init=pattern"
cp third_party/neuvector/dp/.objs/ctrl.o /native-connect-pattern-objects/ctrl.o
compile_entrypoint pattern
sha256sum -c /native-connect-fixed-source.sha256
sha256sum /native-connect-report-* >> /native-harness.sha256
gcc --version > /native-compiler.txt
