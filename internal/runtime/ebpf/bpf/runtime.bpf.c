// runtime.bpf.c - Constellation runtime-agent CO-RE programs.
//
// Hooks (Wave 7 — network probes retired):
//   - tracepoint:sched_process_exec      -> process tree
//   - lsm:file_open                       -> file open events
//
// The network path lives in the NeuVector C data-plane (third_party/neuvector/dp)
// which gives us real on-wire bytes, sessions, L7 from DPI parsers, policy
// verdicts, and threat signatures — strictly more than the kprobe-based
// connect-event capture this program used to ship. The synthetic byte
// estimator that consumed those events was retired in Wave 7 too.
//
// Build:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//     -I/usr/include/bpf -I. \
//     -c runtime.bpf.c -o runtime.bpf.o
//
// Userspace contract (sync with loader_linux.go decodeRecord):
//
//   struct event_hdr { __u8 kind; __u8 _pad[3]; __u32 pid; __u32 ppid;
//                      __u32 uid; __u32 gid; __u64 cgroup_id; __u64 ts; };
//
//   kind=1 process:   hdr + comm[16] + filename[256] + args[256]
//   kind=4 file:      hdr + flags(4) mode(4) comm[16] path[256]

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_COMM 16
#define MAX_PATH 256
#define MAX_ARGS 256

char LICENSE[] SEC("license") = "GPL";

struct event_hdr {
    __u8 kind;
    __u8 _pad[3];
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    __u64 ts;
};

struct cstl_proc_event {
    struct event_hdr h;
    char comm[MAX_COMM];
    char filename[MAX_PATH];
    char args[MAX_ARGS];
};

struct cstl_file_event {
    struct event_hdr h;
    __u32 flags;
    __u32 mode;
    char comm[MAX_COMM];
    char path[MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline void fill_hdr(struct event_hdr *h, __u8 kind) {
    h->kind = kind;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    h->pid = (__u32)(pid_tgid >> 32);
    __u64 uid_gid = bpf_get_current_uid_gid();
    h->uid = (__u32)uid_gid;
    h->gid = (__u32)(uid_gid >> 32);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        h->ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;
    }
    h->cgroup_id = bpf_get_current_cgroup_id();
    h->ts = bpf_ktime_get_ns();
}

SEC("tp/sched/sched_process_exec")
int trace_sched_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct cstl_proc_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_hdr(&e->h, 1);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    unsigned int filename_loc = BPF_CORE_READ(ctx, __data_loc_filename);
    const char *fn = (const char *)((__u64)ctx + (filename_loc & 0xffff));
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);
    e->args[0] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file) {
    struct cstl_file_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_hdr(&e->h, 4);
    e->flags = BPF_CORE_READ(file, f_flags);
    e->mode = BPF_CORE_READ(file, f_mode);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // RT-1: emit the ABSOLUTE path, not the dentry leaf. The FIM / file-profile
    // matchers (handler/runtime_detections.go matchDefaultFIM, events_ingest.go)
    // only match leading-slash absolute paths, so a basename never matched.
    // bpf_d_path() is allowlisted for lsm/file_open and resolves f_path against
    // the mount tree, NUL-terminating into our buffer. It wants &f_path (a
    // pointer to the struct path field), which is in-bounds on the verified
    // file* argument here.
    // f_path is const in this kernel's BTF; bpf_d_path() takes a non-const
    // struct path*, so cast (read-only use, the helper only reads the path).
    long n = bpf_d_path((struct path *)&file->f_path, e->path, sizeof(e->path));
    if (n < 0)
        e->path[0] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
