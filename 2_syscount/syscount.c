#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#define MAX_SYSCALLS (500)

const char *syscall_id_to_name[MAX_SYSCALLS] = {
          "read",
          "write",
          "open",
          "close",
          "stat",
          "fstat",
          "lstat",
          "poll",
          "lseek",
          "mmap",
          "mprotect",
          "munmap",
          "brk",
          "rt_sigaction",
          "rt_sigprocmask",
          "rt_sigreturn",
          "ioctl",
          "pread64",
          "pwrite64",
          "readv",
          "writev",
          "access",
          "pipe",
          "select",
          "sched_yield",
          "mremap",
          "msync",
          "mincore",
          "madvise",
          "shmget",
          "shmat",
          "shmctl",
          "dup",
          "dup2",
          "pause",
          "nanosleep",
          "getitimer",
          "alarm",
          "setitimer",
          "getpid",
          "sendfile",
          "socket",
          "connect",
          "accept",
          "sendto",
          "recvfrom",
          "sendmsg",
          "recvmsg",
          "shutdown",
          "bind",
          "listen",
          "getsockname",
          "getpeername",
          "socketpair",
          "setsockopt",
          "getsockopt",
          "clone",
          "fork",
          "vfork",
          "execve",
          "exit",
          "wait4",
          "kill",
          "uname",
          "semget",
          "semop",
          "semctl",
          "shmdt",
          "msgget",
          "msgsnd",
          "msgrcv",
          "msgctl",
          "fcntl",
          "flock",
          "fsync",
          "fdatasync",
          "truncate",
          "ftruncate",
          "getdents",
          "getcwd",
          "chdir",
          "fchdir",
          "rename",
          "mkdir",
          "rmdir",
          "creat",
          "link",
          "unlink",
          "symlink",
          "readlink",
          "chmod",
          "fchmod",
          "chown",
          "fchown",
          "lchown",
          "umask",
          "gettimeofday",
          "getrlimit",
          "getrusage",
          "sysinfo",
          "times",
          "ptrace",
          "getuid",
          "syslog",
          "getgid",
          "setuid",
          "setgid",
          "geteuid",
          "getegid",
          "setpgid",
          "getppid",
          "getpgrp",
          "setsid",
          "setreuid",
          "setregid",
          "getgroups",
          "setgroups",
          "setresuid",
          "getresuid",
          "setresgid",
          "getresgid",
          "getpgid",
          "setfsuid",
          "setfsgid",
          "getsid",
          "capget",
          "capset",
          "rt_sigpending",
          "rt_sigtimedwait",
          "rt_sigqueueinfo",
          "rt_sigsuspend",
          "sigaltstack",
          "utime",
          "mknod",
          "uselib",
          "personality",
          "ustat",
          "statfs",
          "fstatfs",
          "sysfs",
          "getpriority",
          "setpriority",
          "sched_setparam",
          "sched_getparam",
          "sched_setscheduler",
          "sched_getscheduler",
          "sched_get_priority_max",
          "sched_get_priority_min",
          "sched_rr_get_interval",
          "mlock",
          "munlock",
          "mlockall",
          "munlockall",
          "vhangup",
          "modify_ldt",
          "pivot_root",
          "_sysctl",
          "prctl",
          "arch_prctl",
          "adjtimex",
          "setrlimit",
          "chroot",
          "sync",
          "acct",
          "settimeofday",
          "mount",
          "umount2",
          "swapon",
          "swapoff",
          "reboot",
          "sethostname",
          "setdomainname",
          "iopl",
          "ioperm",
          "create_module",
          "init_module",
          "delete_module",
          "get_kernel_syms",
          "query_module",
          "quotactl",
          "nfsservctl",
          "getpmsg",
          "putpmsg",
          "afs_syscall",
          "tuxcall",
          "security",
          "gettid",
          "readahead",
          "setxattr",
          "lsetxattr",
          "fsetxattr",
          "getxattr",
          "lgetxattr",
          "fgetxattr",
          "listxattr",
          "llistxattr",
          "flistxattr",
          "removexattr",
          "lremovexattr",
          "fremovexattr",
          "tkill",
          "time",
          "futex",
          "sched_setaffinity",
          "sched_getaffinity",
          "set_thread_area",
          "io_setup",
          "io_destroy",
          "io_getevents",
          "io_submit",
          "io_cancel",
          "get_thread_area",
          "lookup_dcookie",
          "epoll_create",
          "epoll_ctl_old",
          "epoll_wait_old",
          "remap_file_pages",
          "getdents64",
          "set_tid_address",
          "restart_syscall",
          "semtimedop",
          "fadvise64",
          "timer_create",
          "timer_settime",
          "timer_gettime",
          "timer_getoverrun",
          "timer_delete",
          "clock_settime",
          "clock_gettime",
          "clock_getres",
          "clock_nanosleep",
          "exit_group",
          "epoll_wait",
          "epoll_ctl",
          "tgkill",
          "utimes",
          "vserver",
          "mbind",
          "set_mempolicy",
          "get_mempolicy",
          "mq_open",
          "mq_unlink",
          "mq_timedsend",
          "mq_timedreceive",
          "mq_notify",
          "mq_getsetattr",
          "kexec_load",
          "waitid",
          "add_key",
          "request_key",
          "keyctl",
          "ioprio_set",
          "ioprio_get",
          "inotify_init",
          "inotify_add_watch",
          "inotify_rm_watch",
          "migrate_pages",
          "openat",
          "mkdirat",
          "mknodat",
          "fchownat",
          "futimesat",
          "newfstatat",
          "unlinkat",
          "renameat",
          "linkat",
          "symlinkat",
          "readlinkat",
          "fchmodat",
          "faccessat",
          "pselect6",
          "ppoll",
          "unshare",
          "set_robust_list",
          "get_robust_list",
          "splice",
          "tee",
          "sync_file_range",
          "vmsplice",
          "move_pages",
          "utimensat",
          "epoll_pwait",
          "signalfd",
          "timerfd_create",
          "eventfd",
          "fallocate",
          "timerfd_settime",
          "timerfd_gettime",
          "accept4",
          "signalfd4",
          "eventfd2",
          "epoll_create1",
          "dup3",
          "pipe2",
          "inotify_init1",
          "preadv",
          "pwritev",
          "rt_tgsigqueueinfo",
          "perf_event_open",
          "recvmmsg",
          "fanotify_init",
          "fanotify_mark",
          "prlimit64",
          "name_to_handle_at",
          "open_by_handle_at",
          "clock_adjtime",
          "syncfs",
          "sendmmsg",
          "setns",
          "getcpu",
          "process_vm_readv",
          "process_vm_writev",
          "kcmp",
          "finit_module",
          "sched_setattr",
          "sched_getattr",
          "renameat2",
          "seccomp",
          "getrandom",
          "memfd_create",
          "kexec_file_load",
          "bpf",
          "execveat",
          "userfaultfd",
          "membarrier",
          "mlock2",
          "copy_file_range",
          "preadv2",
          "pwritev2",
          "pkey_mprotect",
          "pkey_alloc",
          "pkey_free",
          "statx",
          "io_pgetevents",
          "rseq",
          "pidfd_send_signal",
          "io_uring_setup",
          "io_uring_enter",
          "io_uring_register",
          "open_tree",
          "move_mount",
          "fsopen",
          "fsconfig",
          "fsmount",
          "fspick",
          "pidfd_open",
          "clone3",
          "close_range",
          "openat2",
          "pidfd_getfd",
          "faccessat2",
          "process_madvise",
          "epoll_pwait2",
          "mount_setattr",
          "quotactl_fd",
          "landlock_create_ruleset",
          "landlock_add_rule",
          "landlock_restrict_self",
          "memfd_secret",
          "process_mrelease",
          "futex_waitv",
          "set_mempolicy_home_node",
          "cachestat",
          "fchmodat2",
          "map_shadow_stack",
          "futex_wake",
          "futex_wait",
          "futex_requeue",
          NULL,
};

__u64 prev_syscall_counts[MAX_SYSCALLS];
__u64 syscall_counts[MAX_SYSCALLS];

int get_cpu_count() { return get_nprocs(); }

__u64 roundup(__u64 num_to_round, __u64 multiple) {
    return ((num_to_round + multiple - 1) / multiple) * multiple;
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int prog_fd;

    // Load and verify BPF application
    fprintf(stderr, "Loading BPF code in memory\n");
    obj = bpf_object__open_file("syscount.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    // Load BPF program
    fprintf(stderr, "Loading and verifying the code in the kernel\n");
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    // Attach BPF program
    fprintf(stderr, "Attaching BPF program to tracepoint\n");
    prog = bpf_object__find_program_by_name(obj, "syscount");
    if (libbpf_get_error(prog)) {
        fprintf(stderr, "ERROR: finding BPF program failed\n");
        return 1;
    }
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: getting BPF program FD failed\n");
        return 1;
    }
    // Check it out at: /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter
    link = bpf_program__attach_tracepoint(prog, "raw_syscalls", "sys_enter");

    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: Attaching BPF program to tracepoint failed\n");
        return 1;
    }

    // Get syscall_id_to_count map
    struct bpf_map *map;
    map = bpf_object__find_map_by_name(obj, "syscall_id_to_count");
    if (libbpf_get_error(map)) {
        fprintf(stderr, "ERROR: finding BPF map failed\n");
        return 1;
    }

    // Initialize total counts
    for (int i = 0; i < 500; i++) {
        prev_syscall_counts[i] = 0;
    }
    int map_fd = bpf_map__fd(map);
    int num_cpus = get_cpu_count();
    __u64 *values = (__u64 *)malloc(roundup(sizeof(__u64), 8) * num_cpus);
    // For each CPU, iterate through map keys
    // First, get the number of CPUs in the system
    while (1) {
        sleep(5);
        // Gather values
        __u64 *curr_key = NULL;
        __u64 next_key;
        while (bpf_map_get_next_key(map_fd, curr_key, &next_key) == 0) {
            printf("Key: %llu\n", next_key);
            // Get value
            // This kernel
            bpf_map_lookup_elem(map_fd, &next_key, values);
            // Add to total
            __u64 new_total = 0;
            for (int i = 0; i < num_cpus; i++) {
                new_total += values[i];
            }
            syscall_counts[next_key] = new_total - prev_syscall_counts[next_key];
            prev_syscall_counts[next_key] = new_total;
            // Update key
            curr_key = &next_key;
        }
        // Print results
        printf("START: Syscall counts:\n");
        for (int i = 0; i < MAX_SYSCALLS; i++) {
            if (syscall_counts[i] > 0) {
                const char *sc_name = syscall_id_to_name[i];
                printf("%3d %s: %llu\n", i, sc_name ? sc_name : "noname",
                       syscall_counts[i]);
            }
        }
        printf("END: Syscall counts\n\n");
    }

    // Cleanup
    free(values);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}
