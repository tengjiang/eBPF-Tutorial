#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#define MAX_SYSCALLS (500)

// you can get the most recent list of syscalls and their syscall number
// in order to populate the syscall_id_to_name[] array below by 
// running the following bash command

// grep "^#define __NR" /usr/include/asm-generic/unistd.h | cut -c14-| awk 'BEGIN {doit=1;} { if (doit) printf("      [%3d] = \"%s\",\n", $2,$1); if ($1 == "syscalls") { doit=0;} } '
// delete any duplicate syscall nr which imply function aliasing
// terminate with ,NULL 

const char *syscall_id_to_name[MAX_SYSCALLS] = {
      [  0] = "read",
      [  1] = "write",
      [  2] = "open",
      [  3] = "close",
      [  4] = "stat",
      [  5] = "fstat",
      [  6] = "lstat",
      [  7] = "poll",
      [  8] = "lseek",
      [  9] = "mmap",
      [ 10] = "mprotect",
      [ 11] = "munmap",
      [ 12] = "brk",
      [ 13] = "rt_sigaction",
      [ 14] = "rt_sigprocmask",
      [ 15] = "rt_sigreturn",
      [ 16] = "ioctl",
      [ 17] = "pread64",
      [ 18] = "pwrite64",
      [ 19] = "readv",
      [ 20] = "writev",
      [ 21] = "access",
      [ 22] = "pipe",
      [ 23] = "select",
      [ 24] = "sched_yield",
      [ 25] = "mremap",
      [ 26] = "msync",
      [ 27] = "mincore",
      [ 28] = "madvise",
      [ 29] = "shmget",
      [ 30] = "shmat",
      [ 31] = "shmctl",
      [ 32] = "dup",
      [ 33] = "dup2",
      [ 34] = "pause",
      [ 35] = "nanosleep",
      [ 36] = "getitimer",
      [ 37] = "alarm",
      [ 38] = "setitimer",
      [ 39] = "getpid",
      [ 40] = "sendfile",
      [ 41] = "socket",
      [ 42] = "connect",
      [ 43] = "accept",
      [ 44] = "sendto",
      [ 45] = "recvfrom",
      [ 46] = "sendmsg",
      [ 47] = "recvmsg",
      [ 48] = "shutdown",
      [ 49] = "bind",
      [ 50] = "listen",
      [ 51] = "getsockname",
      [ 52] = "getpeername",
      [ 53] = "socketpair",
      [ 54] = "setsockopt",
      [ 55] = "getsockopt",
      [ 56] = "clone",
      [ 57] = "fork",
      [ 58] = "vfork",
      [ 59] = "execve",
      [ 60] = "exit",
      [ 61] = "wait4",
      [ 62] = "kill",
      [ 63] = "uname",
      [ 64] = "semget",
      [ 65] = "semop",
      [ 66] = "semctl",
      [ 67] = "shmdt",
      [ 68] = "msgget",
      [ 69] = "msgsnd",
      [ 70] = "msgrcv",
      [ 71] = "msgctl",
      [ 72] = "fcntl",
      [ 73] = "flock",
      [ 74] = "fsync",
      [ 75] = "fdatasync",
      [ 76] = "truncate",
      [ 77] = "ftruncate",
      [ 78] = "getdents",
      [ 79] = "getcwd",
      [ 80] = "chdir",
      [ 81] = "fchdir",
      [ 82] = "rename",
      [ 83] = "mkdir",
      [ 84] = "rmdir",
      [ 85] = "creat",
      [ 86] = "link",
      [ 87] = "unlink",
      [ 88] = "symlink",
      [ 89] = "readlink",
      [ 90] = "chmod",
      [ 91] = "fchmod",
      [ 92] = "chown",
      [ 93] = "fchown",
      [ 94] = "lchown",
      [ 95] = "umask",
      [ 96] = "gettimeofday",
      [ 97] = "getrlimit",
      [ 98] = "getrusage",
      [ 99] = "sysinfo",
      [100] = "times",
      [101] = "ptrace",
      [102] = "getuid",
      [103] = "syslog",
      [104] = "getgid",
      [105] = "setuid",
      [106] = "setgid",
      [107] = "geteuid",
      [108] = "getegid",
      [109] = "setpgid",
      [110] = "getppid",
      [111] = "getpgrp",
      [112] = "setsid",
      [113] = "setreuid",
      [114] = "setregid",
      [115] = "getgroups",
      [116] = "setgroups",
      [117] = "setresuid",
      [118] = "getresuid",
      [119] = "setresgid",
      [120] = "getresgid",
      [121] = "getpgid",
      [122] = "setfsuid",
      [123] = "setfsgid",
      [124] = "getsid",
      [125] = "capget",
      [126] = "capset",
      [127] = "rt_sigpending",
      [128] = "rt_sigtimedwait",
      [129] = "rt_sigqueueinfo",
      [130] = "rt_sigsuspend",
      [131] = "sigaltstack",
      [132] = "utime",
      [133] = "mknod",
      [134] = "uselib",
      [135] = "personality",
      [136] = "ustat",
      [137] = "statfs",
      [138] = "fstatfs",
      [139] = "sysfs",
      [140] = "getpriority",
      [141] = "setpriority",
      [142] = "sched_setparam",
      [143] = "sched_getparam",
      [144] = "sched_setscheduler",
      [145] = "sched_getscheduler",
      [146] = "sched_get_priority_max",
      [147] = "sched_get_priority_min",
      [148] = "sched_rr_get_interval",
      [149] = "mlock",
      [150] = "munlock",
      [151] = "mlockall",
      [152] = "munlockall",
      [153] = "vhangup",
      [154] = "modify_ldt",
      [155] = "pivot_root",
      [156] = "_sysctl",
      [157] = "prctl",
      [158] = "arch_prctl",
      [159] = "adjtimex",
      [160] = "setrlimit",
      [161] = "chroot",
      [162] = "sync",
      [163] = "acct",
      [164] = "settimeofday",
      [165] = "mount",
      [166] = "umount2",
      [167] = "swapon",
      [168] = "swapoff",
      [169] = "reboot",
      [170] = "sethostname",
      [171] = "setdomainname",
      [172] = "iopl",
      [173] = "ioperm",
      [174] = "create_module",
      [175] = "init_module",
      [176] = "delete_module",
      [177] = "get_kernel_syms",
      [178] = "query_module",
      [179] = "quotactl",
      [180] = "nfsservctl",
      [181] = "getpmsg",
      [182] = "putpmsg",
      [183] = "afs_syscall",
      [184] = "tuxcall",
      [185] = "security",
      [186] = "gettid",
      [187] = "readahead",
      [188] = "setxattr",
      [189] = "lsetxattr",
      [190] = "fsetxattr",
      [191] = "getxattr",
      [192] = "lgetxattr",
      [193] = "fgetxattr",
      [194] = "listxattr",
      [195] = "llistxattr",
      [196] = "flistxattr",
      [197] = "removexattr",
      [198] = "lremovexattr",
      [199] = "fremovexattr",
      [200] = "tkill",
      [201] = "time",
      [202] = "futex",
      [203] = "sched_setaffinity",
      [204] = "sched_getaffinity",
      [205] = "set_thread_area",
      [206] = "io_setup",
      [207] = "io_destroy",
      [208] = "io_getevents",
      [209] = "io_submit",
      [210] = "io_cancel",
      [211] = "get_thread_area",
      [212] = "lookup_dcookie",
      [213] = "epoll_create",
      [214] = "epoll_ctl_old",
      [215] = "epoll_wait_old",
      [216] = "remap_file_pages",
      [217] = "getdents64",
      [218] = "set_tid_address",
      [219] = "restart_syscall",
      [220] = "semtimedop",
      [221] = "fadvise64",
      [222] = "timer_create",
      [223] = "timer_settime",
      [224] = "timer_gettime",
      [225] = "timer_getoverrun",
      [226] = "timer_delete",
      [227] = "clock_settime",
      [228] = "clock_gettime",
      [229] = "clock_getres",
      [230] = "clock_nanosleep",
      [231] = "exit_group",
      [232] = "epoll_wait",
      [233] = "epoll_ctl",
      [234] = "tgkill",
      [235] = "utimes",
      [236] = "vserver",
      [237] = "mbind",
      [238] = "set_mempolicy",
      [239] = "get_mempolicy",
      [240] = "mq_open",
      [241] = "mq_unlink",
      [242] = "mq_timedsend",
      [243] = "mq_timedreceive",
      [244] = "mq_notify",
      [245] = "mq_getsetattr",
      [246] = "kexec_load",
      [247] = "waitid",
      [248] = "add_key",
      [249] = "request_key",
      [250] = "keyctl",
      [251] = "ioprio_set",
      [252] = "ioprio_get",
      [253] = "inotify_init",
      [254] = "inotify_add_watch",
      [255] = "inotify_rm_watch",
      [256] = "migrate_pages",
      [257] = "openat",
      [258] = "mkdirat",
      [259] = "mknodat",
      [260] = "fchownat",
      [261] = "futimesat",
      [262] = "newfstatat",
      [263] = "unlinkat",
      [264] = "renameat",
      [265] = "linkat",
      [266] = "symlinkat",
      [267] = "readlinkat",
      [268] = "fchmodat",
      [269] = "faccessat",
      [270] = "pselect6",
      [271] = "ppoll",
      [272] = "unshare",
      [273] = "set_robust_list",
      [274] = "get_robust_list",
      [275] = "splice",
      [276] = "tee",
      [277] = "sync_file_range",
      [278] = "vmsplice",
      [279] = "move_pages",
      [280] = "utimensat",
      [281] = "epoll_pwait",
      [282] = "signalfd",
      [283] = "timerfd_create",
      [284] = "eventfd",
      [285] = "fallocate",
      [286] = "timerfd_settime",
      [287] = "timerfd_gettime",
      [288] = "accept4",
      [289] = "signalfd4",
      [290] = "eventfd2",
      [291] = "epoll_create1",
      [292] = "dup3",
      [293] = "pipe2",
      [294] = "inotify_init1",
      [295] = "preadv",
      [296] = "pwritev",
      [297] = "rt_tgsigqueueinfo",
      [298] = "perf_event_open",
      [299] = "recvmmsg",
      [300] = "fanotify_init",
      [301] = "fanotify_mark",
      [302] = "prlimit64",
      [303] = "name_to_handle_at",
      [304] = "open_by_handle_at",
      [305] = "clock_adjtime",
      [306] = "syncfs",
      [307] = "sendmmsg",
      [308] = "setns",
      [309] = "getcpu",
      [310] = "process_vm_readv",
      [311] = "process_vm_writev",
      [312] = "kcmp",
      [313] = "finit_module",
      [314] = "sched_setattr",
      [315] = "sched_getattr",
      [316] = "renameat2",
      [317] = "seccomp",
      [318] = "getrandom",
      [319] = "memfd_create",
      [320] = "kexec_file_load",
      [321] = "bpf",
      [322] = "execveat",
      [323] = "userfaultfd",
      [324] = "membarrier",
      [325] = "mlock2",
      [326] = "copy_file_range",
      [327] = "preadv2",
      [328] = "pwritev2",
      [329] = "pkey_mprotect",
      [330] = "pkey_alloc",
      [331] = "pkey_free",
      [332] = "statx",
      [333] = "io_pgetevents",
      [334] = "rseq",
      [424] = "pidfd_send_signal",
      [425] = "io_uring_setup",
      [426] = "io_uring_enter",
      [427] = "io_uring_register",
      [428] = "open_tree",
      [429] = "move_mount",
      [430] = "fsopen",
      [431] = "fsconfig",
      [432] = "fsmount",
      [433] = "fspick",
      [434] = "pidfd_open",
      [435] = "clone3",
      [436] = "close_range",
      [437] = "openat2",
      [438] = "pidfd_getfd",
      [439] = "faccessat2",
      [440] = "process_madvise",
      [441] = "epoll_pwait2",
      [442] = "mount_setattr",
      [443] = "quotactl_fd",
      [444] = "landlock_create_ruleset",
      [445] = "landlock_add_rule",
      [446] = "landlock_restrict_self",
      [447] = "memfd_secret",
      [448] = "process_mrelease",
      [449] = "futex_waitv",
      [450] = "set_mempolicy_home_node",
      [451] = "cachestat",
      [452] = "fchmodat2",
      [453] = "map_shadow_stack",
      [454] = "futex_wake",
      [455] = "futex_wait",
      [456] = "futex_requeue",
      [457] = "statmount",
      [458] = "listmount",
      [459] = "lsm_get_self_attr",
      [460] = "lsm_set_self_attr",
      [461] = "lsm_list_modules",
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
