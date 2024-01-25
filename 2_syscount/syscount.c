#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>

const char *syscall_id_to_name[] = {"sys_read",
                                    "sys_write",
                                    "sys_open",
                                    "sys_close",
                                    "sys_newstat",
                                    "sys_newfstat",
                                    "sys_newlstat",
                                    "sys_poll",
                                    "sys_lseek",
                                    "sys_mmap",
                                    "sys_mprotect",
                                    "sys_munmap",
                                    "sys_brk",
                                    "sys_rt_sigaction",
                                    "sys_rt_sigprocmask",
                                    "sys_rt_sigreturn",
                                    "sys_ioctl",
                                    "sys_pread64",
                                    "sys_pwrite64",
                                    "sys_readv",
                                    "sys_writev",
                                    "sys_access",
                                    "sys_pipe",
                                    "sys_select",
                                    "sys_sched_yield",
                                    "sys_mremap",
                                    "sys_msync",
                                    "sys_mincore",
                                    "sys_madvise",
                                    "sys_shmget",
                                    "sys_shmat",
                                    "sys_shmctl",
                                    "sys_dup",
                                    "sys_dup2",
                                    "sys_pause",
                                    "sys_nanosleep",
                                    "sys_getitimer",
                                    "sys_alarm",
                                    "sys_setitimer",
                                    "sys_getpid",
                                    "sys_sendfile",
                                    "sys_socket",
                                    "sys_connect",
                                    "sys_accept",
                                    "sys_sendto",
                                    "sys_recvfrom",
                                    "sys_sendmsg",
                                    "sys_recvmsg",
                                    "sys_shutdown",
                                    "sys_bind",
                                    "sys_listen",
                                    "sys_getsockname",
                                    "sys_getpeername",
                                    "sys_socketpair",
                                    "sys_setsockopt",
                                    "sys_getsockopt",
                                    "sys_clone",
                                    "sys_fork",
                                    "sys_vfork",
                                    "sys_execve",
                                    "sys_exit",
                                    "sys_wait4",
                                    "sys_kill",
                                    "sys_uname",
                                    "sys_semget",
                                    "sys_semop",
                                    "sys_semctl",
                                    "sys_shmdt",
                                    "sys_msgget",
                                    "sys_msgsnd",
                                    "sys_msgrcv",
                                    "sys_msgctl",
                                    "sys_fcntl",
                                    "sys_flock",
                                    "sys_fsync",
                                    "sys_fdatasync",
                                    "sys_truncate",
                                    "sys_ftruncate",
                                    "sys_getdents",
                                    "sys_getcwd",
                                    "sys_chdir",
                                    "sys_fchdir",
                                    "sys_rename",
                                    "sys_mkdir",
                                    "sys_rmdir",
                                    "sys_creat",
                                    "sys_link",
                                    "sys_unlink",
                                    "sys_symlink",
                                    "sys_readlink",
                                    "sys_chmod",
                                    "sys_fchmod",
                                    "sys_chown",
                                    "sys_fchown",
                                    "sys_lchown",
                                    "sys_umask",
                                    "sys_gettimeofday",
                                    "sys_getrlimit",
                                    "sys_getrusage",
                                    "sys_sysinfo",
                                    "sys_times",
                                    "sys_ptrace",
                                    "sys_getuid",
                                    "sys_syslog",
                                    "sys_getgid",
                                    "sys_setuid",
                                    "sys_setgid",
                                    "sys_geteuid",
                                    "sys_getegid",
                                    "sys_setpgid",
                                    "sys_getppid",
                                    "sys_getpgrp",
                                    "sys_setsid",
                                    "sys_setreuid",
                                    "sys_setregid",
                                    "sys_getgroups",
                                    "sys_setgroups",
                                    "sys_setresuid",
                                    "sys_getresuid",
                                    "sys_setresgid",
                                    "sys_getresgid",
                                    "sys_getpgid",
                                    "sys_setfsuid",
                                    "sys_setfsgid",
                                    "sys_getsid",
                                    "sys_capget",
                                    "sys_capset",
                                    "sys_rt_sigpending",
                                    "sys_rt_sigtimedwait",
                                    "sys_rt_sigqueueinfo",
                                    "sys_rt_sigsuspend",
                                    "sys_sigaltstack",
                                    "sys_utime",
                                    "sys_mknod",
                                    "sys_uselib",
                                    "sys_personality",
                                    "sys_ustat",
                                    "sys_statfs",
                                    "sys_fstatfs",
                                    "sys_sysfs",
                                    "sys_getpriority",
                                    "sys_setpriority",
                                    "sys_sched_setparam",
                                    "sys_sched_getparam",
                                    "sys_sched_setscheduler",
                                    "sys_sched_getscheduler",
                                    "sys_sched_get_priority_max",
                                    "sys_sched_get_priority_min",
                                    "sys_sched_rr_get_interval",
                                    "sys_mlock",
                                    "sys_munlock",
                                    "sys_mlockall",
                                    "sys_munlockall",
                                    "sys_vhangup",
                                    "sys_modify_ldt",
                                    "sys_pivot_root",
                                    "_sysctl",
                                    "sys_prctl",
                                    "sys_arch_prctl",
                                    "sys_adjtimex",
                                    "sys_setrlimit",
                                    "sys_chroot",
                                    "sys_sync",
                                    "sys_acct",
                                    "sys_settimeofday",
                                    "sys_mount",
                                    "sys_umount2",
                                    "sys_swapon",
                                    "sys_swapoff",
                                    "sys_reboot",
                                    "sys_sethostname",
                                    "sys_setdomainname",
                                    "stub_iopl",
                                    "sys_ioperm",
                                    "create_module",
                                    "sys_init_module",
                                    "sys_delete_module",
                                    "get_kernel_syms",
                                    "query_module",
                                    "sys_quotactl",
                                    "nfsservctl",
                                    "getpmsg",
                                    "putpmsg",
                                    "afs_syscall",
                                    "tuxcall",
                                    "security",
                                    "sys_gettid",
                                    "sys_readahead",
                                    "sys_setxattr",
                                    "sys_lsetxattr",
                                    "sys_fsetxattr",
                                    "sys_getxattr",
                                    "sys_lgetxattr",
                                    "sys_fgetxattr",
                                    "sys_listxattr",
                                    "sys_llistxattr",
                                    "sys_flistxattr",
                                    "sys_removexattr",
                                    "sys_lremovexattr",
                                    "sys_fremovexattr",
                                    "sys_tkill",
                                    "sys_time",
                                    "sys_futex",
                                    "sys_sched_setaffinity",
                                    "sys_sched_getaffinity",
                                    "set_thread_area",
                                    "sys_io_setup",
                                    "sys_io_destroy",
                                    "sys_io_getevents",
                                    "sys_io_submit",
                                    "sys_io_cancel",
                                    "get_thread_area",
                                    "sys_lookup_dcookie",
                                    "sys_epoll_create",
                                    "epoll_ctl_old",
                                    "epoll_wait_old",
                                    "sys_remap_file_pages",
                                    "sys_getdents64",
                                    "sys_set_tid_address",
                                    "sys_restart_syscall",
                                    "sys_semtimedop",
                                    "sys_fadvise64",
                                    "sys_timer_create",
                                    "sys_timer_settime",
                                    "sys_timer_gettime",
                                    "sys_timer_getoverrun",
                                    "sys_timer_delete",
                                    "sys_clock_settime",
                                    "sys_clock_gettime",
                                    "sys_clock_getres",
                                    "sys_clock_nanosleep",
                                    "sys_exit_group",
                                    "sys_epoll_wait",
                                    "sys_epoll_ctl",
                                    "sys_tgkill",
                                    "sys_utimes",
                                    "vserver",
                                    "sys_mbind",
                                    "sys_set_mempolicy",
                                    "sys_get_mempolicy",
                                    "sys_mq_open",
                                    "sys_mq_unlink",
                                    "sys_mq_timedsend",
                                    "sys_mq_timedreceive",
                                    "sys_mq_notify",
                                    "sys_mq_getsetattr",
                                    "sys_kexec_load",
                                    "sys_waitid",
                                    "sys_add_key",
                                    "sys_request_key",
                                    "sys_keyctl",
                                    "sys_ioprio_set",
                                    "sys_ioprio_get",
                                    "sys_inotify_init",
                                    "sys_inotify_add_watch",
                                    "sys_inotify_rm_watch",
                                    "sys_migrate_pages",
                                    "sys_openat",
                                    "sys_mkdirat",
                                    "sys_mknodat",
                                    "sys_fchownat",
                                    "sys_futimesat",
                                    "sys_newfstatat",
                                    "sys_unlinkat",
                                    "sys_renameat",
                                    "sys_linkat",
                                    "sys_symlinkat",
                                    "sys_readlinkat",
                                    "sys_fchmodat",
                                    "sys_faccessat",
                                    "sys_pselect6",
                                    "sys_ppoll",
                                    "sys_unshare",
                                    "sys_set_robust_list",
                                    "sys_get_robust_list",
                                    "sys_splice",
                                    "sys_tee",
                                    "sys_sync_file_range",
                                    "sys_vmsplice",
                                    "sys_move_pages",
                                    "sys_utimensat",
                                    "sys_epoll_pwait",
                                    "sys_signalfd",
                                    "sys_timerfd_create",
                                    "sys_eventfd",
                                    "sys_fallocate",
                                    "sys_timerfd_settime",
                                    "sys_timerfd_gettime",
                                    "sys_accept4",
                                    "sys_signalfd4",
                                    "sys_eventfd2",
                                    "sys_epoll_create1",
                                    "sys_dup3",
                                    "sys_pipe2",
                                    "sys_inotify_init1",
                                    "sys_preadv",
                                    "sys_pwritev",
                                    "sys_rt_tgsigqueueinfo",
                                    "sys_perf_event_open",
                                    "sys_recvmmsg",
                                    "sys_fanotify_init",
                                    "sys_fanotify_mark",
                                    "sys_prlimit64",
                                    "sys_name_to_handle_at",
                                    "sys_open_by_handle_at",
                                    "sys_clock_adjtime",
                                    "sys_syncfs",
                                    "sys_sendmmsg",
                                    "sys_setns",
                                    "sys_getcpu",
                                    "sys_process_vm_readv",
                                    "sys_process_vm_writev",
                                    "sys_kcmp",
                                    "sys_finit_module"};

__u64 prev_syscall_counts[500];
__u64 syscall_counts[500];

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
        for (int i = 0; i < 500; i++) {
            if (syscall_counts[i] > 0) {
                printf("%s: %llu\n", syscall_id_to_name[i],
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
