#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int prog_fd;

    // Load and verify BPF application
    fprintf(stderr, "Loading BPF code in memory\n");
    obj = bpf_object__open_file("unbounded_loop.bpf.o", NULL);
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
    prog = bpf_object__find_program_by_name(obj, "handle_tp");
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
    link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_execve");

    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: Attaching BPF program to tracepoint failed\n");
        return 1;
    }

    printf("BPF tracepoint program attached. Press ENTER to exit...\n");
    getchar();

    // Cleanup
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}
