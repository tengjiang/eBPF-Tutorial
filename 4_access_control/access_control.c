#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *links[2];
    int prog_fd;

    // Load and verify BPF application
    fprintf(stderr, "Loading BPF code in memory\n");
    obj = bpf_object__open_file("access_control.bpf.o", NULL);
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
    char *prog_names[] = {"lsm_access_control_open",
                          "lsm_access_control_file_permission"};
    for (int i = 0; i < 2; i++) {
        printf("Attaching program %s\n", prog_names[i]);
        prog = bpf_object__find_program_by_name(obj, prog_names[i]);
        if (libbpf_get_error(prog)) {
            fprintf(stderr, "ERROR: finding BPF program failed\n");
            return 1;
        }
        prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            fprintf(stderr, "ERROR: getting BPF program FD failed\n");
            return 1;
        }

        links[i] = bpf_program__attach_lsm(prog);
        if (libbpf_get_error(links[i])) {
            fprintf(stderr,
                    "ERROR: Attaching BPF program to LSM hook failed\n");
            return 1;
        }
    }

    printf("BPF program attached. Press ENTER to exit...\n");
    getchar();

    // Cleanup
    for (int i = 0; i < 2; i++) {
        bpf_link__destroy(links[i]);
    }
    bpf_object__close(obj);

    return 0;
}
