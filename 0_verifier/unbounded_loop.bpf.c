// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Laura Bauman */
/* Adapted by teng in 2024 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_tp(void *ctx)
{
    for (int i = 0; i >= 0; i++) { // Should not pass the verifier
        bpf_printk("Hello World.\n");
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";