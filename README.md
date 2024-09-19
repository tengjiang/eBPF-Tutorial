# EECS6891: eBPF Tutorial

This repo contains the code and slides for course EECS6891 (eBPF Seminar).
The examples were tested on a Debian 12 VM and an x86 machine with kernel version 5.15.

## Slides

Slides are contained in a PDF file called [EECS6891 - eBPF Tutorial.pdf](./EECS6891%20-%20eBPF%20Tutorial.pdf)

## Dependencies

Install the following packages:
```sh
sudo apt install \
    clang \
    llvm \
    libelf-dev \
    libpcap-dev \
    build-essential \
    libbpf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    linux-tools-common 
```


### Running the examples

Each folder contains an example. To run it, first compile:

```sh
make
```

And then run the `.out` file which is the driver. More detailed instructions (if needed) are in each folder.


### About `vmlinux.h`
`vmlinux.h` is essential for eBPF programs because it provides the kernel's type definitions and data structures, enabling the programs to interact with the kernel. It supports BPF's CO-RE (Compile Once, Run Everywhere) feature, allowing programs to be portable across different kernel versions. By including `vmlinux.h`, developers can avoid manually defining kernel structures, making eBPF development easier and more efficient.

`vmlinux.h` is generated code. To generate `vmlinux.h`:
```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### References
* https://www.aquasec.com/blog/vmlinux-h-ebpf-programs/


