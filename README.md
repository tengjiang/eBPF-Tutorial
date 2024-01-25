# EECS6891: eBPF Tutorial

This repo contains the code and slides for course EECS6891 (eBPF Seminar).
The examples were tested on a Debian 12 VM.

## Slides

Slides are contained in a PDF file called [EECS6891 - eBPF Tutorial.pdf](./EECS6891%20-%20eBPF%20Tutorial.pdf)

## Dependencies

Install the following packages:
```sh
sudo apt-get install \
    clang \
    llvm \
    libelf-dev \
    libpcap-dev \
    build-essential \
    libbpf \
    linux-headers-$(uname -r) \
    bpftool
```

### Running the examples

Each folder contains an example. To run it, first compile:

```sh
make
```

And then run the `.out` file which is the driver.