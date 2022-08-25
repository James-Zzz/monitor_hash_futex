# monitor_hash_futex
Demo for testing monitor hash_futex kernel function call

Validated at kernel version: 5.15

Please install clang-12

## Prerequisites
CONFIG_DEBUG_INFO_BTF must be configured.
Check CONFIG_DEBUG_INFO_BTF on your kenrel config:
```
#cat /boot//config-$(uname -r)|grep BTF
```
## Build

Clone libbpf-bootstrap from:[libbfp-bootstrap](https://github.com/libbpf/libbpf-bootstrap.git)

Change work directory to libbpf-bootstrap, fetch source code form submodules
```
#git submodule update --init --recursive
```

Clone bcc source code from: [bcc](https://github.com/iovisor/bcc.git)

Clone libbpf source code to bcc/src/cc/libbpf folder from: [libbpf](https://github.com/libbpf/libbpf.git)

Change work directory to bcc/libbpf-tools, add monitor_hash_futex to "APPS" in Makefile, and then make:
```
#make BPFTOOL_SRC=/src/to/libbpf-bootstrap/bpftool/src CLANG=/usr/bin/clang-12
```

monitor_hash_futex executable would be generated at bcc/libbpf-tools folder.

## Usage:
Step 1. Launch monitor_hash_futex to monitor hash_futex:
```
#sudo ./monitor_hash_futex
```
