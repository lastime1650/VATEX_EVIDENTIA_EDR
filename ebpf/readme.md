# EBPF Initialize

## 1. create vmlinux.h
```c

/*
    Debian
*/
sudo apt install linux-image-$(uname -r)-dbgsym
sudo apt install bpftool
bpftool btf dump file /path/to/vmlinux format c > vmlinux.h

/*
    Redhat
*/
sudo dnf install dnf-plugins-core
sudo dnf debuginfo-install kernel-$(uname -r)
sudo dnf install bpftool
bpftool btf dump file /usr/lib/debug/lib/modules/$(uname -r)/vmlinux format c > vmlinux.h

```

## 2. (For the Network bpf) tc filter check and enable
