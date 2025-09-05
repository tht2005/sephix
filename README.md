# sephix - a lightweight tool for creating sandbox environment

## Dependencies
- Flex
- Bison
- Libconfuse (temporary)
- Libseccomp
- Libcap
- Libnl

## Usage
```bash
sephix --profile <profile_name|profile_path> exec <command>
```

## Profile
Profile is located at `/etc/sephix/<profile_name>` or `~/.config/sephix/<profile_name` by default.
```conf
# Unshare namespaces
unshare-uts
unshare-ipc
unshare-pid
unshare-net
unshare-cgroup

# Make directory in sandbox and bind from the host
mkdir /dev
bind /dev /dev

mkdir /usr
bind /usr /usr

mkdir /home
bind /home /home

mkdir /lib
bind /lib /lib

mkdir /lib64
bind /lib64 /lib64

mkdir /etc
bind /etc /etc

mkdir /tmp
tmpfs /tmp

mkdir /proc
proc /proc

# Set permission for files and directories
perm r /
perm w /dev/
perm rx /usr/bin/ /lib64/ /usr/lib64/
perm rwxc @{HOME} # built-in @{...} variable
perm rwc /tmp

# Filter syscalls
seccomp.default allow # or kill, kill-process (default behavior of seccomp filter)
seccomp.allow ioctl
seccomp.deny mount umount2 pivot_root move_mount open_tree ptrace bpf
seccomp.deny userfaultfd perf_event_open kexec_load finit_module init_module
seccomp.deny setns unshare clone3
seccomp.deny process_vm_readv process_vm_writev keyctl open_by_handle_at quotactl

# Normal applications should drop all capabilities
caps.drop-all
caps.keep cap_chown cap_net_bind_service cap_net_raw
caps.drop cap_sys_admin cap_net_admin cap_net_raw

# Set network interface up
ifup lo
```
