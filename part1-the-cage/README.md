# Part 1 — The Cage

The VM itself: what the sandbox runs on, what it is allowed to do, and what confines it. Everything in this part is Tier 1 unless marked otherwise — it comes from procfs, sysfs, dmesg, and direct measurement inside the guest.

## The hypervisor is Firecracker on KVM

The guest kernel reports "Hypervisor detected: KVM" and "Booting paravirtualized kernel on KVM". It uses kvm-clock, PV spinlocks, PV remote TLB flush, and PV sched yield. The ACPI tables carry the Firecracker signature: OEM ID `FIRECK`, table IDs `FCVMFADT`, `FCVMDSDT`, `FCVMMADT`, compiler `FCAT 20240119`. The I/O memory map adds an Amazon marker: an ACPI device `AMZNC10C:00` at 0x000de000. That is the first direct guest-visible marker supporting AWS as the host platform (Tier 2 — the AMZN ID could be Firecracker's emulation rather than the physical host, but it is a concrete Amazon marker in the guest's ACPI namespace). The kernel command line has `pci=off` and six `virtio_mmio.device` entries; dmesg adds "PCI: Fatal: No config space access function found" and "DMI not present or invalid". There is no PCI bus and no DMI. This is the same Firecracker ACPI signature as the Google Jules microVM.

The six virtio-mmio devices (slots 5–10, at 0xc0001000–0xc0006000) are, by type ID: memory balloon (0x0005), block (0x0002), block (0x0002), network (0x0001), vsock (0x0013), entropy/rng (0x0004). Two block devices, one network device, one vsock device, one balloon, one rng. There is no virtio-console device. The interrupt counts show the block and network devices doing the most work, and vsock with 3,452 interrupts — active, not idle.

## The kernel

Linux 6.18.56, `#1 SMP Fri Nov 20 05:34:02 UTC 2026`, built by `root@buildkitsandbox` with gcc (Debian 12.2.0-14+deb12u1). The build is three days old at probe time. The command line is:

`reboot=k panic=1 nomodule ip=169.254.0.2::169.254.0.1:255.255.255.255:::off:169.254.0.1:: psi=1 ro i8042.nomux init=/opt/vercel/celld-init.sh i8042.noaux i8042.dumbkbd quiet root_container_telemetry_sockets=apm build_version=2026.11.20-18b806b9453c0071fa35c268e0c4ea72daf7a06b console=ttyS0 i8042.nopnp remove_blocked_ca_roots=1 pci=off virtio_mmio.device=4K@0xc0001000:5 root=/dev/vda rw virtio_mmio.device=4K@0xc0002000:6 virtio_mmio.device=4K@0xc0003000:7 virtio_mmio.device=4K@0xc0004000:8 virtio_mmio.device=4K@0xc0005000:9 virtio_mmio.device=4K@0xc0006000:10`

Three of those parameters are Vercel-specific and unknown to the kernel (`root_container_telemetry_sockets=apm`, `build_version=...`, `remove_blocked_ca_roots=1`); the kernel passes them to userspace. The init is `/opt/vercel/celld-init.sh`. `nomodule` means no kernel modules can be loaded, and `/proc/sys/kernel/modules_disabled` reads 1. The guest IP is 169.254.0.2 with gateway 169.254.0.1. The console is ttyS0.

One discrepancy to record: the command line says `root=/dev/vda`, but the actual root filesystem is `/dev/vdb`. The init evidently pivots or overrides it. Do not claim the root disk is vda.

The distribution is Ubuntu 26.04.1 LTS (Resolute Raccoon). The sandbox was 14 minutes old when the first probe ran.

## The kernel configuration

The full kernel config is in `evidence/bundle-4/kernel-config.gz` (Linux 6.18.56, 3,906 lines, 1,531 options enabled, 1,474 not set). It is a lean, purpose-built guest kernel, and it explains several observations from first principles.

There is no LSM at all. Only `CONFIG_SECURITYFS=y` is set. There is no Yama, AppArmor, SELinux, Landlock, Tomoyo, or Smack compiled in, and no `CONFIG_LSM=` line. That is why `/proc/self/attr/current` does not exist, `/sys/kernel/security` is empty, and there is no yama sysctl.

KASLR is off (`# CONFIG_RANDOMIZE_BASE is not set`), so the kernel base address is fixed at 0xffffffff81000000 — confirmed by `/proc/kallsyms` showing `_stext` at exactly that address. Lockdown is off (`# CONFIG_SECURITY_LOCKDOWN_LSM is not set`). There is no heap zeroing on alloc or free (`INIT_ON_ALLOC_DEFAULT_ON` and `INIT_ON_FREE_DEFAULT_ON` are not set), no slab freelist randomization, no static usermode helper, and no stackleak plugin.

Seccomp is on (`CONFIG_SECCOMP=y`, `CONFIG_SECCOMP_FILTER=y`). eBPF is on (`CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_BPF_JIT_ALWAYS_ON=y`) with unprivileged BPF off by default (`CONFIG_BPF_UNPRIV_DEFAULT_OFF=y`) — only root can use eBPF, which matches `BPF_MAP_CREATE` succeeding as root. `CONFIG_KPROBES=y`. But ftrace is not compiled in (`# CONFIG_FTRACE is not set`), so there is no function tracer and no ftrace tracefs — that is why mounting tracefs fails.

Modules are compiled in (`CONFIG_MODULES=y`, `CONFIG_MODULE_SIG=y`, `CONFIG_MODULE_SIG_ALL=y`) but disabled at runtime by the `nomodule` boot argument and `modules_disabled=1`. All namespaces are enabled (user, pid, net, ipc, uts, time, cgroup). io_uring is on (`CONFIG_IO_URING=y`) — a real kernel, unlike gVisor, which disables it. Vsock is fully enabled (`CONFIG_VSOCKETS=y`, `CONFIG_VSOCKETS_DIAG=y`, `CONFIG_VSOCKETS_LOOPBACK=y`, `CONFIG_VIRTIO_VSOCKETS=y`). `CONFIG_VIRTIO_CONSOLE=y` is compiled in, but no virtio-console device is attached — the guest console is serial ttyS0, and the driver is unused. `CONFIG_VIRTIO_PCI=y` is likewise compiled in but unused (`pci=off`). There is no KVM host support in the guest kernel; it is a guest-only build.

Hardening is mixed. Stack protector (strong) and kernel stack offset randomization are on, the slab freelist is hardened, and `/dev/mem` is restricted (`CONFIG_STRICT_DEVMEM=y`, though `/proc/kcore` is masked by a bind-mount). But KASLR, lockdown, and heap/stack zeroing are all off. Netfilter is fully enabled (`CONFIG_NETFILTER=y`, `CONFIG_NF_TABLES=y`, `CONFIG_IP_NF_IPTABLES=y`, `CONFIG_IP6_NF_IPTABLES=y`), yet the guest image has no `iptables` or `nft` command-line tools — `iptables-save` and `nft` both report \"command not found\". The firewall rules cannot be inspected or modified from inside the guest; that is a tooling gap, not evidence of \"no firewall\". The egress blocks (port 25, 445, UDP 123) are enforced host-side or by the proxy.

## The CPU is the real host CPU

The guest sees an Intel Xeon, Family 6, Model 106, Stepping 6, at 2.90 GHz, 2 vCPUs, 54 MiB L3 cache, with full AVX-512 (F, DQ, CD, BW, VL, VBMI, VBMI2, VNNI, BITALG, VPOPCNTDQ) plus VAES and VPCLMULQDQ. Family 6 Model 106 is Ice Lake-SP. The hypervisor vendor is KVM, the CPUID level is 27, microcode is 0x1, and the `hypervisor` and `cpuid_fault` flags are set. The CPUID is not synthetic or masked — this is the host CPU passed through, unlike the NotebookLM sandbox, which presented a synthetic Haswell profile with a blank brand string and a zeroed hypervisor leaf.

`systemd-detect-virt` prints "docker". That is a mis-detection. The sandbox is a Firecracker microVM, not a Docker container.

Syscall latency confirms a real hardware VM rather than syscall emulation. `getpid` averages 154.1 ns over 20,000 iterations; `clock_gettime_ns` (vDSO) averages 109.6 ns. That is roughly twice bare metal, consistent with a KVM VM exit and entry, and an order of magnitude faster than the NotebookLM gVisor sandbox, where `getpid` took about 1,162 ns.

The speculative-execution mitigations (from `lscpu`) are: Spectre v2 mitigated with Enhanced/Automatic IBRS, conditional IBPB, and a PBRSB-eIBRS software sequence, but BHI is listed as Vulnerable; MMIO stale data mitigated by clearing CPU buffers, with SMT host state unknown; Speculative Store Bypass disabled via prctl; TSX disabled. The rest are listed as Not affected or mitigated. These are the host kernel's mitigations as reported to the guest.

## Memory and cgroup limits

MemTotal is 4,386,888 kB, about 4.18 GiB. MemFree was 3,978,104 kB and MemAvailable 4,057,476 kB at probe time. There is no swap. The cgroup memory.max is 4,294,967,296 bytes (exactly 4 GiB), memory.current was about 238 MiB, cpu.max is "max 100000" (no CPU quota), pids.max is "max" (no PID cap), and memory.swap.max is "max". The cgroup CPU statistics show no throttling at all (nr_throttled 0, throttled_usec 0). The cgroup path is `0::/` — the root of the cgroup v2 hierarchy. CommitLimit is 2,193,444 kB. The virtio balloon device is present but not inflated (Balloon 0 kB).

The resource limits are real, not fingerprints. RLIMIT_NPROC is 17,113 and open files 1,048,576. There is no memory pressure: the cgroup memory events are all zero (low 0, high 0, max 0, oom 0, oom_kill 0, oom_group_kill 0). Entropy is full at 256 bits, and a hardware RNG device (virtio-rng) is present.

## Namespaces

The probe process and PID 1 share identical namespace inodes for all eight namespaces. The network (4026531833), time (4026531834), and user (4026531837) namespaces are the initial-namespace inodes — the sandbox shares the host VM's initial net, user, and time namespaces. The mount (4026532112), uts (4026532113), ipc (4026532114), pid (4026532115), and cgroup (4026532116) namespaces are dedicated, in a consecutive block. This is the same pattern as the Gemini Spark Config B container: dedicated mount/uts/ipc/pid/cgroup, shared initial net/user/time. `nsenter -t 1 -m -p hostname` succeeds as root and returns the hostname. Entering PID 1's namespaces is unrestricted.

## The disks

There are two virtio-blk disks, both XFS. `/dev/vdb` is 64G and is `/` (3.6G used). `/dev/vda` is 33G and is mounted at `/run/vercel/share` (384M used), from the host path `/volumes/run/vercel/share` per mountinfo — a host-provided shared volume. `/dev/shm` is a 64M tmpfs. The disk reports `rotational=1`, a virtio-blk artifact, and TRIM/discard is not supported (`fstrim` returns "the discard operation is not supported"; discard_max_bytes is 0). Read-ahead is 128K.

Filesystem performance is local-disk fast. Writing 1 MB in 4K chunks with fsync takes 3.2 ms; reading it back takes 0.3 ms; `stat` averages 959 ns. For comparison, the NotebookLM sandbox's 9P `stat` took 41.79 us — the Vercel local XFS stat is about 44x faster. The sequential write figure in the defensive bundle (2651 MB/s over 12 ms) and the 4K write rate (529K ops/sec over 2 ms) are burst measurements over milliseconds, not sustained rates; they show only that no obvious rate limit was hit in those bursts.

## The network

`eth0` is 169.254.0.2/16, MAC 06:00:a9:fe:00:02 — the MAC encodes the link-local address (a9:fe is 169.254). The default route is via 169.254.0.1, and DNS is 169.254.0.1. IPv6 is link-local only (fe80::/64); there is no IPv6 default route and IPv6 egress fails with "Network is unreachable", even though DNS returns AAAA records. Egress is IPv4-only in practice.

## Root, and what confines it

The operator is real root: uid 0, gid 0, CapInh/CapPrm/CapEff/CapBnd all 000001ffffffffff (all 41 capabilities), NoNewPrivs 0. The uid_map and gid_map are identity (0 0 4294967295) — there is no user namespace. This is not a restricted root and not uid 1000.

What confines root is thin: a seccomp filter (Seccomp 2, one filter) whose contents cannot be read (querying it returns EACCES), and the mount namespace. There is no LSM — `/proc/self/attr/current` does not exist and `/sys/kernel/security` is empty. There is no Yama — `/proc/sys/kernel/yama/ptrace_scope` does not exist, so ptrace is governed by CAP_SYS_PTRACE, which root holds. `kptr_restrict` is 1, but root still sees real addresses in `/proc/kallsyms` (ffffffff81000000 T _stext), which is the expected behaviour for CAP_SYSLOG under kptr_restrict=1.

Two hardening measures are visible even to root. `/proc/kcore` and `/proc/keys` are bind-mounted read-only from `/null`, so root cannot read kernel memory or the kernel keyring through them. And `nomodule` plus `modules_disabled=1` means root cannot load a kernel module.

There is no systemd running, no sshd running (though `/run/sshd` exists), and no docker.sock. The process tree is minimal: PID 1 (`sandbox-init`), the operator's `tailcat` (PID 923, the operator's own tool, not Vercel's), and the probe itself. The base image has no `strace`, `tcpdump`, `gdb`, or `binutils`; the probe installed them with `apt-get`.

## Open items in the cage

- The `.rock` directory at `/` (dated Nov 23 08:55) was not investigated.
- The host identity (cloud provider, region, instance type) is not observable from inside and is not established by the evidence. See the main README limitations.
- The seccomp policy (which syscalls are allowed or blocked) is unknown; the filter cannot be read.
