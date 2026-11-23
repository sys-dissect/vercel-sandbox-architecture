# Vercel Sandbox Architecture

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)

An empirical dissection of the Vercel Sandbox execution environment, measured from inside a live sandbox on 2026-11-23. The sandbox is a Firecracker microVM running a Go supervisor (`sandbox-init`) that exposes a ConnectRPC control plane, with full network egress through a TLS-intercepting proxy. Everything here was observed from inside the guest as root, in a single 45-minute Hobby-plan session, and graded by how it was obtained.

This is the third in the sys-dissect sandbox series, after the Gemini Spark and Gemini Notebook (NotebookLM) audits. The shape is closest to Jules: a real Firecracker microVM with root and network, not a gVisor syscall emulator and not an air-gapped cell. What is different here is the supervisor — a single Go binary, `sandbox-init`, that is PID 1, the HTTP proxy, and the ConnectRPC control plane all at once — and the fact that the operator is root, with all 41 capabilities, in the initial user namespace.

## Limitations, up front

Read these before citing anything in this repo.

- The ptrace ATTACH/SEIZE test against PID 1 was never run. The probe script had a bug (a 3-tuple unpack of a 2-tuple `waitpid` return) and crashed before the test. Whether root can ptrace PID 1 is unknown. Strace did attach successfully, which is suggestive, but it is not the same test.
- The TCP 23456 listener is attributed to `sandbox-init` by elimination (it is the only Vercel process and holds the sockets). `ss` never showed the owning process by name. That attribution is Tier 2.
- `cell.sock` and `apm.sock` were listening at 14:27 UTC and gone at 14:32 UTC. They are transient. Do not present them as persistent listeners, and their owning processes were never identified.
- The disk rate numbers (529K 4K ops/sec, 2651 MB/s sequential) are burst measurements over 2 ms and 12 ms. They are not sustained rates and should not be cited as throughput.
- The host identity claims that circulated during the audit — AWS, us-east-1, a specific EC2 reverse-DNS name, an m6i/c6i.metal instance type — are unverified. They do not appear in the evidence bundles. What the guest can see is a KVM host with an Ice Lake-SP CPU, plus one Amazon marker: an ACPI device `AMZNC10C:00` in the I/O memory map (evidence/bundle-4/iomem.txt). That supports AWS as the host platform (Tier 2 — the AMZN ID could be Firecracker's emulation), but the region and instance type remain unverified and are not observable from inside.
- The virtio device list is balloon, block, block, network, vsock, rng. There is no virtio-console device. An earlier draft of the host profile listed "console" — that was wrong.
- `systemd-detect-virt` prints "docker". That is a mis-detection. The sandbox is a Firecracker microVM, not Docker.
- The `tailcat` process (PID 923) is the operator's own tool, run inside the sandbox to reach it over his tailnet. Its traffic is excluded from the Vercel findings.
- The SpawnService `.proto` in `part3-the-mind/schemas/` is reconstructed from binary strings, not from a FileDescriptorProto. Message and method names are observed; field numbers are not verified except `StdinResponse.bytes_written = 1`. The Pty method name is inferred from `PtyInput`/`PtyOutput`.
- The sandbox was a Hobby-plan instance with a 45-minute lifetime. The probes are a one-shot capture, not a longitudinal study. The proxy CA in the evidence expired about 24 hours after the sandbox booted.

## Key Findings at a Glance

| Finding | Value | Grade |
|---|---|---|
| Hypervisor | Firecracker on KVM (ACPI `FIRECK` / `FCAT 20240119`, `pci=off`) | Tier 1 |
| Kernel | Linux 6.18.56, built 2026-11-20 by `root@buildkitsandbox` | Tier 1 |
| CPU | Intel Xeon Family 6 Model 106 (Ice Lake-SP) @ 2.90 GHz, 2 vCPU, 54 MiB L3, AVX-512 | Tier 1 |
| Memory | 4,386,888 kB (~4.18 GiB); cgroup memory.max 4 GiB; no swap; no CPU quota | Tier 1 |
| Operator privilege | Real root, uid 0, all 41 capabilities, identity uid_map, no user namespace | Tier 1 |
| LSM / Yama | None. No AppArmor/SELinux, no Yama sysctl. Seccomp filter present, contents unreadable | Tier 1 |
| Syscall latency | getpid 154.1 ns avg (20k iters) — ~2x bare metal, not gVisor-style emulation | Tier 1 |
| Filesystem | Local XFS on /dev/vdb (64G); stat 959 ns; write+fsync 1 MB in 3.2 ms | Tier 1 |
| PID 1 | `sandbox-init`, Go 1.26.10, statically linked, stripped, FIPS 140-3 mode; uid 1000 with all 41 caps | Tier 1 |
| Control plane | ConnectRPC over h2c + protobuf, service `vercel.sandbox.spawn.v1.SpawnService`, 6 methods | Tier 2 (API shape from strings) |
| Control auth | Ed25519 signature verification via `--pubkey` | Tier 2 |
| Host control channel | TCP `*:23456`, host 169.254.0.1 connects in | Tier 2 (owner by elimination) |
| Egress | Full NAT via 169.254.0.1; example.com 200 in 33 ms; direct-IP HTTPS works | Tier 1 |
| Egress proxy | TLS MITM; per-sandbox ECDSA P-256 CA, valid ~24h, CA:TRUE pathlen 0 | Tier 1 |
| Egress policy | TCP mostly open; blocked: 25 (SMTP), 445 (SMB), UDP 123 (NTP) | Tier 1 |
| Metadata endpoint | 169.254.169.254 unreachable (timeout) | Tier 1 |
| vsock | /dev/vsock exists (virtio-vsock, active); guest→host connect EACCES on all 21 ports scanned | Tier 1 |
| Telemetry | StatsD metrics to 127.0.0.1:8125 with no listener (dropped); APM socket present | Tier 1 |
| Namespaces | Dedicated mnt/uts/ipc/pid/cgroup; shared initial net/user/time | Tier 1 |
| eBPF | BPF_MAP_CREATE works as root; mounting tracefs is EPERM; modules disabled | Tier 1 |

## Contents

- [Part 1 — The Cage](part1-the-cage/README.md): the VM. Firecracker/KVM, the kernel, the CPU, memory and cgroup limits, namespaces, the two XFS disks, the network, root privilege, and the absence of LSM/Yama.
- [Part 2 — The Machinery](part2-the-machinery/README.md): the supervisor. `sandbox-init` as PID 1, its sockets, the 23456 control channel, the transient cell/apm sockets, vsock, seccomp, eBPF, the dead StatsD listener, and the virtio device map.
- [Part 3 — The Mind](part3-the-mind/README.md): the control plane. The SpawnService ConnectRPC API, Ed25519 auth, the MITM proxy and its 24-hour CA, the egress port policy, and the unreachable metadata endpoint.
- [part3-the-mind/schemas/spawn.proto](part3-the-mind/schemas/spawn.proto): a reconstruction of the SpawnService from binary strings.
- [evidence/bundle-1/](evidence/bundle-1/): the first probe bundle (29 files, 2026-11-23 14:27 UTC). The root-tailored one-shot probe.
- [evidence/bundle-2/](evidence/bundle-2/): the follow-up bundle (7 JSON, 14:32 UTC). Agent sockets, hypervisor topology, vsock, seccomp, kernel tracing, gateway, CPU/storage.
- [evidence/bundle-3/](evidence/bundle-3/): the defensive bundle (5 JSON). The CA certificate, egress ports, speculative mitigations, disk rates, memory/RNG. The binary and the cert PEM are not in the repo.
- [evidence/bundle-4/](evidence/bundle-4/): the expert bundle (8 files). The kernel config (`kernel-config.gz`, Linux 6.18.56), I/O memory map, PID 1 memory maps and smaps rollup, zoneinfo, and the iptables/nftables tooling check.

## Methodology

The operator ran a probe script inside the sandbox as root (via `sudo` from the `ubuntu` user) and copied the output out before the 45-minute Hobby timeout. The probe collected procfs, sysfs, cgroup, network, and filesystem state, measured syscall and filesystem latency, straced PID 1, sniffed the loopback and eth0 interfaces with tcpdump, and read the supervisor's `/proc/1` entries. Two follow-up rounds added structured JSON probes (socket probing, vsock scans, gateway scans, eBPF and seccomp checks) and a static analysis of the extracted `sandbox-init` binary and proxy CA certificate (read with `file`, `readelf`, `strings`, and `openssl x509`; the binary was never executed).

Claims are graded the same way as the earlier sandbox audits:

- **Tier 1 — observed.** A value read directly from a file, a command's output, or a measured result in the evidence bundles. The kernel version, the CPU model, the socket list, the 404 responses on `init.sock`, the EACCES on vsock connects, the CA validity dates.
- **Tier 2 — inferred.** A conclusion drawn from observed facts that the evidence does not directly prove. The 23456 listener belonging to `sandbox-init`, the control plane being ConnectRPC (from the binary's `connect`/`h2c`/`protowire` symbols), Ed25519 request signing (from the `auth` package, the `--pubkey` argument, and the Ed25519ph string), the vsock channel being host-initiated only, the Pty method name.

Where a claim is Tier 2, the text says so. Where a test failed or was not run, the text says that too.

## Reproducing the Measurements

The sandbox is a Hobby-plan instance with a 45-minute lifetime, so a reproduction needs a fresh sandbox and the probe run immediately.

1. Create a sandbox (`sandbox create --name probe --timeout 1h --non-persistent`, or the SDK equivalent). The default image is `vercel/sandbox/universal` (Ubuntu, Node 24, Python 3.14).
2. You are root inside the sandbox. Copy the probe script in and run it as root. The probe writes to `~/vercel-evidence/`.
3. Copy the evidence out before the timeout (`sandbox cp -r <name>:<path> ./vercel-evidence`). The sandbox is non-persistent; stopping it wipes the evidence.
4. The base image has no `strace`, `tcpdump`, `gdb`, or `binutils`. Install them with `apt-get` if you want the supervisor probes.
5. For the binary and cert analysis, copy `/run/vercel/share/sandbox-init` and `/run/cell/ca-cert.pem` out and analyze them offline with `file`, `readelf`, `strings`, and `openssl x509`. Do not execute the binary.

The probe scripts that produced `evidence/bundle-1/` are not in this repo; the evidence files are the record. The follow-up probes that produced bundles 2 and 3 were structured JSON collectors run by the operator's agent.

## Scrubbing

The evidence in this repo is scrubbed. The per-sandbox Ed25519 `--pubkey` value is replaced with `[REDACTED]` wherever it appeared. The Go BuildID string is replaced with `[REDACTED]`. One external peer IP in the tcpdump capture is replaced with `[REDACTED]`. In `evidence/bundle-3/01-ca-cert.json`, the certificate's public-key hex block and signature value are replaced with `[REDACTED]`; the subject, issuer, validity, serial, key usage, basic constraints, and subject key identifier are kept. The `sandbox-init` binary (11 MB) and the full cert PEM are not in the repo. The hostname `331a024e-31b` is kept; it is an ephemeral per-sandbox ID, not a credential.

## License

MIT. See [LICENSE](LICENSE).
