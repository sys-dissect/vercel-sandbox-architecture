# Part 2 — The Machinery

The supervisor: what runs the sandbox, what it listens on, and what it can and cannot do. PID 1 is not an init system. It is a single Go binary that is the init, the control plane, and the HTTP proxy at the same time.

## sandbox-init

PID 1 is `/run/vercel/share/sandbox-init`, started as:

`/run/vercel/share/sandbox-init --socket=/run/vercel/share/init.sock --pubkey=[REDACTED]`

The `--pubkey` value is redacted in this repo; it is a per-sandbox Ed25519 public key. It runs as uid 1000 (`ubuntu`) with all 41 capabilities, including Ambient. It has 7 threads, VmRSS 15 MB, and a seccomp filter. Its signal masks are set (SigBlk `fffffffc3bba3a00`, SigCgt `fffffffd7fc1feff`) — it is a proper init that handles signals and reaps children. Its working directory is `/vercel` and its root is `/`.

The binary lives on the shared volume `/run/vercel/share` (`/dev/vda`), not on the root disk. It is 11,333,794 bytes, SHA-256 `6be389bd35310e80cfb70cd9513d5c773d4f4eb41c54d951de60bf83a3b7f375`. It is an ELF64 EXEC, entry point 0x490b20, statically linked, stripped — no symbol table. Go runtime metadata survives (gopclntab, typelink, `.go.buildinfo`, `.go.module`). It was built with Go 1.26.10. It has a `.go.fipsinfo` section and enforces FIPS 140-only constraints in its strings (RSA keys of at least 2048 bits, HKDF/HMAC keys of at least 112 bits, SHA-2/SHA-3 only, AES-only CBC/CTR) — it was built in Go's FIPS 140-3 mode. The binary is not in this repo.

The module is `github.com/vercel/api/hive-containers/sandbox-controller`. The main package is `cmd/sandbox-init` (`main.go`, `listener.go`). The generated protobuf code is in `gen/spawn`. The internal packages are `internal/sandboxinit/auth`, `internal/sandboxinit/fsinfo`, and `internal/sandboxinit/service`. The "hive-containers" name is Vercel's internal platform name for the sandbox/container system.

Its environment sets CA bundle paths for every tool — AWS, cargo, curl, git, gRPC, node, npm, pip, requests, OpenSSL — all to `/etc/ssl/certs/ca-certificates.crt`. There are no secrets in its environment. Its PATH starts with `/vercel/.local/bin` and `/vercel/.global/pnpm/bin`.

## Sockets

At 14:27 UTC the listening Unix sockets were:

- `/run/vercel/share/init.sock` (inode 1112) — owned by `sandbox-init`, PID 1 FD 4. This is the `--socket` argument. It is a Go HTTP server.
- `/run/cell/cell.sock` (inode 568) — the "cell" daemon.
- `/run/apm/apm.sock` (inode 564) — APM telemetry.

At 14:32 UTC, `cell.sock` and `apm.sock` no longer existed. They are transient — created on demand and removed when idle, or closed when their owners exit. Their owning processes were never identified; `ss` showed no process for either at 14:27. Do not present them as persistent listeners.

There is one TCP listener: `*:23456`. An established connection shows the host connecting in: `[::ffff:169.254.0.2]:23456` from `[::ffff:169.254.0.1]:41738`. The host (169.254.0.1) initiates a connection into the sandbox on port 23456. `ss` never showed the owning process by name, so attributing the 23456 listener to `sandbox-init` is Tier 2, by elimination — it is the only Vercel process, and it holds the sockets.

PID 1's file descriptors tell the same story. FD 0/1/2 are pipes. FD 3 is `/sys/fs/cgroup/cpu.max` — the supervisor reads the CPU cgroup limit. FD 4 is the `init.sock` socket. FD 5 is an eventpoll watching FDs 4, 6, 7, 10, and 8. FD 6 is an eventfd. FD 7 is a socket, and FD 8 and 10 are pipes. FD 15 is a pidfd for PID 1872 — PID 1 tracks a child process through it. Between 14:27 and 14:32, FD 7, 8, and 10 were all re-created with new inodes (FD 7 went from socket:[2736] to socket:[5094]). FD 7 is a live, accepted connection socket, not a static listener — it gets replaced, which fits it being the host's 23456 control connection being re-established. FD 4 (init.sock) did not change.

## init.sock is a Go HTTP server, not REST

Probing `init.sock` with HTTP GET to `/`, `/health`, `/version`, `/status`, and `/v1/status` all returns HTTP/1.1 404 Not Found, Content-Type text/plain, `X-Content-Type-Options: nosniff`, Content-Length 19 — Go's default "404 page not found" body. The socket is an HTTP server, but none of those paths exist. The API is not REST. It is ConnectRPC, and the paths are covered in Part 3.

## strace on PID 1 works

As root with CAP_SYS_PTRACE, `strace -f -p 1` attached to all 7 threads. In 8 seconds PID 1 made exactly 3 syscalls: one `tgkill` sending SIGURG (the Go runtime's preemption signal). The supervisor is idle and epoll-driven when nothing is happening. The strace exit code 124 is just the `timeout` killing it after 8 seconds, which is expected.

That proves attach works and that the supervisor is event-driven, but it captured no control-plane traffic — PID 1 was idle. To see the control traffic, strace has to run while a command is executing. That was not done.

The explicit ptrace test (PTRACE_ATTACH and PTRACE_SEIZE on PID 1) was never run. The probe script crashed on a bug — a 3-tuple unpack of the 2-tuple `waitpid` return — before the test. Whether root can ptrace PID 1 is unknown. Do not claim it either way.

## vsock

`/dev/vsock` exists as a character device (10:259), mode 600, root only. It is a real virtio-vsock device (type 0x0013) with 3,452 interrupts — it is active, in use by the platform. An earlier line in the first bundle said "no vsock/virtio devs"; that was a false negative from the probe script (`ls` exited non-zero because `/dev/vport*` and `/dev/virtio*` do not exist, which tripped the fallback echo). The device does exist.

The guest cannot use it to reach the host. Getting the guest's own CID fails with ENOTTY ("Inappropriate ioctl for device"). Connecting to host CID 2 on all 21 ports scanned (22, 52, 80, 443, 1024, 1025, 2049, 2345, 23456, 5000, 5005, 5201, 8000, 8080, 9999, 10000, 10701, 10702, 10703, 30000, 50000) returns EACCES, permission denied, every time. EACCES is not ECONNREFUSED and not a timeout — the connect is blocked by a permission or policy before it reaches the host. So the guest cannot initiate vsock connections to the host, even as root, on any port. The channel is host-initiated only, or guest-initiated vsock is deliberately blocked (Tier 2). Do not conclude from this that the host listens on no vsock port — the probe was blocked before reaching the host.

## Seccomp and eBPF

PID 1 is under a seccomp filter (Seccomp 2, one filter), but the filter cannot be read — querying it returns EACCES. The kernel does not expose a process's seccomp BPF program to userspace. The syscall allowlist and blocklist are unknown. Do not claim any specific syscall is blocked or allowed.

`BPF_MAP_CREATE` succeeds as root (it returned a valid fd, 4), so eBPF is available to the guest. Mounting tracefs (`/sys/kernel/tracing`) fails with EPERM, so ftrace via a tracefs mount is not available. Kernel modules are disabled (`modules_disabled=1`, `nomodule` on the command line).

## Telemetry to a dead listener

The tcpdump capture shows many UDP packets from 127.0.0.1:50193 to 127.0.0.1:8125 — the StatsD/DogStatsD port — each answered by ICMP "udp port 8125 unreachable". Something in the sandbox emits StatsD metrics to localhost:8125, but nothing is listening there. The metrics are dropped. The APM socket (`/run/apm/apm.sock`) and the kernel command-line parameter `root_container_telemetry_sockets=apm` show telemetry is configured, but the StatsD collector is absent. That is the observed behaviour; where the metrics were supposed to go is not established.

## The virtio device map

Six devices, matching the six `virtio_mmio.device` slots:

| Device | Type ID | Function |
|---|---|---|
| virtio0 | 0x0005 | memory balloon |
| virtio1 | 0x0002 | block (/dev/vda or /dev/vdb) |
| virtio2 | 0x0002 | block (/dev/vda or /dev/vdb) |
| virtio3 | 0x0001 | network (eth0) |
| virtio4 | 0x0013 | vsock |
| virtio5 | 0x0004 | entropy (rng) |

There is no virtio-console device. PCI is absent. The interrupt counts (IO-APIC, edge) are: virtio2 (block) 8,928; virtio3 (network) 6,644; virtio4 (vsock) 3,452; virtio1 (block) 853; virtio0 (balloon) 39; virtio5 (rng) 31.

## The gateway is DNS-only

The gateway at 169.254.0.1 exposes only TCP port 53 (DNS). Every other port scanned — 22, 80, 443, 1024, 2345, 23456, 8080, 9090, 41738 — is closed (ECONNREFUSED). The gateway is a NAT and DNS forwarder, not a general service host. Port 41738 was the ephemeral source port of the host's connection to the sandbox's 23456; it is closed, as expected.

## The operator's own tooling

The `tailcat` process (PID 923, `tailcat serve all,no-auth-ssh`) is the operator's own tool, run inside the sandbox to reach it over his tailnet. Its traffic — a TLS connection to 199.38.181.166:443 and UDP to several peers — is his, not Vercel's, and is excluded from the Vercel findings. The `/vercel` directory also holds a `.codex` directory and a mode-600 `.npmrc` whose contents were not read. The `.sudo_as_admin_successful` marker exists. The probe ran via `sudo` from the `ubuntu` user.
