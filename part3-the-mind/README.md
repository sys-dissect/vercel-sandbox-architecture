# Part 3 — The Mind

The control plane: how the host talks to the sandbox, how requests are authenticated, and how egress traffic is intercepted. The API shape here is Tier 2 — it is reconstructed from the supervisor binary's strings, not from a captured request or a FileDescriptorProto. The strings themselves are Tier 1.

## The SpawnService

The supervisor's control plane is ConnectRPC over HTTP/2 cleartext (h2c) with protobuf. The binary links `connectrpc.com/connect` and `golang.org/x/net/http2/h2c`, and its strings show `*connect.Handler`, `*h2c.h2cHandler`, `*protowire.Type`, `RegisterMessage`, `RegisterEnum`, and `RegisterFile`. The protobuf package is `vercel.sandbox.spawn.v1` and the service is `SpawnService` (`spawnv1connect.SpawnServiceHandler`).

The six methods, from the function signatures and message types in the binary:

| Method | Type | Request → Response |
|---|---|---|
| Spawn | server-streaming | SpawnRequest → stream of SpawnEvent (SpawnStarted, ExitStatus) |
| Stdin | unary | StdinRequest → StdinResponse (bytes_written) |
| Kill | unary | KillRequest → KillResponse |
| Ping | unary | PingRequest → PingResponse |
| Pty | bidi-streaming | PtyInput ↔ PtyOutput (PtyStart, PtyStarted, PtyResize) |
| EnableSignedGit | unary | EnableSignedGitRequest → EnableSignedGitResponse |

The Connect paths follow the `/<package>.<Service>/<Method>` convention:

- `/vercel.sandbox.spawn.v1.SpawnService/Spawn`
- `/vercel.sandbox.spawn.v1.SpawnService/Stdin`
- `/vercel.sandbox.spawn.v1.SpawnService/Kill`
- `/vercel.sandbox.spawn.v1.SpawnService/Ping`
- `/vercel.sandbox.spawn.v1.SpawnService/Pty`
- `/vercel.sandbox.spawn.v1.SpawnService/EnableSignedGit`

The Pty method name is inferred from `PtyInput`/`PtyOutput` — the exact RPC name is not directly in the extracted strings — so it is Tier 2. `EnableSignedGit` enables git commit signing inside the sandbox. A reconstruction of the service is in [schemas/spawn.proto](schemas/spawn.proto). Its header states what is observed and what is not: message and method names are observed, field numbers are not verified except `StdinResponse.bytes_written = 1`, and the Pty method name is inferred.

This explains the 404s on `init.sock`. The REST paths that were tried (`/`, `/health`, `/version`, `/status`, `/v1/status`) do not exist because the API is ConnectRPC, not REST. The actual endpoints are the six service paths above.

## Authentication is Ed25519 (Tier 2)

The binary has an internal `auth` package (`internal/sandboxinit/auth`). PID 1 is started with a `--pubkey` argument carrying a per-sandbox Ed25519 public key (redacted in this repo). The strings include an Ed25519ph (prehashed Ed25519) error message. The strong inference is that the host signs control-plane requests with an Ed25519 key and `sandbox-init` verifies them with the `--pubkey`. That is why PID 1 takes a public key on its command line. No signed request was captured, so this is Tier 2, not Tier 1. The `--pubkey` value is not reproduced in this repo.

## The egress proxy and its 24-hour CA

Outbound HTTPS goes through a TLS-intercepting proxy. The proxy's CA certificate, `/run/cell/ca-cert.pem`, is bind-mounted read-only onto `/etc/pki/ca-trust/source/anchors/vercel-proxy-ca.pem` and `/usr/local/share/ca-certificates/vercel-proxy-ca.crt`, so it is in the system trust store. The supervisor's environment then points every tool's CA bundle at that store — AWS, cargo, curl, git, gRPC, node, npm, pip, requests, OpenSSL. This is comprehensive and deliberate: every tool is configured to trust Vercel's proxy CA. The same pattern exists on the Meta Muse VM, but here it is explicit and CA-based rather than proxy-variable-based.

The CA itself, parsed with `openssl x509`:

- Subject and issuer are both `O=Vercel, CN=Vercel Network Proxy CA` — self-signed.
- Signature algorithm `ecdsa-with-SHA256`. Public key ECDSA P-256 (`prime256v1`), 256-bit.
- Serial `b8:6e:81:56:fe:69:4d:81:35:5f:25:46:2c:d3:5f:26`.
- Validity: Not Before Nov 23 14:12:45 2026 GMT, Not After Nov 24 14:32:45 2026 GMT — about 24 hours and 20 minutes. It is generated at sandbox boot and expires about a day later. It is a per-sandbox, ephemeral CA, which limits the blast radius if it is compromised.
- Key Usage (critical): Certificate Sign, CRL Sign.
- Basic Constraints (critical): CA:TRUE, pathlen 0. It can only sign end-entity certificates, not other CAs. Properly constrained.
- Subject Key Identifier `43:1D:58:93:02:8E:D6:E1:F3:9A:AA:92:34:4A:6C:49:4C:47:BB:78`.
- No SANs, no Authority Key Identifier. No private key was in the evidence — only the public certificate. The private key stays on the host.

The full PEM is not in this repo, and the public-key bytes and signature value are redacted in the scrubbed `evidence/bundle-3/01-ca-cert.json`. The certificate SHA-256 is `5b4921848f9b0c5c1928ea7906afb0bc0f59f092ade6ff774744053d9760a19a`.

## The egress port policy

Egress is permissive for TCP, with specific blocks. The probe tested twelve ports with a ~1.5 s timeout.

Allowed, with 1–3 ms latency (FTP 32 ms):

- 21 FTP (`ftp.gnu.org`)
- 22 SSH (`github.com`)
- 53 DNS over TCP (`1.1.1.1`)
- 80 HTTP (`example.com`)
- 389 LDAP (`ldap.google.com`)
- 443 HTTPS (`cloudflare.com`)
- 465 SMTPS (`smtp.gmail.com`)
- 587 Submission (`smtp.gmail.com`)
- 8080 HTTP-Alt (`1.1.1.1`)

Blocked, all timing out at ~1502 ms with errno 11 (EAGAIN):

- 25 SMTP (`smtp.gmail.com`) — the standard anti-spam block.
- 445 SMB (`microsoft.com`) — a lateral-movement vector.
- 123 NTP over UDP (`pool.ntp.org`) — UDP NTP is blocked; the guest uses kvm-clock, which is host-synced, so NTP is not needed.

The pattern is the standard cloud posture: block port 25 to prevent spam, allow the submission ports 465 and 587; block SMB; block UDP NTP. The MITM proxy handles the TCP traffic, including port 22 — the proxy passes it through or the SSH goes via the proxy's CONNECT. The sandbox is not air-gapped. That is the sharpest contrast with the Google sandboxes in this series, where there is no default route at all.

## The metadata endpoint is unreachable

`curl http://169.254.169.254/` times out (000 after 3.0 s). There is no cloud metadata endpoint reachable from the guest. That is the observed fact. Any claim about a host firewall dropping ARP or IP traffic to that address, or about EC2 IAM credentials, is not in the evidence bundles and is not repeated here as fact.

## Open items in the control plane

- The Connect service paths above are derived from the package and service names; no live request to any of them was captured. Calling them confirms the API.
- The Pty method name is inferred, not observed.
- The Ed25519 signing is inferred, not observed from a signed request.
- No control-plane traffic was captured on the wire. Strace ran while PID 1 was idle; running it while a command executes would show the RPCs.
- The `.proto` is a reconstruction from strings. Field numbers are not verified except `StdinResponse.bytes_written = 1`.
