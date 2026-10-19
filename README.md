# socks5 task pump

A SOCKS5 proxy whose listener runs on the Cobalt Strike **client** and whose
target sockets live inside a **Beacon Object File**.  There is no
`CreateThread`, `CreateProcess`, fork&run, or process injection anywhere in the
chain.  Every byte moves through normal Beacon tasking.

```
   operator tool (proxychains, browser, ...)
            |
            v
   socks5_orchestrator.py          <-- SOCKS5 listener, client machine
            |  HTTPS + JWT
            v
   csrestapi / team server  ==== Beacon C2 ====> target Beacon
                                                    |
                                                    +--> target:port
```

## Setup

See [SETUP.md](SETUP.md) for the full guide. Minimal outline:

1. Start the team server with `--experimental-db` and your C2 profile.
2. Start `csrestapi` with the team server password and a dedicated REST user.
3. Build the BOF: `make`.
4. Run `socks5_orchestrator.py` on the client (see [Run](#run)).

## Why this shape

A BOF executes synchronously on Beacon's task thread and its image is unloaded
when `go()` returns, so a BOF cannot host a long-running SOCKS5 listener by
itself.  The built-in `socks` command is a native Cobalt Strike pivot.  It is
faster for interactive traffic, but it is outside this project's design: the
listener must stay on the client and every byte must move through normal Beacon
tasking.

This project keeps the same task-pump idea, but:

* the listener is on the client, so no new listener is exposed on the
  team server;
* the target sockets are created by the BOF in the Beacon process and stay
  open between BOF invocations;
* the BOF state table is heap-allocated and persisted with
  `BeaconAddValue`/`BeaconGetValue`, because the BOF image itself is freed;
* each operation is a short, bounded, non-blocking `select()`/`recv()`/`send()`
  call, so one invocation never parks the Beacon task thread for long.

The cost is latency and throughput: one BOF task per chunk, bounded by the
Beacon task check-in interval, not by REST polling.  Use a short sleep to
control task volume and large chunks for throughput; expect poor performance
for bulk transfer and interactive RDP.

## Latency: why one task is about one second

Every operation is a separate Beacon task.  Cobalt Strike delivers and returns
tasks on Beacon check-in, and a Beacon checks in about once per second even at
`sleep=0`.  `sleep=0` is not a continuous connection: it still has a check-in
floor.  The REST client can poll every 20 ms, but the task cannot run or return
until the next check-in.

Measured on the test Beacons:

| Measurement | Result |
| --- | --- |
| Beacon check-in interval at `sleep=0` | ~0.98-1.01 s |
| PING task: submit -> 404 -> COMPLETED | 0.06 s -> 0.76 s |
| REST request duration | 20-80 ms |
| RDP X.224 via task pump (`CONNECT` + `WRITE_READ`, `sleep=1`) | ~1.98 s |
| RDP X.224 via built-in native SOCKS (baseline, not used) | ~0.18 s |

This is why RDP is slow: the handshake is a serialized sequence of X.224, MCS,
security, capability, and channel-join exchanges, and every exchange waits for
the next check-in.  `OP_WRITE_READ` already combines the client write and server
read into one task; the remaining cost is the check-in itself.

Why other proxies are faster:

* **Native pivots** (`socks`, `rportfwd`) use Cobalt Strike's job/tunnel
  machinery, not one BOF task per I/O.  This project intentionally does not use
  them.
* **Thread/process-based BOF proxies** keep a relay running in the target
  process.  They are fast but use `CreateThread`/`CreateProcess`, which this
  project forbids.
* **Async BOF / Async PICO** runs a long-lived BOF in a Beacon job thread and
  can wake the Beacon for output.  Public APIs only provide `BeaconWakeup()` and
  a stop event; there is no operator-to-running-BOF data channel.  The write
  direction still arrives as a task, and the target still has a job thread.
* **Separate tunnels** (Chisel, SharpSocks, etc.) are fast but bypass the Beacon
  C2 or add a target-side listener/process, which this project forbids.

Within the no-thread, no-process, no-extra-channel design, the ~1 s/task floor
cannot be removed.  Reduce the number of exchanges (RDP tuning) or use a
different persistent tunnel outside these constraints.  See
[SETUP.md section 8.3](SETUP.md#83-rdp-and-other-latency-sensitive-protocols).

## Requirements

* Cobalt Strike 4.12+ (REST API, `/api/v1/beacons/{bid}/execute/bof/pack`).
* Team Server started with `--experimental-db`, and `csrestapi` running.
* A BOF compiled for the target Beacon's architecture (`beaconArch`).
* Python 3.9+ on the client machine (standard library only).

## Build

```sh
make            # socks5.x64.o
make x86        # socks5.x86.o (needs i686-w64-mingw32-gcc)
```

The x64 object imports only `Beacon*`, `KERNEL32$*`, `MSVCRT$*`, and
`WS2_32$*`; verify with `nm -u socks5.x64.o`.

## Run

```sh
python socks5_orchestrator.py \
  --rest-url https://127.0.0.1:50443 \
  --user csrestapi \
  --password '<teamserver-password>' \
  --bid 12345 \
  --listen 127.0.0.1 --port 1080 \
  --insecure
```

`--bid` may be omitted when exactly one live Beacon exists.  The orchestrator
selects `socks5.x86.o`/`socks5.x64.o` from the Beacon's `beaconArch`.

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--read-timeout-ms` | How long each READ task waits for target data (default 500). Keep it below the client timeout; the Beacon check-in floor dominates. |
| `--connect-timeout-ms` | CONNECT task timeout (default 4000). |
| `--task-timeout` | Seconds to wait for one REST task result (default 180). |
| `--bof @files/...` | Use a BOF already on the REST server instead of uploading the local object inline. |
| `--max-clients` | Concurrent SOCKS clients (default and maximum 16, the BOF stream limit). |
| `--idle-poll-ms` | Pause after an empty READ before polling again (default 100). Trades task volume against polling overhead; it does not remove the check-in floor. |
| `--drain-timeout` | Seconds to keep forwarding client data after target EOF (default 5). |
| `--reset` | Send RESET (close every BOF-held socket) and exit. |
| `--reset-on-start` / `--reset-on-exit` | Clean stale streams automatically. |
| `--verbose` | Log SOCKS activity and raw BOF output to stderr. |

Point the tool at the proxy, e.g.:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://10.0.0.5/
proxychains4 -q nmap -sT -Pn 10.0.0.0/24
```

## BOF wire format

Request (20-byte header, network byte order):

```
u32 magic        0x53355231 ("S5R1")
u32 op           CONNECT(1) READ(2) WRITE(3) CLOSE(4) PING(5) RESET(6)
                 WRITE_READ(7)
u32 stream_id
u32 timeout_ms   0 = operation default
u32 payload_len
u8  payload[]
```

* CONNECT: `u16 port_be | host bytes`
* READ:    `u32 max_bytes` (optional; 0 or >32768 means 32768)
* WRITE:   raw bytes
* WRITE_READ: raw bytes; sends them, then returns any server data in the
  **same** BOF task.  This is what the relay uses so each RDP
  request/response exchange costs one task instead of two.
* CLOSE/RESET/PING: empty

Result (text, written with `BeaconOutput`):

```
S5R <stream_id> <status> <error> <hex-data>\n
```

`status`: `0=OK 1=AGAIN 2=EOF 3=ERROR 4=BAD_REQUEST`.
`error` is the Winsock error code where applicable.  Data is hex encoded so
the Beacon output path never mangles binary.

## Limits

* `MAX_STREAMS` = 16 (one target socket per stream; raise and rebuild if
  needed).
* `MAX_CHUNK` = 32768 bytes per READ/WRITE task.  A READ also drains the
  socket buffer so a multi-segment server response reaches the client in
  one task without an extra round trip.
* Sockets and state die if the Beacon process exits; use `--reset` to clean up
  stale state after a reconnect.
* The orchestrator serializes BOF tasks per Beacon, so concurrent SOCKS
  clients share the Beacon task queue.  This is inherent to the task-pump
  design.  The dominant latency is the Beacon check-in interval (~1s even at
  `sleep=0`), not `--idle-poll-ms`.
* The REST client re-authenticates once on HTTP 401.  A task whose result is
  lost (Beacon dies mid-operation) must be cleaned up with `--reset`.
* `csrestapi` must be able to read the BOF.  The orchestrator sends the object
  inline as `@files/socks5.x64.o` with a base64 `files` map, so no server-side
  upload is required.

## Manual testing from Aggressor

`socks5.cna` provides `socks5_ping`, `socks5_reset`, `socks5_close`, and
`socks5_run <bid> <op> <stream_id> <hex-payload> [timeout_ms]`.  For example,
connect to `example.com:80` on stream 1:

```
socks5_run 12345 1 1 00506578616d706c652e636f6d
```

Then read:

```
socks5_run 12345 2 1 ""
```

The result appears in the Beacon console as `S5R 1 0 0 <hex>`.
