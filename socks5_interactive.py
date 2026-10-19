#!/usr/bin/env python3
"""Interactive Beacon picker/controller for the socks5 task pump.

The UI never blocks on REST calls or on the orchestrator child process:

  * a refresh thread re-reads the Beacon list every second
  * an action thread starts/stops/switches the orchestrator
  * the main thread polls the keyboard and redraws the menu

Controls:

  Up / Down / Left / Right (or k/j/h/l)   move selection
  Enter                                   start or switch Beacon
  s                                       stop the proxy
  r                                       refresh now
  q                                       quit (proxy keeps running)
  Ctrl+C                                  quit and stop the proxy

Switching Beacons drops existing SOCKS connections because the target sockets
live in the old Beacon's BOF state.
"""

import argparse
import contextlib
import os
import queue
import select
import signal
import socket
import subprocess
import sys
import threading
import time

import socks5_orchestrator as O

BASE = os.path.dirname(os.path.abspath(__file__))
IS_WINDOWS = os.name == "nt"

CLEAR = "\x1b[2J\x1b[H"
HOME = "\x1b[H"
CLR_LINE = "\x1b[K"
CLR_BELOW = "\x1b[J"
HIDE_CURSOR = "\x1b[?25l"
SHOW_CURSOR = "\x1b[?25h"
REVERSE = "\x1b[7m"
RESET = "\x1b[0m"


def enable_ansi():
    if not IS_WINDOWS:
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


@contextlib.contextmanager
def raw_terminal():
    if IS_WINDOWS:
        yield
        return
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def read_key_now():
    if IS_WINDOWS:
        import msvcrt

        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            ch2 = msvcrt.getwch()
            return {
                "H": "up", "P": "down", "K": "left", "M": "right",
            }.get(ch2, "none")
        if ch in ("\r", "\n"):
            return "enter"
        if ch == "\x03":
            return "interrupt"
        if ch == "\x1b":
            return "quit"
        low = ch.lower()
        return {
            "q": "quit", "s": "stop", "r": "refresh",
            "k": "up", "j": "down", "h": "left", "l": "right",
        }.get(low, "none")

    fd = sys.stdin.fileno()
    ch = os.read(fd, 1)
    if not ch:
        return "quit"
    if ch == b"\x03":
        return "interrupt"
    if ch == b"\x1b":
        # Terminals send either CSI ("\x1b[A") or SS3 ("\x1bOA") for arrows.
        # Read the rest of the sequence without blocking the UI.
        seq = b""
        deadline = time.time() + 0.15
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                break
            part = os.read(fd, 1)
            if not part:
                break
            seq += part
            if part in (b"A", b"B", b"C", b"D") and seq[:1] in (b"[", b"O"):
                break
        if seq.endswith(b"A"):
            return "up"
        if seq.endswith(b"B"):
            return "down"
        if seq.endswith(b"C"):
            return "right"
        if seq.endswith(b"D"):
            return "left"
        if seq == b"":
            return "quit"
        return "none"
    if ch in (b"\r", b"\n"):
        return "enter"
    try:
        low = ch.decode("latin1").lower()
    except UnicodeDecodeError:
        return "none"
    return {
        "q": "quit", "s": "stop", "r": "refresh",
        "k": "up", "j": "down", "h": "left", "l": "right",
    }.get(low, "none")


def poll_key(timeout):
    """Wait up to timeout seconds for a key. Return None on timeout."""
    if IS_WINDOWS:
        import msvcrt

        deadline = time.time() + timeout
        while time.time() < deadline:
            if msvcrt.kbhit():
                return read_key_now()
            time.sleep(0.02)
        return None
    try:
        ready, _, _ = select.select([sys.stdin.fileno()], [], [], timeout)
    except (OSError, ValueError):
        return None
    if not ready:
        return None
    return read_key_now()


def bof_for(beacon):
    if not beacon:
        return None
    arch = beacon.get("beaconArch") or "x64"
    suffix = "x86.o" if arch == "x86" else "x64.o"
    path = os.path.join(BASE, "socks5." + suffix)
    return path if os.path.exists(path) else None


def port_open(host, port, timeout=0.3):
    target = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    try:
        with socket.create_connection((target, port), timeout):
            return True
    except OSError:
        return False


def cut(value, width):
    text = "" if value is None else str(value)
    if len(text) <= width:
        return text
    return text[:width - 2] + ".."


def parse_args():
    parser = argparse.ArgumentParser(
        description="Interactive Beacon picker for the socks5 task pump."
    )
    parser.add_argument("--rest-url", default="https://127.0.0.1:50443")
    parser.add_argument("--user", default="csrestapi")
    parser.add_argument("--password",
                        default=os.environ.get("CS_REST_PASSWORD", ""))
    parser.add_argument("--insecure", action="store_true",
                        help="Do not verify the REST API TLS certificate")
    parser.add_argument("--ca-cert", default=None)
    parser.add_argument("--bid", default=None,
                        help="Beacon id to preselect in the menu")
    parser.add_argument("--bof", default=None,
                        help="BOF path or @files/name to pass through")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1080)
    parser.add_argument("--task-timeout", type=float, default=90.0)
    parser.add_argument("--read-timeout-ms", type=int, default=500)
    parser.add_argument("--connect-timeout-ms", type=int, default=4000)
    parser.add_argument("--write-timeout-ms", type=int, default=4000)
    parser.add_argument("--refresh-interval", type=float, default=1.0,
                        help="Seconds between Beacon list refreshes")
    parser.add_argument("--reset-on-stop", action="store_true",
                        help="Send RESET to the old Beacon when stopping "
                             "or switching")
    parser.add_argument("--all", action="store_true",
                        help="Show dead Beacons too")
    parser.add_argument("--logdir", default=BASE)
    return parser.parse_args()


class Picker:
    def __init__(self, args, cs):
        self.args = args
        self.cs = cs
        self.lock = threading.RLock()

        self.beacons = []
        self.selected = 0
        self.last_refresh = 0.0
        self.refresh_error = ""
        self.message = ""

        self.proc = None
        self.proc_bid = None
        self.proc_state = "stopped"
        self.action_name = None
        self.log_handle = None
        self.err_handle = None

        self.cancel_event = threading.Event()
        self.stop_event = threading.Event()
        self.action_queue = queue.Queue()
        self.refresh_thread = threading.Thread(
            target=self._refresh_loop, name="beacon-refresh", daemon=True)
        self.action_thread = threading.Thread(
            target=self._action_loop, name="proxy-action", daemon=True)

    # ---- lifecycle ---------------------------------------------------
    def start_threads(self):
        self.refresh_thread.start()
        self.action_thread.start()

    def shutdown(self):
        self.cancel_event.set()
        self.stop_event.set()
        self.action_queue.put(None)
        self.refresh_thread.join(timeout=2.0)
        self.action_thread.join(timeout=5.0)

    # ---- beacon list -------------------------------------------------
    def refresh_once(self):
        try:
            beacons = self.cs.list_beacons()
        except Exception as exc:  # noqa: BLE001
            with self.lock:
                self.refresh_error = str(exc)
                self.last_refresh = time.time()
            return
        if not self.args.all:
            beacons = [b for b in beacons if b.get("alive", True)]
        beacons.sort(key=lambda b: (
            not b.get("alive", True),
            (b.get("computer") or ""),
            (b.get("process") or ""),
            str(b.get("bid")),
        ))
        with self.lock:
            old_bid = None
            if self.beacons and 0 <= self.selected < len(self.beacons):
                old_bid = self.beacons[self.selected].get("bid")
            self.beacons = beacons
            if old_bid is not None:
                for index, beacon in enumerate(beacons):
                    if str(beacon.get("bid")) == str(old_bid):
                        self.selected = index
                        break
            if self.selected >= len(beacons):
                self.selected = max(0, len(beacons) - 1)
            self.refresh_error = ""
            self.last_refresh = time.time()

    def _refresh_loop(self):
        interval = max(0.2, float(self.args.refresh_interval))
        while not self.stop_event.is_set():
            self.refresh_once()
            self.stop_event.wait(interval)

    def move(self, delta):
        with self.lock:
            if not self.beacons:
                return
            self.selected = (self.selected + delta) % len(self.beacons)
            self.message = ""

    def selected_beacon(self):
        with self.lock:
            if not self.beacons:
                return None
            if self.selected >= len(self.beacons):
                self.selected = len(self.beacons) - 1
            return self.beacons[self.selected]

    # ---- actions (background thread) ---------------------------------
    def enqueue_start(self, beacon):
        with self.lock:
            if self.action_name is not None:
                self.message = "busy (%s); press s to cancel" % self.action_name
                return
            self.action_name = "queued"
        self.action_queue.put(("start", beacon))

    def enqueue_stop(self):
        with self.lock:
            if self.action_name == "starting":
                self.cancel_event.set()
                self.message = "cancelling start..."
        self.action_queue.put(("stop", None))

    def _action_loop(self):
        while True:
            item = self.action_queue.get()
            if item is None:
                return
            action, payload = item
            self.cancel_event.clear()
            try:
                if action == "start":
                    self._do_start(payload)
                elif action == "stop":
                    self._do_stop(bool(self.args.reset_on_stop))
            except Exception as exc:  # noqa: BLE001
                with self.lock:
                    self.message = "%s failed: %s" % (action, exc)
                    self.proc_state = "error"
            finally:
                with self.lock:
                    self.action_name = None

    def _set_message(self, text, state=None):
        with self.lock:
            self.message = text
            if state is not None:
                self.proc_state = state

    def _open_logs(self):
        os.makedirs(self.args.logdir, exist_ok=True)
        self.log_handle = open(
            os.path.join(self.args.logdir, "orchestrator.log"),
            "a", encoding="utf-8", errors="replace", buffering=1)
        self.err_handle = open(
            os.path.join(self.args.logdir, "orchestrator.err"),
            "a", encoding="utf-8", errors="replace", buffering=1)

    def _close_logs(self):
        for handle in (self.log_handle, self.err_handle):
            try:
                if handle is not None:
                    handle.close()
            except OSError:
                pass
        self.log_handle = None
        self.err_handle = None

    def _tail_err(self, count=4):
        try:
            with open(os.path.join(self.args.logdir, "orchestrator.err"),
                      "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()[-count:]
            return " | ".join(line.strip() for line in lines if line.strip())
        except OSError:
            return ""

    def _terminate_child(self, send_reset=False):
        with self.lock:
            proc = self.proc
            bid = self.proc_bid
            if proc is not None:
                self.proc_state = "stopping"
                self.message = "stopping pid=%s..." % proc.pid
        if proc is not None and proc.poll() is None:
            # Ask the child to shut down cleanly first so its finally block
            # can run (and send RESET when --reset-on-exit is enabled).
            try:
                if IS_WINDOWS:
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    proc.send_signal(signal.SIGINT)
            except (OSError, ValueError):
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        with self.lock:
            self.proc = None
            self.proc_bid = None
            self.proc_state = "stopped"
            self._close_logs()
        if send_reset and bid is not None:
            self._do_reset(bid)
        return bid

    def _do_stop(self, send_reset):
        with self.lock:
            self.action_name = "stopping"
            self.message = "stopping proxy..."
        self._terminate_child(send_reset=send_reset)
        self._set_message("proxy stopped", "stopped")

    def _do_start(self, beacon):
        if beacon is None:
            self._set_message("no Beacon selected", "stopped")
            return
        if not beacon.get("alive", True):
            self._set_message("Beacon %s is not alive"
                              % beacon.get("bid"), "stopped")
            return
        bof = self.args.bof
        if not bof:
            bof = bof_for(beacon)
            if bof is None:
                self._set_message(
                    "no local BOF for arch %s (build socks5.%s.o or pass --bof)"
                    % (beacon.get("beaconArch"),
                       "x86" if beacon.get("beaconArch") == "x86" else "x64"),
                    "stopped")
                return

        with self.lock:
            self.action_name = "starting"
            self.message = "starting on %s (%s)..." % (
                beacon.get("bid"), beacon.get("computer"))
            self.proc_state = "starting"

        self._terminate_child(send_reset=False)

        if self.cancel_event.is_set():
            self._set_message("start cancelled", "stopped")
            return
        with self.lock:
            self.message = "starting on %s (%s)..." % (
                beacon.get("bid"), beacon.get("computer"))
        if port_open(self.args.listen, self.args.port):
            self._set_message(
                "port %s:%s already in use; stop the existing listener first"
                % (self.args.listen, self.args.port), "stopped")
            return

        self._open_logs()
        try:
            self.log_handle.write("\n===== %s  bid=%s =====\n"
                                  % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                     beacon.get("bid")))
            cmd = [
                sys.executable, "-u",
                os.path.join(BASE, "socks5_orchestrator.py"),
                "--rest-url", self.args.rest_url,
                "--user", self.args.user,
                "--bid", str(beacon.get("bid")),
                "--listen", self.args.listen,
                "--port", str(self.args.port),
                "--task-timeout", str(self.args.task_timeout),
                "--read-timeout-ms", str(self.args.read_timeout_ms),
                "--connect-timeout-ms", str(self.args.connect_timeout_ms),
                "--write-timeout-ms", str(self.args.write_timeout_ms),
                "--reset-on-start",
                "--reset-on-exit",
                "--verbose",
            ]
            if self.args.bof:
                cmd.extend(["--bof", self.args.bof])
            if self.args.insecure:
                cmd.append("--insecure")
            if self.args.ca_cert:
                cmd.extend(["--ca-cert", self.args.ca_cert])

            env = os.environ.copy()
            env["CS_REST_PASSWORD"] = self.args.password
            kwargs = dict(cwd=BASE, stdout=self.log_handle,
                          stderr=self.err_handle, env=env)
            if IS_WINDOWS:
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs["start_new_session"] = True

            proc = subprocess.Popen(cmd, **kwargs)
        except OSError as exc:
            with self.lock:
                self._close_logs()
            self._set_message("could not start orchestrator: %s" % exc,
                              "error")
            return

        with self.lock:
            self.proc = proc
            self.proc_bid = beacon.get("bid")
            self.proc_state = "starting"

        host = ("127.0.0.1" if self.args.listen in ("0.0.0.0", "::")
                else self.args.listen)
        started = time.time()
        deadline = started + 20
        while time.time() < deadline:
            if self.cancel_event.is_set():
                self._terminate_child(send_reset=False)
                self._set_message("start cancelled", "stopped")
                return
            if proc.poll() is not None:
                err = self._tail_err()
                with self.lock:
                    self.proc = None
                    self.proc_bid = None
                    self.proc_state = "error"
                    self._close_logs()
                self.message = ("proxy exited during startup (code %s)%s"
                                % (proc.returncode,
                                   (": " + err) if err else ""))
                return
            if port_open(host, self.args.port):
                with self.lock:
                    self.proc_state = "running"
                    self.message = ("started pid=%s via %s (%s) on %s:%s"
                                    % (proc.pid, beacon.get("bid"),
                                       beacon.get("computer"),
                                       self.args.listen, self.args.port))
                return
            with self.lock:
                self.message = ("waiting for listener... %ds (pid=%s, bid=%s)"
                                % (int(time.time() - started), proc.pid,
                                   beacon.get("bid")))
            time.sleep(0.2)

        self._terminate_child(send_reset=False)
        err = self._tail_err()
        self._set_message("timed out waiting for listener%s"
                          % ((": " + err) if err else ""), "error")

    def _do_reset(self, bid):
        with self.lock:
            self.action_name = "resetting"
            self.message = "sending RESET to %s..." % bid
        beacon = None
        with self.lock:
            for item in self.beacons:
                if str(item.get("bid")) == str(bid):
                    beacon = item
                    break
        bof = self.args.bof or bof_for(beacon)
        if bof is None:
            self._set_message("no BOF available, RESET skipped", "stopped")
            return
        try:
            name, data = O.load_bof(bof)
            runner = O.TaskRunner(self.cs, bid, name, data, 60, 0.5, False)
            try:
                runner.run_sync(O.OP_RESET, 0, b"", 0)
            finally:
                runner.stop()
            self._set_message("RESET sent to %s" % bid, "stopped")
        except Exception as exc:  # noqa: BLE001
            self._set_message("RESET failed: %s" % exc, "stopped")

    # ---- child status / rendering ------------------------------------
    def poll_child(self):
        with self.lock:
            proc = self.proc
        if proc is None:
            return
        code = proc.poll()
        if code is None:
            return
        with self.lock:
            if self.proc is not proc:
                return
            self.proc = None
            self.proc_bid = None
            self.proc_state = "stopped"
            self.message = ("proxy exited (code %s); see orchestrator.err"
                            % code)
            self._close_logs()

    def render(self, first=False):
        with self.lock:
            beacons = list(self.beacons)
            selected = self.selected
            proc = self.proc
            proc_bid = self.proc_bid
            proc_state = self.proc_state
            action_name = self.action_name
            message = self.message
            last_refresh = self.last_refresh
            refresh_error = self.refresh_error

        running = proc is not None and proc.poll() is None
        age = (time.time() - last_refresh) if last_refresh else -1
        lines = []
        lines.append("socks5 interactive Beacon picker")
        lines.append("REST %s   user %s   list refresh %.0fs"
                     % (self.args.rest_url, self.args.user,
                        self.args.refresh_interval))
        if running and proc_state == "running":
            status = "PROXY RUNNING   pid=%s  bid=%s  %s:%s" % (
                proc.pid, proc_bid, self.args.listen, self.args.port)
        elif running and proc_state == "starting":
            status = "PROXY STARTING  pid=%s  bid=%s" % (proc.pid, proc_bid)
        elif running and proc_state == "stopping":
            status = "PROXY STOPPING  pid=%s  bid=%s" % (proc.pid, proc_bid)
        elif action_name:
            status = "PROXY %s" % action_name.upper()
        elif proc_state == "error":
            status = "PROXY ERROR"
        else:
            status = "PROXY STOPPED"
        lines.append(status)
        if age >= 0:
            lines.append("Beacon list updated %.1fs ago%s"
                         % (age, ("  ERROR: " + refresh_error)
                            if refresh_error else ""))
        else:
            lines.append("Beacon list loading...")
        lines.append("-" * 104)
        lines.append("  %-12s %-20s %-10s %-14s %-5s %-6s %-9s %s"
                     % ("bid", "computer", "user", "process", "arch",
                        "sleep", "last", "state"))
        lines.append("-" * 104)
        if not beacons:
            lines.append("  (no Beacons; press r to refresh)")
        for index, beacon in enumerate(beacons):
            marker = ">" if index == selected else " "
            state = "alive" if beacon.get("alive", True) else "dead"
            if not (self.args.bof or bof_for(beacon)):
                state += " !no-bof"
            line = ("%s %-12s %-20s %-10s %-14s %-5s %-6s %-9s %s"
                    % (marker,
                       cut(beacon.get("bid"), 12),
                       cut(beacon.get("computer"), 20),
                       cut(beacon.get("user"), 10),
                       cut(beacon.get("process"), 14),
                       cut(beacon.get("beaconArch"), 5),
                       cut((beacon.get("sleep") or {}).get("sleep"), 6),
                       cut(beacon.get("lastCheckinFormatted"), 9),
                       state))
            if index == selected:
                line = REVERSE + line + RESET
            lines.append(line)
        lines.append("-" * 104)
        lines.append("up/down or left/right: select   Enter: start/switch   "
                     "s: stop   r: refresh   q: quit")
        lines.append("")
        if message:
            lines.append(message)

        out = [CLEAR if first else HOME]
        for line in lines:
            out.append(line + CLR_LINE + "\n")
        out.append(CLR_BELOW)
        sys.stdout.write("".join(out))
        sys.stdout.flush()


def main():
    args = parse_args()
    if not sys.stdin.isatty():
        sys.stderr.write(
            "[interactive] stdin is not a TTY; use "
            "socks5_orchestrator.py --bid <bid> instead\n")
        return 2
    if not args.password:
        sys.stderr.write("[interactive] REST password required "
                         "(--password or CS_REST_PASSWORD)\n")
        return 2

    enable_ansi()
    sys.stdout.write("Connecting to %s ...\n" % args.rest_url)
    sys.stdout.flush()
    cs = O.CSRest(args.rest_url, args.user, args.password, args.insecure,
                  args.ca_cert)
    try:
        cs.login()
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write("[interactive] REST login failed: %s\n" % exc)
        return 1

    picker = Picker(args, cs)
    picker.refresh_once()
    picker.start_threads()
    if args.bid:
        with picker.lock:
            for index, beacon in enumerate(picker.beacons):
                if str(beacon.get("bid")) == str(args.bid):
                    picker.selected = index
                    break

    sys.stdout.write(HIDE_CURSOR)
    sys.stdout.flush()
    first = True
    last_render = 0.0
    interrupted = False
    try:
        with raw_terminal():
            while True:
                now = time.time()
                key = poll_key(0.1)
                if key is not None:
                    if key in ("up", "left"):
                        picker.move(-1)
                    elif key in ("down", "right"):
                        picker.move(1)
                    elif key == "enter":
                        beacon = picker.selected_beacon()
                        if beacon is not None:
                            picker.enqueue_start(beacon)
                    elif key == "stop":
                        picker.enqueue_stop()
                    elif key == "refresh":
                        threading.Thread(
                            target=picker.refresh_once, daemon=True).start()
                        with picker.lock:
                            picker.message = "refreshing..."
                    elif key == "interrupt":
                        interrupted = True
                        break
                    elif key == "quit":
                        break
                    picker.poll_child()
                    picker.render(first=first)
                    first = False
                    last_render = time.time()
                elif now - last_render >= 0.5:
                    picker.poll_child()
                    picker.render(first=first)
                    first = False
                    last_render = now
                else:
                    picker.poll_child()
    except KeyboardInterrupt:
        interrupted = True
    finally:
        picker.shutdown()
        if interrupted:
            picker._terminate_child(send_reset=False)
        sys.stdout.write(SHOW_CURSOR + "\n")
        sys.stdout.flush()

    if picker.proc is not None and picker.proc.poll() is None:
        print("Proxy left running: pid=%s bid=%s (%s:%s)"
              % (picker.proc.pid, picker.proc_bid,
                 args.listen, args.port))
        print("Stop it with: Stop-Process -Id %s -Force" % picker.proc.pid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
