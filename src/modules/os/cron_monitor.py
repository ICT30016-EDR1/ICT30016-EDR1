"""
cron_monitor.py
=======================
Monitoring layer for the cron job hijacking agent. Unlike the OS agent
(which looks at process UID/EUID at runtime), a hijacked cron job never
produces a uid mismatch -- cron launches the script directly as root, so
the malicious process has real_uid == effective_uid == 0 from the start.
The signature of this attack instead lives in the FILE: a script that
root's crontab trusts gets modified by a non-root user who found it
writable.

This module collects telemetry about two kinds of trusted files:
  - the cron-referenced SCRIPTS themselves (event_type="cron_script_state")
  - the cron CONFIG files that reference them -- /etc/crontab and each
    file under /etc/cron.d/ (event_type="cron_config_state")

The config-file tracking closes a gap the script-only version had: an
attacker who edits /etc/cron.d/<job> directly -- changing the schedule,
the user field, or swapping in a reference to a different script
entirely -- never touches the script file itself, so watching only the
scripts would miss it completely.

For each tracked file, this module emits:
  - at startup, a one-off "here is what this file looks like right now"
    fact (hash, permissions, owner)
  - from then on, a fresh fact every time that file is modified
    (debounced -- see CronScriptHandler)

Periodic re-enumeration: a background thread re-parses the cron
sources every RESCAN_INTERVAL_SECONDS and compares the result against
what's currently tracked. Anything new -- a brand-new file dropped
into /etc/cron.d/, or an existing cron job edited to reference a
script that didn't exist (or wasn't referenced) before -- gets an
initial baseline fact emitted and is added to the live watchdog watch
immediately, without restarting this process. This replaces the
earlier "enumerate once at startup only" behaviour: previously a cron
job added after this agent started was invisible until a restart.

It makes NO judgment about whether a given hash, permission, or change
is suspicious. That is cron_detection.py's job: comparing hashes
against a baseline, and separately flagging world/group-writable
files as a standing risk. This mirrors the split used by the other
two agents: monitor emits facts, detection emits judgments.

Usage:
    sudo python3 monitor.py

Note: removal of a cron job / script (rather than addition) is not
tracked here -- a path that disappears simply stops producing events.
Detecting "a previously-tracked cron job vanished" would be a
reasonable further addition but is out of scope for this pass.
"""

import sys
import os
import re
import glob
import hashlib
import subprocess
import threading
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from common.events import MonitoringEvent

# How often the background thread re-parses the cron sources looking
# for newly added config files / newly referenced scripts. Lower is
# more responsive but means more frequent crontab/file parsing; higher
# means a longer window where a brand-new cron job stays invisible.
RESCAN_INTERVAL_SECONDS = 15

# Matches script-like paths referenced inside a crontab line: a .sh
# file anywhere, or anything under /opt or /usr/local. Deliberately the
# same pattern used by the bash version of this detector, so both stay
# consistent.
SCRIPT_PATTERN = re.compile(r"(/\S+\.sh|/opt/\S+|/usr/local/\S+)")


def get_cron_sources():
    """
    /etc/crontab plus every file currently under /etc/cron.d/.
    Recomputed fresh on EVERY call (not cached at import time) so a
    newly added /etc/cron.d/<job> file is visible on the next rescan,
    not just at process startup.
    """
    return ["/etc/crontab"] + glob.glob("/etc/cron.d/*")


def get_cron_referenced_scripts():
    """
    Parse root's crontab plus /etc/crontab and /etc/cron.d/* for script
    paths they invoke. Purely structural extraction -- no judgment
    about whether any of the referenced scripts are safe.
    """
    text_blobs = []

    try:
        result = subprocess.run(
            ["crontab", "-l", "-u", "root"],
            capture_output=True, text=True, check=False,
        )
        text_blobs.append(result.stdout)
    except FileNotFoundError:
        pass  # crontab command not installed; skip

    for path in get_cron_sources():
        try:
            with open(path, "r") as f:
                text_blobs.append(f.read())
        except (FileNotFoundError, PermissionError):
            continue

    scripts = set()
    for blob in text_blobs:
        for line in blob.splitlines():
            if line.strip().startswith("#"):
                continue
            for match in SCRIPT_PATTERN.findall(line):
                scripts.add(match)

    # Only report paths that actually exist as files right now.
    return sorted(p for p in scripts if os.path.isfile(p))


def get_cron_config_paths():
    """
    The cron configuration files themselves -- /etc/crontab and each
    file under /etc/cron.d/. Distinct from get_cron_referenced_scripts(),
    which extracts the script paths THESE files point at; this tracks
    the config files' own content/identity, so an attacker editing the
    schedule or swapping in a different script reference is visible
    too, not just an attacker who tampers with the script itself.
    """
    return sorted(p for p in get_cron_sources() if os.path.isfile(p))


def describe_script(path):
    """
    Return the structural facts for one tracked file: its hash,
    permissions, and owning UID. No judgment about whether any of
    these values are good or bad -- that's detection.py's job. Used
    for both cron-referenced scripts and the cron config files
    themselves, since the facts needed are identical either way.
    """
    try:
        stat_info = os.stat(path)
        with open(path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

    return {
        "path": path,
        "sha256": file_hash,
        "mode": oct(stat_info.st_mode & 0o777),
        "owner_uid": stat_info.st_uid,
        "size_bytes": stat_info.st_size,
    }


class CronScriptHandler(FileSystemEventHandler):
    """
    Watches the directories containing tracked files, and emits a
    fresh fact whenever one of them is modified. Used for both the
    cron-referenced scripts (event_type="cron_script_state") and the
    cron config files themselves (event_type="cron_config_state") --
    same mechanism, different tracked set and fact label.

    tracked_paths can grow at runtime (the rescan thread calls
    add_path() when it finds something new), so access to it is
    guarded by a lock -- it's read from the watchdog callback thread
    and written from the rescan thread.

    Debounced: a single logical write (chmod + truncate + write +
    close, e.g. from `cp`) can fire several raw inotify events on the
    same path within milliseconds of each other. Without debouncing,
    each one becomes its own fact/verdict, and response.py ends up
    re-acting on stale, already-superseded permission snapshots --
    producing several identical-looking actions for what was really
    one real-world change.
    """

    DEBOUNCE_SECONDS = 0.5

    def __init__(self, tracked_paths, event_type="cron_script_state"):
        self.tracked_paths = set(tracked_paths)
        self.event_type = event_type
        self._last_emit = {}  # path -> timestamp of last fact emitted
        self._lock = threading.Lock()

    def add_path(self, path):
        """Called by the rescan thread when a new file is found to track."""
        with self._lock:
            self.tracked_paths.add(path)

    def on_modified(self, event):
        if event.is_directory:
            return

        with self._lock:
            if event.src_path not in self.tracked_paths:
                return

            now = time.time()
            last = self._last_emit.get(event.src_path, 0)
            if now - last < self.DEBOUNCE_SECONDS:
                return  # part of the same burst as a very recent event -- skip
            self._last_emit[event.src_path] = now

        facts = describe_script(event.src_path)
        if facts is None:
            return  # file disappeared between the event and reading it

        MonitoringEvent(
            source="cron",
            event_type=self.event_type,
            data=facts,
        ).emit()


def _ensure_watched(observer, script_handler, config_handler, directory,
                     watched_dirs, watched_dirs_lock):
    """Schedule both handlers on `directory` if it isn't already being
    watched. Safe to call after observer.start() -- watchdog supports
    adding watches to a running observer."""
    with watched_dirs_lock:
        if directory in watched_dirs:
            return
        observer.schedule(script_handler, directory, recursive=False)
        observer.schedule(config_handler, directory, recursive=False)
        watched_dirs.add(directory)


def _rescan_loop(observer, script_handler, config_handler,
                  watched_dirs, watched_dirs_lock):
    """
    Runs forever in a background thread. Every RESCAN_INTERVAL_SECONDS,
    re-parses the cron sources and compares against what's already
    tracked. Anything new gets an initial baseline fact emitted (same
    as the startup loop in main()) and is added to the live watch, so
    a cron job added after this agent started is picked up without a
    restart.
    """
    while True:
        time.sleep(RESCAN_INTERVAL_SECONDS)

        try:
            current_scripts = set(get_cron_referenced_scripts())
            current_configs = set(get_cron_config_paths())
        except Exception as exc:
            print(f"[!] rescan failed: {exc}", flush=True)
            continue

        new_scripts = current_scripts - script_handler.tracked_paths
        new_configs = current_configs - config_handler.tracked_paths

        for path in sorted(new_scripts):
            facts = describe_script(path)
            if facts:
                MonitoringEvent(source="cron", event_type="cron_script_state", data=facts).emit()
            script_handler.add_path(path)
            _ensure_watched(observer, script_handler, config_handler,
                             os.path.dirname(path), watched_dirs, watched_dirs_lock)
            print(f"[*] New cron-referenced script detected -- now tracked: {path}", flush=True)

        for path in sorted(new_configs):
            facts = describe_script(path)
            if facts:
                MonitoringEvent(source="cron", event_type="cron_config_state", data=facts).emit()
            config_handler.add_path(path)
            _ensure_watched(observer, script_handler, config_handler,
                             os.path.dirname(path), watched_dirs, watched_dirs_lock)
            print(f"[*] New cron config file detected -- now tracked: {path}", flush=True)


def main():
    scripts = get_cron_referenced_scripts()
    config_paths = get_cron_config_paths()
    print(f"[*] Cron-based monitoring agent started. Tracking "
          f"{len(scripts)} cron-referenced script(s) and "
          f"{len(config_paths)} cron config file(s).")
    print(f"[*] Re-checking for newly added cron jobs every "
          f"{RESCAN_INTERVAL_SECONDS}s.")
    print("[*] Emitting events as JSON lines. Press Ctrl+C to stop.\n")

    # Emit one fact per tracked file immediately, so a detection engine
    # has something to build its initial baseline from.
    for path in scripts:
        facts = describe_script(path)
        if facts:
            MonitoringEvent(source="cron", event_type="cron_script_state", data=facts).emit()

    for path in config_paths:
        facts = describe_script(path)
        if facts:
            MonitoringEvent(source="cron", event_type="cron_config_state", data=facts).emit()

    script_handler = CronScriptHandler(scripts, event_type="cron_script_state")
    config_handler = CronScriptHandler(config_paths, event_type="cron_config_state")
    observer = Observer()

    # watchdog watches directories, not individual files, so watch the
    # unique set of parent directories for BOTH tracked sets, and let
    # each handler filter down to its own exact paths. Scheduling both
    # handlers on every directory is harmless -- each one's
    # on_modified() immediately returns if the modified path isn't in
    # ITS OWN tracked_paths, so a script event is never mistaken for a
    # config event or vice versa.
    watched_dirs = set()
    watched_dirs_lock = threading.Lock()
    for directory in {os.path.dirname(p) for p in scripts} | {os.path.dirname(p) for p in config_paths}:
        observer.schedule(script_handler, directory, recursive=False)
        observer.schedule(config_handler, directory, recursive=False)
        watched_dirs.add(directory)

    observer.start()

    rescan_thread = threading.Thread(
        target=_rescan_loop,
        args=(observer, script_handler, config_handler, watched_dirs, watched_dirs_lock),
        daemon=True,
    )
    rescan_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[*] Stopping cron-based monitoring agent.")
    observer.join()


if __name__ == "__main__":
    main()
