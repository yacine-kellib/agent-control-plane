#!/usr/bin/env python3
"""
_rpc.py — line-delimited JSON over stdio. The whole transport, deliberately.

Each service is a real OS process. They talk by writing one JSON object per line
to a pipe. No shared memory, no shared objects, no imports across the boundary
at run time — which is what makes the separation in brief §6.1 mean something.
An architecture diagram showing seven boxes that are really seven imports in one
interpreter has drawn the boxes, not built them.

The protocol is boring on purpose (brief §7):

    →  {"id": 1, "method": "evaluate", "args": {...}}
    ←  {"id": 1, "ok": true,  "result": {...}}
    ←  {"id": 1, "ok": false, "error": {"rule": "DR-9", "detail": "...", "type": "FailClosed"}}

A control decision that cannot be traced to bytes on a wire is a control
decision taken on trust.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys


class RemoteFailure(Exception):
    """A fail-closed raised on the other side of a pipe, carried across intact."""

    def __init__(self, rule: str, detail: str, kind: str = "FailClosed"):
        self.rule, self.detail, self.kind = rule, detail, kind
        super().__init__(f"[{rule}] {detail}")


# ------------------------------------------------------------------- server
def serve(handlers: dict) -> None:
    """
    Run a service loop until stdin closes.

    Unknown methods are an error, never a no-op: a service that silently ignores
    a call it does not understand is a service whose caller believes something
    happened.
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        rid, method, args = req.get("id"), req.get("method"), req.get("args") or {}
        try:
            fn = handlers.get(method)
            if fn is None:
                raise RemoteFailure("RPC-1", f"unknown method {method!r}")
            out = {"id": rid, "ok": True, "result": fn(**args)}
        except Exception as e:                       # noqa: BLE001 — carried, not swallowed
            out = {"id": rid, "ok": False, "error": {
                "rule": getattr(e, "rule", "RPC-2"),
                "detail": getattr(e, "detail", str(e)),
                "type": type(e).__name__}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


# ------------------------------------------------------------------- client
class Service:
    """A handle on a running service process."""

    def __init__(self, name: str, module: str, repo_root: str):
        self.name = name
        env = dict(os.environ, PYTHONPATH=repo_root, PYTHONUNBUFFERED="1")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", module],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
            cwd=repo_root, env=env)
        self._id = 0

    def call(self, method: str, **args):
        self._id += 1
        req = json.dumps({"id": self._id, "method": method, "args": args})
        try:
            self.proc.stdin.write(req + "\n")
            self.proc.stdin.flush()
            line = self.proc.stdout.readline()
        except (BrokenPipeError, ValueError):
            raise RemoteFailure("RPC-3", f"{self.name} is not responding")
        if not line:
            err = ""
            try:
                err = self.proc.stderr.read()[-800:]
            except Exception:                        # noqa: BLE001
                pass
            raise RemoteFailure("RPC-3", f"{self.name} died: {err.strip()}")
        resp = json.loads(line)
        if not resp.get("ok"):
            e = resp.get("error") or {}
            raise RemoteFailure(e.get("rule", "RPC-2"), e.get("detail", "?"),
                                e.get("type", "FailClosed"))
        return resp.get("result")

    @property
    def pid(self) -> int:
        return self.proc.pid

    def close(self) -> None:
        try:
            self.proc.stdin.close()
        except Exception:                            # noqa: BLE001
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:                            # noqa: BLE001
            self.proc.kill()
