"""Start the public sandbox: the poisoned test server on loopback, then the gateway.

Both run as children of this process. When either exits, the other is stopped
and the container exits too, so the host restarts a whole, fresh sandbox.
Standard library only.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE_PORT = 8100  # examples/poisoned_server.py binds 127.0.0.1:8100
DATA_DIR = Path(os.environ.get("MSG_SANDBOX_DATA_DIR", "/tmp/msg-sandbox"))


def wait_for_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"nothing listens on 127.0.0.1:{port} after {timeout:.0f} s")


def sandbox_environment() -> tuple[dict[str, str], str]:
    env = dict(os.environ)
    env.setdefault("MSG_ENVIRONMENT", "sandbox")
    env["MSG_DATABASE_URL"] = f"sqlite:///{DATA_DIR / 'gateway.db'}"
    port = env.get("PORT", "8000")
    # Render sets these to the service's public name and URL.
    public_host = env.get("RENDER_EXTERNAL_HOSTNAME")
    public_url = env.get("RENDER_EXTERNAL_URL")
    env.setdefault("MSG_ALLOWED_HOSTS", ",".join(["127.0.0.1", "localhost", *([public_host] if public_host else [])]))
    env.setdefault(
        "MSG_ALLOWED_ORIGINS",
        ",".join([f"http://127.0.0.1:{port}", f"http://localhost:{port}", *([public_url] if public_url else [])]),
    )
    return env, port


def main() -> int:
    # Fresh data on every start: the sandbox keeps nothing between runs.
    shutil.rmtree(DATA_DIR, ignore_errors=True)
    DATA_DIR.mkdir(parents=True)
    env, port = sandbox_environment()

    fixture = subprocess.Popen([sys.executable, str(HERE / "poisoned_server.py")], env=env)
    try:
        wait_for_port(FIXTURE_PORT)
    except RuntimeError as exc:
        print(f"sandbox: the test server did not start: {exc}", file=sys.stderr)
        fixture.terminate()
        return 1

    gateway = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn", "mcp_security_gateway.main:app",
            "--host", "0.0.0.0", "--port", port,
            "--no-server-header",
            # The gateway reads X-Forwarded-For itself; see mcp_security_gateway.sandbox.
            "--no-proxy-headers",
        ],
        env=env,
    )
    children = (fixture, gateway)

    def stop(signum: int, frame: object) -> None:
        for child in children:
            if child.poll() is None:
                child.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    while all(child.poll() is None for child in children):
        time.sleep(0.5)
    stop(signal.SIGTERM, None)
    for child in children:
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
    return next((child.returncode for child in children if child.returncode), 0)


if __name__ == "__main__":
    sys.exit(main())
