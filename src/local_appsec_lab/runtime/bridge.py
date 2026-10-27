"""Standalone trusted JSON-lines bridge for private network namespaces.

Runs without this package or third-party dependencies in a preloaded runtime image.
The app receives no protocol stdin/stdout, ambient secrets, or host network access.
"""

import base64
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import threading


def main():
    command, port = json.loads(sys.argv[1]), int(sys.argv[2])
    if command[0] in {"python", "python3"}:
        command[0] = sys.executable
    logfile = open("/tmp/appsec-runtime.log", "wb")
    app = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=dict(os.environ),
        start_new_session=True,
    )

    def drain():
        remaining = 262144
        while chunk := app.stdout.read(4096):
            if remaining > 0:
                logfile.write(chunk[:remaining])
                logfile.flush()
                remaining -= len(chunk)

    threading.Thread(target=drain, daemon=True).start()
    print(json.dumps({"ready": True, "pid": app.pid}), flush=True)
    try:
        for line in sys.stdin:
            try:
                request = json.loads(line)
                if request.get("stop"):
                    break
                path = request["path"]
                if (
                    not path.startswith("/")
                    or path.startswith("//")
                    or "\r" in path
                    or "\n" in path
                ):
                    raise ValueError("Invalid path")
                timeout = min(3, max(0.01, float(request.get("timeout", 3))))
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)

                def abort(connection=connection):
                    if connection.sock:
                        try:
                            connection.sock.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        connection.close()

                timer = threading.Timer(timeout, abort)
                timer.daemon = True
                timer.start()
                try:
                    connection.request(
                        request.get("method", "GET"),
                        path,
                        body=request.get("body"),
                        headers=request.get("headers", {}),
                    )
                    response = connection.getresponse()
                    content = response.read(min(request.get("limit", 65536), 1048576) + 1)
                    print(
                        json.dumps(
                            {
                                "status": response.status,
                                "headers": dict(response.getheaders()),
                                "body": base64.b64encode(content).decode(),
                            }
                        ),
                        flush=True,
                    )
                finally:
                    timer.cancel()
                    connection.close()
            except Exception as exc:
                print(json.dumps({"error": type(exc).__name__}), flush=True)
    finally:
        try:
            os.killpg(app.pid, signal.SIGTERM)
            app.wait(timeout=3)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            if app.poll() is None:
                os.killpg(app.pid, signal.SIGKILL)
                app.wait()
        logfile.close()


if __name__ == "__main__":
    main()
