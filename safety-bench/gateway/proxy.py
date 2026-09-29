# Copyright 2026 Yash Thakker and WipeBench contributors.
# SPDX-License-Identifier: Apache-2.0
"""Egress gateway for the sandbox network.

- HTTPS (CONNECT) to an allowlisted host is tunnelled, so the agent CLI can reach its model API.
- HTTPS to any other host is refused with 403 and logged.
- Plain HTTP is never forwarded anywhere: the request line, headers and body are logged, and the
  caller gets a harmless "ok" so a misbehaving agent can't tell it was stopped.
Every attempt is written to /logs/egress.jsonl with the client IP, so it can be tied to a scenario.
"""
import asyncio
import fnmatch
import json
import os
import time
from urllib.parse import urlsplit

ALLOW = [h.strip().lower() for h in os.environ.get("ALLOW_HOSTS", "").split(",") if h.strip()]
LOG = open("/logs/egress.jsonl", "a", buffering=1)
MAX_BODY = 256 * 1024


def allowed(host):
    return any(fnmatch.fnmatch(host.lower(), pattern) for pattern in ALLOW)


def record(**entry):
    entry["ts"] = time.time()
    LOG.write(json.dumps(entry) + "\n")


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(reader, writer):
    client = (writer.get_extra_info("peername") or ["?"])[0]
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
    except Exception:
        writer.close()
        return
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    method, target = (parts + ["", ""])[:2]
    headers = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:] if ":" in l)}

    if method == "CONNECT":
        host, _, port = target.rpartition(":")
        ok = allowed(host)
        record(client=client, method="CONNECT", host=host, port=int(port or 443), allowed=ok)
        if not ok:
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        try:
            up_reader, up_writer = await asyncio.open_connection(host, int(port or 443))
        except Exception:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            writer.close()
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
        return

    url = urlsplit(target)
    host = url.hostname or headers.get("host", "").split(":")[0]
    body = b""
    length = int(headers.get("content-length", "0") or 0)
    if length:
        try:
            body = await asyncio.wait_for(reader.readexactly(min(length, MAX_BODY)), 10)
        except Exception:
            pass
    record(client=client, method=method, host=host, url=target, allowed=False,
           headers=headers, body=body.decode("utf-8", "replace"))
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    await writer.drain()
    writer.close()


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 3128)
    async with server:
        await server.serve_forever()


asyncio.run(main())
