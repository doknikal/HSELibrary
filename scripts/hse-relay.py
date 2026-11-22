#!/usr/bin/env python3
"""HSE Library local relay: manual-proxy replacement for broken macOS PAC.

Browser -> 127.0.0.1:18080 (this relay, set as manual HTTP/HTTPS proxy).
- Hosts in the HSE PAC whitelist  -> tunneled via libtest.hse.ru:3128 with
  injected Proxy-Authorization (credentials read at startup from Keychain).
- All other hosts                 -> connected directly from this Mac.
Whitelist is parsed from the app-generated PAC and re-read on mtime change.
"""
import asyncio, base64, os, re, subprocess, sys, time

HOME = os.path.expanduser("~")
PAC = os.path.join(HOME, "Library/Application Support/HSE Library/hse-library.pac")
UP_HOST, UP_PORT = "libtest.hse.ru", 3128
LISTEN = ("127.0.0.1", 18080)
LOG = print
def log(*a): LOG(time.strftime("%H:%M:%S"), *a, flush=True)

_state = {"mtime": 0, "exact": set(), "suf": set()}

def load_list():
    try:
        m = os.stat(PAC).st_mtime
    except FileNotFoundError:
        return
    if m == _state["mtime"]:
        return
    try:
        src = open(PAC, encoding="utf-8").read()
        ex = re.search(r"var EXACT=\{(.*?)\};", src, re.S)
        sf = re.search(r"var SUF=\[(.*?)\];", src, re.S)
        _state["exact"] = set(re.findall(r'"([^"]+)"', ex.group(1))) if ex else set()
        _state["suf"] = set(re.findall(r'"([^"]+)"', sf.group(1))) if sf else set()
        _state["mtime"] = m
        log("PAC loaded:", len(_state["exact"]), "exact,", len(_state["suf"]), "suffix")
    except Exception as e:
        log("PAC parse error:", e)

def hse(host):
    load_list()
    h = host.lower().rstrip(".")
    if h in _state["exact"]:
        return True
    for s in _state["suf"]:
        if h == s or h.endswith("." + s):
            return True
    return False

def keychain():
    def run(args):
        return subprocess.run(args, capture_output=True, text=True).stdout.strip()
    dump = run(["security", "find-internet-password", "-s", UP_HOST,
                "-l", "HSE Library Proxy"])
    acct = ""
    for line in dump.splitlines():
        m = re.search(r'"acct"<blob>="(.*)"', line)
        if m:
            acct = m.group(1)
    pw = run(["security", "find-internet-password", "-s", UP_HOST,
              "-l", "HSE Library Proxy", "-w"])
    if not acct or not pw:
        sys.exit("No HSE proxy credentials in Keychain (log in via the app first)")
    tok = base64.b64encode(f"{acct}:{pw}".encode()).decode()
    return "Basic " + tok

AUTH = keychain()

async def pipe(a, b):
    try:
        while True:
            d = await a.read(65536)
            if not d:
                break
            b.write(d)
            await b.drain()
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass

async def connect_via(remote, host):
    """Open a tunnel: via HSE upstream if whitelisted, else direct. Returns (r, w) or None."""
    if hse(host):
        try:
            r, w = await asyncio.open_connection(UP_HOST, UP_PORT)
        except Exception as e:
            log("upstream fail", host, e)
            return None
        w.write(f"CONNECT {host}:{remote[1]} HTTP/1.1\r\nHost: {host}:{remote[1]}\r\n"
                f"Proxy-Authorization: {AUTH}\r\n\r\n".encode())
        await w.drain()
        line = await r.readline()
        if b" 200 " not in line:
            log("upstream CONNECT refused:", line[:60])
            try:
                w.close()
            except Exception:
                pass
            return None
        # drain remaining response headers
        while True:
            h = await r.readline()
            if h in (b"\r\n", b"", b"\n"):
                break
        return r, w
    try:
        return await asyncio.open_connection(host, remote[1])
    except Exception as e:
        log("direct fail", host, e)
        return None

async def handle(reader, writer):
    try:
        line = await asyncio.wait_for(reader.readline(), 60)
        parts = line.split()
        if len(parts) < 2:
            writer.close(); return
        method, target = parts[0].decode(errors="replace"), parts[1].decode(errors="replace")
        # drain request headers
        while True:
            h = await asyncio.wait_for(reader.readline(), 10)
            if h in (b"\r\n", b"", b"\n"):
                break
        if method == "CONNECT":
            host, _, port = target.partition(":")
            upstream = await connect_via((host, int(port or 443)), host)
            if not upstream:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                await writer.drain(); writer.close(); return
            ur, uw = upstream
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(pipe(reader, uw), pipe(ur, writer))
        elif method in ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"):
            m = re.match(r"https?://([^/:]+)(:\d+)?(/.*)", target)
            if not m:
                writer.close(); return
            host = m.group(1)
            if hse(host):
                # absolute-form via upstream with auth; simplest: deny plaintext via HSE (rare)
                writer.write(b"HTTP/1.1 403 plaintext forbidden via HSE\r\nContent-Length: 0\r\n\r\n")
                await writer.drain(); writer.close(); return
            ur, uw = await asyncio.open_connection(host, int(m.group(2)[1:]) if m.group(2) else 80)
            uw.write(f"{method} {m.group(3) or '/'} HTTP/1.1\r\nHost: {host}\r\n"
                     "Connection: close\r\n\r\n".encode())
            await uw.drain()
            await pipe(ur, writer)
        else:
            writer.close()
    except Exception as e:
        log("handler:", type(e).__name__, str(e)[:80])
        try:
            writer.close()
        except Exception:
            pass

async def main():
    load_list()
    srv = await asyncio.start_server(handle, *LISTEN, limit=1 << 20)
    log("hse-relay on %s:%s (upstream %s:%s)" % (LISTEN[0], LISTEN[1], UP_HOST, UP_PORT))
    async with srv:
        await srv.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
