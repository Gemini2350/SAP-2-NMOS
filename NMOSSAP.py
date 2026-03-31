#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import threading
import time
import uuid
import json
import hashlib
import requests
import signal
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

# ---------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------

PORT = 8085
SAP_GROUP = "239.255.255.255"
SAP_PORT = 9875
STREAM_TIMEOUT = 60
HB_INTERVAL = 5

# ---------------------------------------------------------------------
# GLOBAL STATE
# ---------------------------------------------------------------------

NODE = {}
DEVICE = {}
SOURCES = {}
FLOWS = {}
SENDERS = {}
STREAMS = {}

REGISTRAR_URL = None
NODE_ID = None
DEVICE_ID = None

RUNNING = True
server = None

# CACHE
SENDER_CACHE = []
CACHE_TS = 0
CACHE_TTL = 10

# ---------------------------------------------------------------------
# UTILS
# ---------------------------------------------------------------------

def gen_id():
    return str(uuid.uuid4())

def now_ts():
    ns = int(time.time_ns())
    return f"{ns // 1_000_000_000}:{ns % 1_000_000_000}"

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def hash_sdp(s):
    return hashlib.sha256(s.encode()).hexdigest()

# ---------------------------------------------------------------------
# QUERY API (CACHE + PAGING)
# ---------------------------------------------------------------------

def fetch_all_senders():
    all_senders = []

    try:
        query_url = REGISTRAR_URL.replace("registration", "query")

        limit = 100
        until = None

        while True:
            url = f"{query_url}/senders?paging.limit={limit}&paging.order=update"

            if until:
                url += f"&paging.until={until}"

            print(f"[QUERY] GET {url}")

            r = requests.get(url, timeout=2)

            if r.status_code != 200:
                print("[QUERY] ERROR", r.status_code, r.text)
                break

            data = r.json()
            print(f"[QUERY] got {len(data)} senders")

            if not data:
                break

            for s in data:
                print(f"  -> ID={s.get('id')} LABEL='{s.get('label')}'")

            all_senders.extend(data)

            link = r.headers.get("Link")

            if not link or 'rel="next"' not in link:
                break

            try:
                next_part = link.split(";")[0].strip("<>")
                if "paging.until=" in next_part:
                    until = next_part.split("paging.until=")[1]
                else:
                    break
            except:
                break

        print(f"[QUERY] TOTAL cached senders: {len(all_senders)}")

    except Exception as e:
        print("[QUERY] EXCEPTION", e)

    return all_senders


def get_existing_senders():
    global SENDER_CACHE, CACHE_TS

    now = time.time()

    if now - CACHE_TS > CACHE_TTL:
        print("[CACHE] refresh sender cache")
        SENDER_CACHE = fetch_all_senders()
        CACHE_TS = now
    else:
        print("[CACHE] using cached senders")

    return SENDER_CACHE


def find_existing_sender(sdp):
    parsed = parse_sdp(sdp)
    name = parsed.get("name")

    print(f"[MATCH] SDP name = '{name}'")

    if not name:
        return None

    senders = get_existing_senders()

    for s in senders:
        label = s.get("label")
        print(f"[MATCH] compare '{name}' == '{label}'")

        if label == name:
            print(f"[MATCH] FOUND sender {s['id']}")
            return s

    print("[MATCH] no existing sender found")
    return None

# ---------------------------------------------------------------------
# SDP PARSER
# ---------------------------------------------------------------------

def parse_sdp(sdp):
    data = {}

    for l in sdp.splitlines():
        if l.startswith("s="):
            data["name"] = l[2:].strip()

        elif l.startswith("c=IN IP4"):
            data["ip"] = l.split()[2].split("/")[0]

        elif l.startswith("m=audio"):
            data["port"] = int(l.split()[1])

        elif "rtpmap" in l and "L" in l:
            p = l.split("L")[1].split("/")
            data["bit"] = int(p[0])
            data["rate"] = int(p[1])
            if len(p) > 2:
                data["ch"] = int(p[2])

    return data

# ---------------------------------------------------------------------
# NMOS BUILDERS
# ---------------------------------------------------------------------

def build_node(node_id):
    ip = get_ip()
    return {
        "id": node_id,
        "version": now_ts(),
        "label": "SAP Auto Node",
        "description": "SAP Auto-discovered Node",
        "tags": {},
        "href": f"http://{ip}:{PORT}/x-nmos/node/v1.3/",
        "hostname": "sap-auto",
        "api": {
            "versions": ["v1.3"],
            "endpoints": [{
                "host": ip,
                "port": PORT,
                "protocol": "http"
            }]
        },
        "caps": {},
        "services": [],
        "clocks": [{"name": "clk0", "ref_type": "internal"}],
        "interfaces": [{
            "name": "eth0",
            "chassis_id": "00-00-00-00-00-00",
            "port_id": "00-00-00-00-00-00"
        }]
    }

def build_device(device_id, node_id):
    ip = get_ip()
    return {
        "id": device_id,
        "version": now_ts(),
        "label": "SAP Device",
        "description": "Auto-discovered device",
        "tags": {},
        "type": "urn:x-nmos:device:generic",
        "node_id": node_id,
        "senders": [],
        "receivers": [],
        "controls": [{
            "href": f"http://{ip}:{PORT}/x-nmos/connection/v1.1/",
            "type": "urn:x-nmos:control:sr-ctrl/v1.1"
        }]
    }

def build_source(id, device_id, sdp):
    p = parse_sdp(sdp)
    name = p.get("name", f"SAP Source {id[:4]}")
    ch = p.get("ch", 2)

    return {
        "id": id,
        "version": now_ts(),
        "label": name,
        "description": "SAP discovered source",
        "tags": {},
        "device_id": device_id,
        "format": "urn:x-nmos:format:audio",
        "grain_rate": {"numerator": 25, "denominator": 1},
        "clock_name": "clk0",
        "channels": [{"label": f"Ch{i}"} for i in range(ch)],
        "parents": [],
        "caps": {}
    }

def build_flow(id, source_id, device_id, sdp):
    p = parse_sdp(sdp)
    name = p.get("name", f"SAP Flow {id[:4]}")

    return {
        "id": id,
        "version": now_ts(),
        "label": name,
        "description": "SAP flow",
        "tags": {},
        "device_id": device_id,
        "source_id": source_id,
        "format": "urn:x-nmos:format:audio",
        "media_type": "audio/L24",
        "bit_depth": p.get("bit", 24),
        "grain_rate": {"numerator": 25, "denominator": 1},
        "sample_rate": {"numerator": p.get("rate", 48000), "denominator": 1},
        "parents": []
    }

def build_sender(id, flow_id, device_id, sdp):
    p = parse_sdp(sdp)
    name = p.get("name", f"SAP Sender {id[:4]}")
    ip = get_ip()

    return {
        "id": id,
        "version": now_ts(),
        "label": name,
        "description": "SAP sender",
        "tags": {},
        "device_id": device_id,
        "flow_id": flow_id,
        "transport": "urn:x-nmos:transport:rtp.mcast",
        "manifest_href": f"http://{ip}:{PORT}/x-manifest/senders/{id}/manifest",
        "interface_bindings": ["eth0"],
        "subscription": {"active": True, "receiver_id": None}
    }

# ---------------------------------------------------------------------
# REGISTRATION
# ---------------------------------------------------------------------

def post(reg, t, d):
    try:
        r = requests.post(f"{reg}/resource", json={"type": t, "data": d}, timeout=2)
        if r.status_code not in (200, 201):
            print(f"[{t}] ERROR {r.status_code}: {r.text}")
            return False
        else:
            print(f"[{t}] OK")
            return True
    except Exception as e:
        print(f"[{t}] EXCEPTION {e}")
        return False

def register_all():
    print("[RE-REGISTER]")
    post(REGISTRAR_URL, "node", NODE)
    post(REGISTRAR_URL, "device", DEVICE)

# ---------------------------------------------------------------------
# HEARTBEAT
# ---------------------------------------------------------------------

def heartbeat():
    while RUNNING:
        try:
            r = requests.post(f"{REGISTRAR_URL}/health/nodes/{NODE_ID}", timeout=2)
            if r.status_code != 200:
                print("[HB] FAIL → re-register")
                register_all()
            else:
                print("[HB] OK")
        except:
            print("[HB] LOST → re-register")
            register_all()

        time.sleep(HB_INTERVAL)

# ---------------------------------------------------------------------
# WEB SERVER
# ---------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.rstrip("/")

        if path == "/x-nmos/node/v1.3":
            return self.send_json(["self","devices","sources","flows","senders"])
        if path == "/x-nmos/node/v1.3/self":
            return self.send_json(NODE)
        if path == "/x-nmos/node/v1.3/devices":
            return self.send_json([DEVICE])
        if path == "/x-nmos/node/v1.3/sources":
            return self.send_json(list(SOURCES.values()))
        if path == "/x-nmos/node/v1.3/flows":
            return self.send_json(list(FLOWS.values()))
        if path == "/x-nmos/node/v1.3/senders":
            return self.send_json(list(SENDERS.values()))

        for s in STREAMS.values():
            if path.endswith(f"/senders/{s['sender_id']}/manifest"):
                self.send_response(200)
                self.send_header("Content-Type", "application/sdp")
                self.end_headers()
                self.wfile.write(s["sdp"].encode())
                return

        self.send_response(404)
        self.end_headers()

    def send_json(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

# ---------------------------------------------------------------------
# SAP LISTENER
# ---------------------------------------------------------------------

def extract_sdp(data):
    marker = b"application/sdp\x00"
    idx = data.find(marker)
    if idx == -1:
        return None
    return data[idx + len(marker):].decode(errors="ignore")

def register_stream(sdp):
    h = hash_sdp(sdp)

    if h in STREAMS:
        STREAMS[h]["last"] = time.time()
        return

    existing = find_existing_sender(sdp)
    if existing:
        print("[SENDER] reuse", existing["id"])
        STREAMS[h] = {
            "sdp": sdp,
            "sender_id": existing["id"],
            "last": time.time()
        }
        return

    sid = gen_id()
    fid = gen_id()
    seid = gen_id()

    STREAMS[h] = {"sdp": sdp, "sender_id": seid, "last": time.time()}

    SOURCES[sid] = build_source(sid, DEVICE_ID, sdp)
    FLOWS[fid] = build_flow(fid, sid, DEVICE_ID, sdp)
    SENDERS[seid] = build_sender(seid, fid, DEVICE_ID, sdp)

    if seid not in DEVICE["senders"]:
        DEVICE["senders"].append(seid)

    DEVICE["version"] = now_ts()

    post(REGISTRAR_URL, "source", SOURCES[sid])
    post(REGISTRAR_URL, "flow", FLOWS[fid])
    post(REGISTRAR_URL, "sender", SENDERS[seid])
    post(REGISTRAR_URL, "device", DEVICE)

def sap_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except:
        pass

    sock.bind(("0.0.0.0", SAP_PORT))

    mreq = struct.pack("4sl", socket.inet_aton(SAP_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print("[SAP] listening...")

    while RUNNING:
        data, _ = sock.recvfrom(2048)
        sdp = extract_sdp(data)
        if sdp:
            register_stream(sdp)

# ---------------------------------------------------------------------
# SHUTDOWN
# ---------------------------------------------------------------------

def shutdown(sig, frame):
    global RUNNING
    print("\n[SHUTDOWN] stopping...")

    RUNNING = False

    try:
        server.shutdown()
    except:
        pass

    print("[SHUTDOWN] done")
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------

def main():
    global NODE, DEVICE, REGISTRAR_URL, NODE_ID, DEVICE_ID, server

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--registrar", required=True)
    args = parser.parse_args()

    REGISTRAR_URL = args.registrar

    NODE_ID = gen_id()
    DEVICE_ID = gen_id()

    NODE = build_node(NODE_ID)
    DEVICE = build_device(DEVICE_ID, NODE_ID)

    print("[INIT]", NODE_ID, DEVICE_ID)

    register_all()

    server = HTTPServer(("", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    threading.Thread(target=heartbeat, daemon=True).start()

    sap_listener()

if __name__ == "__main__":
    main()