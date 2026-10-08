#!/usr/bin/env python3
"""Take screenshots of the local MISP web UI for the report (headless Chrome + DevTools).

Usage: MISP_EMAIL=... MISP_PASSWORD=... python3 misp_screenshots.py
"""
import base64
import json
import os
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

import websocket

BASE = "https://localhost:8443"
OUT = Path(__file__).resolve().parents[1] / "images"
OUT.mkdir(exist_ok=True)

profile = tempfile.mkdtemp()
chrome = subprocess.Popen([
    "google-chrome", "--headless=new", "--remote-debugging-port=9333",
    "--ignore-certificate-errors", f"--user-data-dir={profile}",
    "--window-size=1440,900", "about:blank"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

for _ in range(50):
    try:
        tabs = json.load(urllib.request.urlopen("http://127.0.0.1:9333/json"))
        page = next(t for t in tabs if t["type"] == "page")
        break
    except Exception:
        time.sleep(0.2)

ws = websocket.create_connection(page["webSocketDebuggerUrl"], suppress_origin=True)
msg_id = 0


def cdp(method, **params):
    global msg_id
    msg_id += 1
    ws.send(json.dumps({"id": msg_id, "method": method, "params": params}))
    while True:
        r = json.loads(ws.recv())
        if r.get("id") == msg_id:
            return r.get("result", {})


def go(url, wait=4):
    cdp("Page.navigate", url=url)
    time.sleep(wait)


def js(expr):
    return cdp("Runtime.evaluate", expression=expr, returnByValue=True)


def shot(name, full=False):
    params = {"format": "png"}
    if full:
        m = cdp("Page.getLayoutMetrics")["cssContentSize"]
        params["clip"] = {"x": 0, "y": 0, "width": 1440,
                          "height": min(m["height"], 2400), "scale": 1}
        params["captureBeyondViewport"] = True
    data = cdp("Page.captureScreenshot", **params)["data"]
    (OUT / f"{name}.png").write_bytes(base64.b64decode(data))
    print("saved", name)


cdp("Page.enable")
cdp("Emulation.setDeviceMetricsOverride", width=1440, height=900,
    deviceScaleFactor=1, mobile=False)

go(f"{BASE}/users/login")
shot("01_misp_login")
js(f"""document.querySelector('#UserEmail').value={json.dumps(os.environ['MISP_EMAIL'])};
document.querySelector('#UserPassword').value={json.dumps(os.environ['MISP_PASSWORD'])};
document.querySelector('form').submit();""")
time.sleep(5)

go(f"{BASE}/events/index")
shot("02_misp_events_list")
for eid in (1, 2, 3):
    go(f"{BASE}/events/view/{eid}", wait=5)
    shot(f"03_misp_event_{eid}")
    js('window.scrollTo(0, 880)')
    time.sleep(1)
    shot(f"03_misp_event_{eid}_attributes")
go(f"{BASE}/attributes/index")
shot("04_misp_attributes")
go(f"{BASE}/attributes/search", wait=3)
shot("05_misp_attribute_search")

ws.close()
chrome.terminate()
