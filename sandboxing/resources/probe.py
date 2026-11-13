"""Offline child-side probes. Output booleans only, never file contents."""
import json
import os
from pathlib import Path
import socket
import sys
import urllib.error
import urllib.request

denied_file, denied_write, forbidden_port, allowed_url = sys.argv[1:]
checks = {}
try:
    with open(denied_file, 'rb') as stream:
        stream.read(1)
    checks['read_denied'] = False
except (OSError, PermissionError):
    checks['read_denied'] = True
try:
    Path(denied_write).write_text('probe')
    checks['write_denied'] = False
except (OSError, PermissionError):
    checks['write_denied'] = True
try:
    with socket.create_connection(('127.0.0.1', int(forbidden_port)), timeout=2):
        pass
    checks['direct_network_denied'] = False
except OSError:
    checks['direct_network_denied'] = True
# Force even loopback through the proxy; urllib normally bypasses it.
proxy = os.environ.get('http_proxy') or os.environ.get('HTTP_PROXY')
if proxy:
    try:
        urllib.request.proxy_bypass = lambda host: False
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy}))
        with opener.open(allowed_url, timeout=3) as response:
            checks['proxy_allowed'] = response.read(20) == b'kindred-probe'
    except Exception:
        checks['proxy_allowed'] = False
    try:
        # An exact loopback allowlist grant must not permit another listener.
        with opener.open(f'http://127.0.0.1:{forbidden_port}/', timeout=3):
            pass
        checks['proxy_denied'] = False
    except urllib.error.HTTPError as error:
        checks['proxy_denied'] = error.code == 403
    except Exception:
        checks['proxy_denied'] = False
else:
    checks['proxy_allowed'] = False
    checks['proxy_denied'] = False
print(json.dumps(checks))
