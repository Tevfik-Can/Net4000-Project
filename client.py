# client.py
from turtledemo.penrose import start

import requests
import time
import csv
from datetime import datetime

SERVER_URL = "http://127.0.0.1:8080"
REQUEST_INTERVAL_MS = 100
TIMEOUT_MS = 500

metrics = []
request_id = 0

while True:
    request_id += 1
    start = time.time()

    try:
        response = requests.get(
            SERVER_URL,
            timeout=TIMEOUT_MS / 1000.0
        )
        end = time.time()
        latency_ms = (end - start) * 1000

        result = "success" if response.status_code == 200 else "http_error"

    except requests.exceptions.Timeout:
        end = time.time()
        latency_ms = (end - start) * 1000
        result = "timeout"

    except Exception:
        end = time.time()
        latency_ms = (end - start) * 1000
        result = "error"
    metric = {
            "request_id": request_id,
            "start_time": start,
            "end_time": end,
            "latency_ms": latency_ms,
            "result": result
        }
    metrics.append(metric)

    time.sleep(REQUEST_INTERVAL_MS / 1000.0)
    if request_id == 10:
        break

print(metrics)