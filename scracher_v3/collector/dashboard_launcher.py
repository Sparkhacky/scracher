import subprocess
import socket
import time

def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        return s.connect_ex((host, port)) == 0

def start_dashboard(host="127.0.0.1", port=8000) -> subprocess.Popen | None:
    if _port_open(host, port):
        return None

    p = subprocess.Popen(
        ["python3", "-m", "uvicorn", "dashboard.app:app", "--host", host, "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    for _ in range(60):
        if _port_open(host, port):
            break
        time.sleep(0.1)

    return p
