#!/usr/bin/env python3
"""回环 TCP HTTP 假后端（正向代理探测用）：回 200 TCP_PONG。

用法: tcp_backend.py <port>
"""
import socket
import sys
from datetime import datetime

port = int(sys.argv[1])
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(8)
print(f"START tcp_backend port={port} at={datetime.now()}", flush=True)
while True:
    conn, _ = srv.accept()
    try:
        conn.recv(65536)
        body = b"TCP_PONG\n"
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() +
            b"\r\nConnection: close\r\n\r\n" + body)
    except Exception as e:  # noqa: BLE001
        print("ERR", e, flush=True)
    finally:
        conn.close()
