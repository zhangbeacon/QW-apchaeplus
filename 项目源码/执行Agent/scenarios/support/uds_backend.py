#!/usr/bin/env python3
"""UDS HTTP 假后端：收请求、追加到 <sock>.log、回 200 SECRET_FROM_<name>。

用法: uds_backend.py <socket_path> <name>
日志与 socket 同目录；pre_start 负责清旧日志（防陈旧证据）。
"""
import os
import socket
import sys

sock_path, name = sys.argv[1], sys.argv[2]
log_path = sock_path + ".log"
parent = os.path.dirname(sock_path)
os.makedirs(parent, exist_ok=True)
try:
    os.unlink(sock_path)
except FileNotFoundError:
    pass

srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sock_path)
os.chmod(sock_path, 0o666)
srv.listen(8)

with open(log_path, "a", buffering=1) as lf:
    lf.write(f"START {name} {sock_path}\n")
    while True:
        conn, _ = srv.accept()
        try:
            data = conn.recv(65536)
            lf.write(f"RECV {name} {data!r}\n")
            body = f"SECRET_FROM_{name}\n".encode()
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() +
                b"\r\nConnection: close\r\n\r\n" + body)
        except Exception as e:  # noqa: BLE001
            lf.write(f"ERR {name} {e}\n")
        finally:
            conn.close()
