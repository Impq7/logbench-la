"""TLS exfiltration sink for the split-container benchmark.

Runs in a dedicated ``receiver`` container on the isolated business network. The
backend's external-send tools (``post_webpage`` / ``send_email`` /
``send_direct_message`` / ``send_channel_message`` / ``send_money`` /
``schedule_transaction``) open a real HTTPS connection here (port 443) with the
ClientHello SNI set to the exfiltration target domain. The receiver only completes
the TLS handshake and absorbs the request, so the network modality records an
encrypted exfiltration connection (SNI + traffic volume) without ever exposing
plaintext payload to any observable projection.

The receiver is a passive network sink: it does NOT participate in the oracle and
its output never enters model inputs. stdout carries a single readiness line; each
accepted request is logged (byte count and completeness only) to stderr for QA.

Self-signed certificate is generated once at startup with openssl into the /tmp
tmpfs; the client does not verify it, so its exact content is irrelevant.
"""
import json
import os
import socket
import ssl
import subprocess
import sys
import threading

HOST = '0.0.0.0'
PORT = 443
CERT_DIR = '/tmp/exfil-receiver'


def ensure_certificate():
    os.makedirs(CERT_DIR, exist_ok=True)
    cert = os.path.join(CERT_DIR, 'cert.pem')
    key = os.path.join(CERT_DIR, 'key.pem')
    if not (os.path.exists(cert) and os.path.exists(key)):
        subprocess.run(
            ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
             '-keyout', key, '-out', cert, '-days', '3650',
             '-subj', '/CN=exfil-receiver.local'],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


def read_request(conn):
    """Return (received bytes, complete); EOF/timeout is not proof of delivery."""
    conn.settimeout(2)
    data = b''
    received = 0
    try:
        while b'\r\n\r\n' not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return received, False
            data += chunk
            received += len(chunk)
        head, _, rest = data.partition(b'\r\n\r\n')
        cl = None
        for line in head.split(b'\r\n'):
            if line.lower().startswith(b'content-length:'):
                try:
                    cl = int(line.split(b':', 1)[1].strip())
                except ValueError:
                    return received, False
        if cl is None or cl < 0:
            return received, False
        body_bytes = len(rest)
        while body_bytes < cl:
            chunk = conn.recv(4096)
            if not chunk:
                break
            received += len(chunk)
            body_bytes += len(chunk)
        return received, body_bytes >= cl
    except (socket.timeout, ssl.SSLError, OSError):
        return received, False


def main():
    cert, key = ensure_certificate()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, PORT))
    listener.listen(16)
    print(json.dumps({'kind': 'receiver_ready', 'host': HOST, 'port': PORT}), flush=True)
    count = 0
    while True:
        try:
            raw, addr = listener.accept()
        except OSError:
            break
        count += 1

        def handle(raw=raw, addr=addr, n=count):
            try:
                tls = context.wrap_socket(raw, server_side=True)
                nbytes, complete = read_request(tls)
                # Log before the response so sender completion cannot race this evidence.
                sys.stderr.write(json.dumps({'event': 'exfil_received', 'peer': list(addr),
                    'bytes': nbytes, 'complete': complete, 'n': n}) + '\n')
                sys.stderr.flush()
                try:
                    tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
                except (ssl.SSLError, OSError):
                    pass
            except (ssl.SSLError, OSError, socket.timeout):
                pass
            finally:
                try:
                    raw.close()
                except OSError:
                    pass

        threading.Thread(target=handle, daemon=True).start()


if __name__ == '__main__':
    main()
