"""Multi-protocol N-modality feature families (benchmark framing).

Extends the P0-A ``body`` representation (plaintext HTTP tool text) to the full
protocol space. Each family is generated from the multi-protocol summary produced
by ``scripts.n_protocol_extract.extract_session_full`` and can be emitted either as
a token document (char n-gram hashing, aligned with T/E) or as a numeric vector
(DictVectorizer), so a screening run can score each family's benign-vs-attempt
discriminative power independently.

Families
--------
  tls_fingerprint  ClientHello JA3 + SNI + cipher suites + extensions + supported
                   groups/versions + ALPN; ServerHello selected suite/version;
                   leaf certificate subject/issuer/SAN. The *only* N signal in an
                   encrypted scenario (payload is ciphertext).
  dns              Queried names / types / classes, response flag. The only N
                   signal in a no-tool (pure text) scenario.
  topology         Connection topology: endpoint (ip:port) tuples, flow counts,
                   protocol mix. Independent of payload semantics and of agent
                   attribution (no application_role / llm_api / tool_http labels).
  timing           Flow durations, inter-arrival gaps, handshake-phase timing,
                   request count. A payload-free side channel.
  handshake        TLS handshake mode: message-type sequence, TLS 1.2 vs 1.3,
                   full vs resumed handshake, record-size profile.

``tls_fingerprint`` / ``dns`` are inherently token-based (they carry identity
semantics); ``topology`` / ``timing`` / ``handshake`` are numeric and are
returned as dicts. Both views are provided for every family that supports them.
"""
import collections
import json
from pathlib import Path

import sys
_SCRIPTS = str(Path(__file__).resolve().parents[1] / 'scripts')
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

from n_protocol_extract import extract_session_full

FAMILIES = ('tls_fingerprint', 'dns', 'topology', 'timing', 'handshake')

TOKEN_FAMILIES = ('tls_fingerprint', 'dns')
NUMERIC_FAMILIES = ('topology', 'timing', 'handshake')


# ---------------------------------------------------------------------------
# token documents
# ---------------------------------------------------------------------------
def _tls_token_doc(summary):
    lines = []
    for t in summary.get('tls', []):
        ch = t.get('client_hello') or {}
        sh = t.get('server_hello') or {}
        parts = []
        if t.get('dport') is not None:
            parts.append('[TLS_DPORT=%s]' % t['dport'])
        if ch.get('ja3'):
            parts.append('[TLS_JA3=%s]' % ch['ja3'])
        if ch.get('sni'):
            parts.append('[TLS_SNI=%s]' % ch['sni'])
        if ch.get('supported_versions'):
            parts.append('[TLS_VER=%s]' % ','.join(ch['supported_versions']))
        if ch.get('alpn'):
            parts.append('[TLS_ALPN=%s]' % ','.join(ch['alpn']))
        for c in ch.get('cipher_suites', [])[:16]:
            parts.append('[TLS_CIPHER=%d]' % c)
        for g in ch.get('supported_groups', [])[:8]:
            parts.append('[TLS_GROUP=%d]' % g)
        if sh.get('cipher_suite') is not None:
            parts.append('[TLS_SRV_CIPHER=%d]' % sh['cipher_suite'])
        if sh.get('selected_version'):
            parts.append('[TLS_SRV_VER=%s]' % sh['selected_version'])
        for cert in t.get('certificates', [])[:1]:
            if cert.get('subject_cn'):
                parts.append('[TLS_CERT_CN=%s]' % cert['subject_cn'])
            for san in cert.get('san_dns', [])[:8]:
                parts.append('[TLS_SAN=%s]' % san)
        lines.append(' '.join(parts))
    return '\n'.join(lines)


def _dns_token_doc(summary):
    lines = []
    for d in summary.get('dns', []):
        for q in d.get('questions', []):
            name = q.get('name')
            if name:
                lines.append('[DNS=%s][DNSTYPE=%s][DNSRESP=%s]' %
                             (name, q.get('type'), 1 if d.get('is_response') else 0))
    return '\n'.join(lines)


def _topology_token_doc(summary):
    parts = []
    for f in summary.get('flows', []):
        ep = '%s:%s' % (f.get('dst'), f.get('dport'))
        parts.append('[ENDPT=%s]' % ep)
    return '\n'.join(parts)


def token_document(summary, family):
    if family == 'tls_fingerprint':
        return _tls_token_doc(summary)
    if family == 'dns':
        return _dns_token_doc(summary)
    if family == 'topology':
        return _topology_token_doc(summary)
    if family in ('timing', 'handshake'):
        return json.dumps(numeric_vector(summary, family), sort_keys=True, ensure_ascii=False)
    raise ValueError('Unknown family: ' + family)


def combined_token_document(summary):
    docs = []
    for fam in TOKEN_FAMILIES:
        docs.append(token_document(summary, fam))
    return '\n'.join(docs)


# ---------------------------------------------------------------------------
# numeric vectors
# ---------------------------------------------------------------------------
def _topology_vector(summary):
    ports = collections.Counter()
    protos = collections.Counter()
    for f in summary.get('flows', []):
        ports[str(f.get('dport'))] += 1
        protos[f.get('protocol', '?')] += 1
    v = {'n_flows': len(summary.get('flows', []))}
    for p, n in ports.items():
        v['port_' + p] = n
    for p, n in protos.items():
        v['proto_' + p] = n
    return v


def _timing_vector(summary):
    flows = summary.get('flows', [])
    rels = [f.get('relative_timestamp') for f in flows if f.get('relative_timestamp') is not None]
    v = {'n_flows': len(flows)}
    if rels:
        rels = sorted(rels)
        v['flow_span'] = rels[-1] - rels[0]
        if len(rels) > 1:
            gaps = [b - a for a, b in zip(rels, rels[1:])]
            v['flow_mean_iat'] = sum(gaps) / len(gaps)
            v['flow_max_iat'] = max(gaps)
    # TLS handshake phase: count full vs resumed (no ClientHello == resumed)
    full = 0
    resumed = 0
    for t in summary.get('tls', []):
        if t.get('client_hello'):
            full += 1
        else:
            resumed += 1
    v['tls_full_handshakes'] = full
    v['tls_resumed_handshakes'] = resumed
    return v


def _handshake_vector(summary):
    hs = collections.Counter()
    tls13 = 0
    tls12 = 0
    alpn = collections.Counter()
    for t in summary.get('tls', []):
        for mtype in t.get('handshake_types', []):
            hs[str(mtype)] += 1
        ch = t.get('client_hello') or {}
        if ch.get('supported_versions'):
            if '0304' in ch['supported_versions']:
                tls13 += 1
            elif '0303' in ch['supported_versions']:
                tls12 += 1
        for a in ch.get('alpn', []):
            alpn[a] += 1
    v = {'hs_clienthello': hs.get('1', 0), 'hs_serverhello': hs.get('2', 0),
         'hs_certificate': hs.get('11', 0), 'hs_finished': hs.get('20', 0),
         'tls13_hellos': tls13, 'tls12_hellos': tls12}
    for a, n in alpn.items():
        v['alpn_' + a] = n
    return v


def numeric_vector(summary, family):
    if family == 'topology':
        return _topology_vector(summary)
    if family == 'timing':
        return _timing_vector(summary)
    if family == 'handshake':
        return _handshake_vector(summary)
    raise ValueError('No numeric vector for family: ' + family)


# ---------------------------------------------------------------------------
# session-level entry point
# ---------------------------------------------------------------------------
def extract(folder, n_events):
    """Return the full multi-protocol summary for a session folder."""
    return extract_session_full(folder, n_events)


def family_views(summary):
    """Return {'token': {family: doc}, 'numeric': {family: dict}} for a summary."""
    token = {fam: token_document(summary, fam) for fam in TOKEN_FAMILIES}
    token['topology'] = _topology_token_doc(summary)
    numeric = {fam: numeric_vector(summary, fam) for fam in NUMERIC_FAMILIES}
    return {'token': token, 'numeric': numeric}
