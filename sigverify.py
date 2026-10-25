"""Pure-stdlib public-key signature verification for Eclipse Cluster K0.

Powered by Cyan Eclipse Technologies (cetech.ai).

The verification gate must run anywhere Python runs — including hosts with
no `cryptography` package and no cosign binary — so the small set of
algorithms cosign uses for key-based image signing is implemented here
directly on Python big-integers:

  * ECDSA over NIST P-256 with SHA-256 (cosign's default key type)
  * Ed25519 (RFC 8032)
  * RSA PKCS#1 v1.5 with SHA-256

Also here: PEM / SubjectPublicKeyInfo parsing (minimal DER reader) and the
DSSE pre-auth-encoding (PAE) used by in-toto attestations.

Verification only. Nothing in this module signs; test fixtures are signed
with the system openssl binary, the same way an external signer would.
"""
import base64
import hashlib

# --------------------------------------------------------------------- DER
def _read_len(data: bytes, i: int):
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    n = first & 0x7F
    return int.from_bytes(data[i:i + n], "big"), i + n


def _read_tlv(data: bytes, i: int):
    """Return (tag, content_bytes, next_index)."""
    tag = data[i]
    i += 1
    if tag & 0x1F == 0x1F:  # multi-byte tag (not expected in SPKI, be safe)
        while data[i] & 0x80:
            i += 1
        i += 1
    length, i = _read_len(data, i)
    return tag, data[i:i + length], i + length


def _decode_oid(content: bytes) -> str:
    out = [content[0] // 40, content[0] % 40]
    val = 0
    for b in content[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            out.append(val)
            val = 0
    return ".".join(str(x) for x in out)


_OID_EC_PUBKEY = "1.2.840.10045.2.1"
_OID_P256 = "1.2.840.10045.3.1.7"
_OID_ED25519 = "1.3.101.112"
_OID_RSA = "1.2.840.113549.1.1.1"


def pem_to_der(pem: str) -> bytes:
    body = "".join(l.strip() for l in pem.splitlines()
                   if l and not l.startswith("-----"))
    return base64.b64decode(body)


def parse_public_key(pem: str) -> dict:
    """Parse a SubjectPublicKeyInfo PEM.

    Returns {"algorithm": "ecdsa-p256"|"ed25519"|"rsa", ...key material}.
    Raises ValueError on anything unsupported — callers fail closed.
    """
    der = pem_to_der(pem)
    tag, spki, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("SPKI is not a SEQUENCE")
    tag, alg_seq, i = _read_tlv(spki, 0)
    tag, oid_bytes, j = _read_tlv(alg_seq, 0)
    oid = _decode_oid(oid_bytes)
    tag, bitstr, _ = _read_tlv(spki, i)
    if bitstr[0] != 0:  # unused-bits count must be 0 for our key types
        raise ValueError("unexpected BIT STRING padding")
    pub = bitstr[1:]
    if oid == _OID_EC_PUBKEY:
        _, curve_oid_bytes, _ = _read_tlv(alg_seq, j)
        if _decode_oid(curve_oid_bytes) != _OID_P256:
            raise ValueError("only NIST P-256 EC keys are supported")
        if len(pub) != 65 or pub[0] != 0x04:
            raise ValueError("expected uncompressed P-256 point")
        return {"algorithm": "ecdsa-p256",
                "x": int.from_bytes(pub[1:33], "big"),
                "y": int.from_bytes(pub[33:65], "big")}
    if oid == _OID_ED25519:
        if len(pub) != 32:
            raise ValueError("expected 32-byte Ed25519 key")
        return {"algorithm": "ed25519", "key": pub}
    if oid == _OID_RSA:
        tag, rsa_seq, _ = _read_tlv(pub, 0)
        _, n_bytes, k = _read_tlv(rsa_seq, 0)
        _, e_bytes, _ = _read_tlv(rsa_seq, k)
        return {"algorithm": "rsa",
                "n": int.from_bytes(n_bytes, "big"),
                "e": int.from_bytes(e_bytes, "big")}
    raise ValueError(f"unsupported public key OID: {oid}")


def key_fingerprint(pem: str) -> str:
    return "sha256:" + hashlib.sha256(pem_to_der(pem)).hexdigest()


# --------------------------------------------------------------------- ECDSA P-256
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        m = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    return x3, (m * (x1 - x3) - y1) % _P


def _ec_mul(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def _ecdsa_parse_sig(sig: bytes):
    """Accept ASN.1 DER ECDSA-Sig-Value (cosign/openssl) or raw r||s."""
    if len(sig) == 64:
        return int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    tag, seq, _ = _read_tlv(sig, 0)
    if tag != 0x30:
        raise ValueError("signature is neither DER nor raw r||s")
    _, r_bytes, i = _read_tlv(seq, 0)
    _, s_bytes, _ = _read_tlv(seq, i)
    return int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")


def ecdsa_p256_verify(key: dict, message: bytes, sig: bytes) -> bool:
    try:
        r, s = _ecdsa_parse_sig(sig)
    except Exception:
        return False
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, _N)
    point = _ec_add(_ec_mul(z * w % _N, (_GX, _GY)),
                    _ec_mul(r * w % _N, (key["x"], key["y"])))
    return point is not None and point[0] % _N == r


# --------------------------------------------------------------------- Ed25519
_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_BY = (4 * pow(5, -1, _Q)) % _Q


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, -1, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = x * _I % _Q
    if x & 1:
        x = _Q - x
    return x


_B_POINT = (_ed_xrecover(_BY), _BY)


def _ed_add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    t = _D * x1 * x2 * y1 * y2 % _Q
    return ((x1 * y2 + x2 * y1) * pow(1 + t, -1, _Q) % _Q,
            (y1 * y2 + x1 * x2) * pow(1 - t, -1, _Q) % _Q)


def _ed_mul(k, point):
    result = (0, 1)
    addend = point
    while k:
        if k & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        k >>= 1
    return result


def _ed_decode_point(data: bytes):
    bits = int.from_bytes(data, "little")
    y = bits & ((1 << 255) - 1)
    x = _ed_xrecover(y)
    if (x & 1) != (bits >> 255):
        x = _Q - x
    return x, y


def _ed_encode_point(point) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_verify(key: dict, message: bytes, sig: bytes) -> bool:
    if len(sig) != 64:
        return False
    try:
        r_point = _ed_decode_point(sig[:32])
        a_point = _ed_decode_point(key["key"])
    except Exception:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + key["key"] + message).digest(),
                       "little")
    # [S]B == R + [H]A  (cofactored-less RFC 8032 verification equation)
    return _ed_mul(s, _B_POINT) == _ed_add(r_point, _ed_mul(h, a_point))


# --------------------------------------------------------------------- RSA
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_verify(key: dict, message: bytes, sig: bytes) -> bool:
    n, e = key["n"], key["e"]
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    expected_tail = _SHA256_DIGESTINFO + hashlib.sha256(message).digest()
    if not em.startswith(b"\x00\x01") or len(em) < len(expected_tail) + 11:
        return False
    sep = em.find(b"\x00", 2)
    if sep < 0 or em[2:sep] != b"\xff" * (sep - 2):
        return False
    return em[sep + 1:] == expected_tail


# --------------------------------------------------------------------- dispatch
_VERIFIERS = {"ecdsa-p256": ecdsa_p256_verify,
              "ed25519": ed25519_verify,
              "rsa": rsa_verify}


def verify_signature(key: dict, message: bytes, signature_b64: str) -> bool:
    """Verify a base64 signature under a parsed public key. Fail closed."""
    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False
    fn = _VERIFIERS.get(key.get("algorithm", ""))
    if fn is None:
        return False
    try:
        return fn(key, message, sig)
    except Exception:
        return False


# --------------------------------------------------------------------- DSSE
def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-auth-encoding for an attestation envelope payload."""
    t = payload_type.encode()
    return (b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" "
            + str(len(payload)).encode() + b" " + payload)
