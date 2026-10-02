#!/usr/bin/env python3
"""Known-answer vectors for Clustor's v1 sealed records: one WAL frame
and one snapshot chunk per AEAD suite, computed with pyca/cryptography —
an implementation independent of both the Fluxor vault and Clustor's
codec.

`tests/sealed_records.rs` pins these bytes. Regenerate with
`python3 tools/sealed_record_vectors.py` and paste the output there only
when the inputs below change; the format itself never does.
"""

import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MASTER = bytes(range(32))
CLUSTER = b"clustor-kat-0001"
PARTITION = 3
REPLICA = 2
EPOCH = 7

WAL_INCARNATION = bytes(range(0xA0, 0xB0))
WAL_SEGMENT = 5
WAL_SEQ = 9
WAL_TERM = 17
WAL_INDEX = 42
WAL_ENTRY = b"sealed wal entry"

SNAP_GENERATION = bytes(range(0xB0, 0xC0))
SNAP_LAST_TERM = 5
SNAP_LAST_INDEX = 1000
SNAP_MEMBERSHIP = bytes([0x07, 0x00, 0x08])  # voters 0-2, no joint set, learner 3
SNAP_CHUNK = 0
SNAP_FLAGS = 1
SNAP_BODY = b"snapshot chunk body"


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def derive(label: bytes, context: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"fluxor/v1", info=label + context
    ).derive(MASTER)


def seal(suite: int, key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
    aead = ChaCha20Poly1305(key) if suite == 1 else AESGCM(key)
    return aead.encrypt(nonce, pt, aad)  # ciphertext ‖ tag


def wal_frame(suite: int):
    ctx = (
        CLUSTER
        + struct.pack("<QQI", PARTITION, REPLICA, EPOCH)
        + WAL_INCARNATION
    )
    key = derive(b"clustor/wal", ctx)
    pt = struct.pack("<QQ", WAL_TERM, WAL_INDEX) + WAL_ENTRY
    c = len(pt)
    nonce = b"WAL0" + struct.pack("<Q", WAL_SEQ)
    aad = (
        CLUSTER
        + struct.pack("<QQQ", PARTITION, REPLICA, WAL_SEGMENT)
        + WAL_INCARNATION
        + struct.pack("<IQII", EPOCH, WAL_SEQ, c, c)
    )
    sealed = seal(suite, key, nonce, aad, pt)
    head = (
        bytes([0xA5, 0, 0, 0])
        + struct.pack("<II", c + 52, EPOCH)
        + WAL_INCARNATION
        + struct.pack("<QI", WAL_SEQ, c)
    )
    body = head + sealed
    return key, body + struct.pack("<I", crc32c(body))


def snap_chunk(suite: int):
    ctx = CLUSTER + struct.pack("<Q", PARTITION) + SNAP_GENERATION + struct.pack("<I", EPOCH)
    key = derive(b"clustor/snapshot", ctx)
    pt = SNAP_BODY
    nonce = b"SNP0" + struct.pack("<Q", SNAP_CHUNK)
    aad = (
        CLUSTER
        + struct.pack("<QQ", PARTITION, REPLICA)
        + SNAP_GENERATION
        + struct.pack("<QQ", SNAP_LAST_TERM, SNAP_LAST_INDEX)
        + SNAP_MEMBERSHIP
        + struct.pack("<IQB", EPOCH, SNAP_CHUNK, SNAP_FLAGS)
        + struct.pack("<I", len(pt))
    )
    sealed = seal(suite, key, nonce, aad, pt)
    head = (
        b"FXSC"
        + struct.pack("<I", EPOCH)
        + SNAP_GENERATION
        + struct.pack("<QB", SNAP_CHUNK, SNAP_FLAGS)
        + bytes(3)
        + struct.pack("<I", len(pt))
    )
    return key, head + sealed


def main() -> None:
    for suite, name in ((1, "CHACHA"), (2, "AES")):
        key, frame = wal_frame(suite)
        print(f'const WAL_KEY_{name}: &str = "{key.hex()}";')
        print(f'const WAL_FRAME_{name}: &str = "{frame.hex()}";')
        key, chunk = snap_chunk(suite)
        print(f'const SNAP_KEY_{name}: &str = "{key.hex()}";')
        print(f'const SNAP_CHUNK_{name}: &str = "{chunk.hex()}";')


if __name__ == "__main__":
    main()
