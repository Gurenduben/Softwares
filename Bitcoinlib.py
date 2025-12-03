# ======================================================
# MINI BITCOINLIB - FULL "NO BALANCE CHECKS" VERSION
# Simplified, legacy-P2PKH only
# Always builds raw transactions WITHOUT verifying:
#   - UTXOs exist
#   - UTXO value amounts
#   - address balances
#   - input/output totals
# ======================================================

import os
import hashlib
from dataclasses import dataclass
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der_canonize


# ------------------------------------------------------
# ------------------- BASE UTILITIES -------------------
# ------------------------------------------------------

def sha256(b): return hashlib.sha256(b).digest()
def ripemd160(b):
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()
def hash160(b): return ripemd160(sha256(b))
def double_sha256(b): return sha256(sha256(b))

def int_to_little_endian(value, length):
    return value.to_bytes(length, "little")

def encode_varint(i):
    if i < 0xfd: return i.to_bytes(1, "little")
    elif i < 0x10000: return b"\xfd" + i.to_bytes(2, "little")
    elif i < 0x100000000: return b"\xfe" + i.to_bytes(4, "little")
    else: return b"\xff" + i.to_bytes(8, "little")


# ------------------------------------------------------
# ------------------- BASE58 ENCODING ------------------
# ------------------------------------------------------

ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def encode_base58(b):
    n_zeros = len(b) - len(b.lstrip(b"\x00"))
    num = int.from_bytes(b, "big")
    out = []
    while num > 0:
        num, r = divmod(num, 58)
        out.append(ALPHABET[r:r+1])
    out = out[::-1] or [ALPHABET[0:1]]
    return (ALPHABET[0:1] * n_zeros + b"".join(out)).decode()

def base58check(prefix, payload):
    return encode_base58(prefix + payload + double_sha256(prefix + payload)[:4])


# ------------------------------------------------------
# ------------------- PRIVATE KEYS ---------------------
# ------------------------------------------------------

MAINNET_WIF = b"\x80"
TESTNET_WIF = b"\xef"

MAINNET_P2PKH = b"\x00"
TESTNET_P2PKH = b"\x6f"


class PrivateKey:
    def __init__(self, secret, compressed=True, testnet=True):
        self.secret = secret
        self.compressed = compressed
        self.testnet = testnet

    @classmethod
    def generate(cls, testnet=True):
        secret = int.from_bytes(os.urandom(32), "big")
        return cls(secret, compressed=True, testnet=testnet)

    def to_wif(self):
        raw = self.secret.to_bytes(32, "big")
        prefix = TESTNET_WIF if self.testnet else MAINNET_WIF
        return base58check(prefix, raw + (b"\x01" if self.compressed else b""))

    def signing_key(self):
        return SigningKey.from_secret_exponent(self.secret, curve=SECP256k1)

    def pubkey_bytes(self):
        vk = self.signing_key().verifying_key
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        return (b"\x02" if y % 2 == 0 else b"\x03") + x.to_bytes(32, "big")

    def address(self):
        h160 = hash160(self.pubkey_bytes())
        prefix = TESTNET_P2PKH if self.testnet else MAINNET_P2PKH
        return base58check(prefix, h160)


# ------------------------------------------------------
# -------------------- SCRIPT HELPERS ------------------
# ------------------------------------------------------

OP_DUP = b"\x76"
OP_HASH160 = b"\xa9"
OP_EQUALVERIFY = b"\x88"
OP_CHECKSIG = b"\xac"

def p2pkh_script_pubkey(address):
    # Minimal base58 decode
    n = 0
    for c in address.encode():
        n = n * 58 + ALPHABET.index(bytes([c]))
    full = n.to_bytes(25, "big")
    h160 = full[1:-4]

    return (
        OP_DUP + OP_HASH160 +
        b"\x14" + h160 +
        OP_EQUALVERIFY + OP_CHECKSIG
    )


# ------------------------------------------------------
# ------------------- TRANSACTION TYPES ----------------
# ------------------------------------------------------

@dataclass
class TxIn:
    txid: str
    vout: int
    script_sig: bytes = b""
    sequence: int = 0xffffffff

    def serialize(self):
        return (
            bytes.fromhex(self.txid)[::-1] +
            int_to_little_endian(self.vout, 4) +
            encode_varint(len(self.script_sig)) +
            self.script_sig +
            int_to_little_endian(self.sequence, 4)
        )

@dataclass
class TxOut:
    value: int
    script_pubkey: bytes

    def serialize(self):
        return (
            int_to_little_endian(self.value, 8) +
            encode_varint(len(self.script_pubkey)) +
            self.script_pubkey
        )

class Tx:
    def __init__(self, version, tx_ins, tx_outs, locktime=0):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime

    def serialize(self):
        r = int_to_little_endian(self.version, 4)
        r += encode_varint(len(self.tx_ins))
        for i in self.tx_ins:
            r += i.serialize()
        r += encode_varint(len(self.tx_outs))
        for o in self.tx_outs:
            r += o.serialize()
        r += int_to_little_endian(self.locktime, 4)
        return r

    def txid(self):
        return double_sha256(self.serialize())[::-1].hex()


# ------------------------------------------------------
# ------------------ SIGHASH + SIGNING -----------------
# ------------------------------------------------------

SIGHASH_ALL = 1

def sighash_preimage(tx, index, script_pubkey):
    temp_ins = []
    for i, txin in enumerate(tx.tx_ins):
        temp_ins.append(TxIn(
            txin.txid,
            txin.vout,
            script_pubkey if i == index else b"",
            txin.sequence
        ))

    temp_tx = Tx(tx.version, temp_ins, tx.tx_outs, tx.locktime)
    return temp_tx.serialize() + int_to_little_endian(SIGHASH_ALL, 4)

def sign_input(tx, index, priv, script_pubkey):
    preimage = sighash_preimage(tx, index, script_pubkey)
    h = double_sha256(preimage)
    z = int.from_bytes(h, "big")

    sig = priv.signing_key().sign_digest(
        z.to_bytes(32, "big"),
        sigencode=sigencode_der_canonize
    ) + bytes([SIGHASH_ALL])

    pub = priv.pubkey_bytes()

    tx.tx_ins[index].script_sig = (
        len(sig).to_bytes(1, "little") + sig +
        len(pub).to_bytes(1, "little") + pub
    )


# ------------------------------------------------------
# ----------- FULL NO BALANCE / NO UTXO CHECKS ---------
# ------------------------------------------------------

def get_utxos(address):
    """
    NO CHECKS MODE:
    Always return an empty list.
    This library never checks:
      - If UTXOs exist
      - If txid/vout is valid
      - How much BTC the address has
    """
    return []

def get_balance(address):
    """
    ALWAYS ZERO — NO CHECKS MODE.
    You can still build/spend ANY amount in a raw tx.
    """
    return 0


# ------------------------------------------------------
# ---------------------- EXAMPLE -----------------------
# ------------------------------------------------------

if __name__ == "__main__":
    print("MINI BITCOINLIB (NO BALANCE CHECKS)")

    pk = PrivateKey.generate(testnet=True)
    print("WIF:", pk.to_wif())
    print("Address:", pk.address())

    # Example: build a tx from ANY fake UTXO
    fake_txid = "11" * 32
    fake_vout = 0

    tx = Tx(
        1,
        [TxIn(fake_txid, fake_vout)],
        [TxOut(50000, p2pkh_script_pubkey(pk.address()))]  # spend ANY value
    )

    sign_input(tx, 0, pk, p2pkh_script_pubkey(pk.address()))

    print("RAW TX:", tx.serialize().hex())
    print("TXID:", tx.txid())
