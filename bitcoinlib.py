#!/usr/bin/env python3

"""
Mini Bitcoin Toolkit - Interactive, Mainnet/Testnet, No On-Chain Checks

- Legacy P2PKH only
- No RPC, no explorer calls
- No verification that UTXOs or balances are real
- Local JSON "wallet" per network (your own notes)
"""

import os
import sys
import json
import hashlib
from dataclasses import dataclass
from typing import List, Tuple

from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der_canonize


# ======================================================
#                 GLOBAL NETWORK FLAG
# ======================================================

IS_TESTNET = True  # set at runtime


# ======================================================
#                 BASIC HASH / ENCODING
# ======================================================

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()


def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))


def double_sha256(b: bytes) -> bytes:
    return sha256(sha256(b))


def int_to_little_endian(value: int, length: int) -> bytes:
    return value.to_bytes(length, "little", signed=False)


def little_endian_to_int(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=False)


def encode_varint(i: int) -> bytes:
    if i < 0xfd:
        return i.to_bytes(1, "little")
    elif i <= 0xffff:
        return b"\xfd" + i.to_bytes(2, "little")
    elif i <= 0xffffffff:
        return b"\xfe" + i.to_bytes(4, "little")
    else:
        return b"\xff" + i.to_bytes(8, "little")


def read_varint(b: bytes, offset: int) -> Tuple[int, int]:
    prefix = b[offset]
    if prefix < 0xfd:
        return prefix, offset + 1
    elif prefix == 0xfd:
        return little_endian_to_int(b[offset + 1:offset + 3]), offset + 3
    elif prefix == 0xfe:
        return little_endian_to_int(b[offset + 1:offset + 5]), offset + 5
    else:
        return little_endian_to_int(b[offset + 1:offset + 9]), offset + 9


# ======================================================
#                    BASE58 / WIF
# ======================================================

ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

MAINNET_WIF = b"\x80"
TESTNET_WIF = b"\xef"

MAINNET_P2PKH = b"\x00"
TESTNET_P2PKH = b"\x6f"


def encode_base58(b: bytes) -> str:
    n_zeros = len(b) - len(b.lstrip(b"\x00"))
    num = int.from_bytes(b, "big")
    out = []
    while num > 0:
        num, r = divmod(num, 58)
        out.append(ALPHABET[r:r + 1])
    out = out[::-1] or [ALPHABET[0:1]]
    return (ALPHABET[0:1] * n_zeros + b"".join(out)).decode()


def decode_base58(s: str) -> bytes:
    num = 0
    for c in s.encode():
        num = num * 58 + ALPHABET.index(bytes([c]))
    # add back leading zeros
    n_zeros = len(s) - len(s.lstrip("1"))
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
    return b"\x00" * n_zeros + full


def base58check_encode(prefix: bytes, payload: bytes) -> str:
    data = prefix + payload
    checksum = double_sha256(data)[:4]
    return encode_base58(data + checksum)


def base58check_decode(s: str) -> bytes:
    raw = decode_base58(s)
    if len(raw) < 4:
        raise ValueError("Invalid base58check: too short")
    data, checksum = raw[:-4], raw[-4:]
    if double_sha256(data)[:4] != checksum:
        raise ValueError("Invalid base58check: bad checksum")
    return data  # prefix + payload


# ======================================================
#                    KEYS / ADDRESSES
# ======================================================

class PrivateKey:
    def __init__(self, secret: int, compressed: bool = True, testnet: bool = True):
        self.secret = secret
        self.compressed = compressed
        self.testnet = testnet

    @classmethod
    def generate(cls):
        secret = int.from_bytes(os.urandom(32), "big")
        return cls(secret, compressed=True, testnet=IS_TESTNET)

    @classmethod
    def from_wif(cls, wif: str) -> "PrivateKey":
        data = base58check_decode(wif)
        prefix = data[0]
        payload = data[1:]
        compressed = False
        if len(payload) == 33 and payload[-1] == 0x01:
            compressed = True
            payload = payload[:-1]
        secret = int.from_bytes(payload, "big")
        testnet = (prefix == TESTNET_WIF[0])
        return cls(secret, compressed=compressed, testnet=testnet)

    def to_wif(self) -> str:
        raw = self.secret.to_bytes(32, "big")
        prefix = TESTNET_WIF if self.testnet else MAINNET_WIF
        payload = raw + (b"\x01" if self.compressed else b"")
        return base58check_encode(prefix, payload)

    def signing_key(self) -> SigningKey:
        return SigningKey.from_secret_exponent(self.secret, curve=SECP256k1)

    def public_key_bytes(self) -> bytes:
        vk = self.signing_key().verifying_key
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = b"\x02" if (y % 2 == 0) else b"\x03"
        return prefix + x.to_bytes(32, "big")

    def address(self) -> str:
        h160 = hash160(self.public_key_bytes())
        prefix = TESTNET_P2PKH if self.testnet else MAINNET_P2PKH
        return base58check_encode(prefix, h160)


# ======================================================
#                   SCRIPT HELPERS
# ======================================================

OP_DUP = b"\x76"
OP_HASH160 = b"\xa9"
OP_EQUALVERIFY = b"\x88"
OP_CHECKSIG = b"\xac"


def p2pkh_script_pubkey(address: str) -> bytes:
    data = base58check_decode(address)
    # data[0] is version (prefix), next 20 bytes are h160
    h160 = data[1:]
    return (
        OP_DUP
        + OP_HASH160
        + b"\x14" + h160
        + OP_EQUALVERIFY
        + OP_CHECKSIG
    )


# ======================================================
#                   TRANSACTIONS
# ======================================================

@dataclass
class TxIn:
    txid: str
    vout: int
    script_sig: bytes = b""
    sequence: int = 0xffffffff

    def serialize(self) -> bytes:
        return (
            bytes.fromhex(self.txid)[::-1] +
            int_to_little_endian(self.vout, 4) +
            encode_varint(len(self.script_sig)) +
            self.script_sig +
            int_to_lle(self.sequence)
        )


def int_to_lle(x: int) -> bytes:
    return int_to_little_endian(x, 4)


@dataclass
class TxOut:
    value: int
    script_pubkey: bytes

    def serialize(self) -> bytes:
        return (
            int_to_little_endian(self.value, 8) +
            encode_varint(len(self.script_pubkey)) +
            self.script_pubkey
        )


class Tx:
    def __init__(self, version: int, tx_ins: List[TxIn], tx_outs: List[TxOut], locktime: int = 0):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime

    def serialize(self) -> bytes:
        r = int_to_little_endian(self.version, 4)
        r += encode_varint(len(self.tx_ins))
        for txin in self.tx_ins:
            r += txin.serialize()
        r += encode_varint(len(self.tx_outs))
        for txout in self.tx_outs:
            r += txout.serialize()
        r += int_to_little_endian(self.locktime, 4)
        return r

    def txid(self) -> str:
        return double_sha256(self.serialize())[::-1].hex()


# ======================================================
#                     SIGNING
# ======================================================

SIGHASH_ALL = 1


def sighash_preimage(tx: Tx, index: int, script_pubkey: bytes) -> bytes:
    tmp_ins = []
    for i, txin in enumerate(tx.tx_ins):
        tmp_ins.append(TxIn(
            txid=txin.txid,
            vout=txin.vout,
            script_sig=script_pubkey if i == index else b"",
            sequence=txin.sequence,
        ))
    tmp_tx = Tx(tx.version, tmp_ins, tx.tx_outs, tx.locktime)
    return tmp_tx.serialize() + int_to_little_endian(SIGHASH_ALL, 4)


def sign_input(tx: Tx, index: int, priv: PrivateKey, script_pubkey: bytes):
    preimage = sighash_preimage(tx, index, script_pubkey)
    h = double_sha256(preimage)
    z = int.from_bytes(h, "big")

    sig = priv.signing_key().sign_digest(
        z.to_bytes(32, "big"),
        sigencode=sigencode_der_canonize
    ) + bytes([SIGHASH_ALL])

    pub = priv.public_key_bytes()

    tx.tx_ins[index].script_sig = (
        len(sig).to_bytes(1, "little") + sig +
        len(pub).to_bytes(1, "little") + pub
    )


# ======================================================
#                   LOCAL WALLET (JSON)
# ======================================================

def wallet_filename() -> str:
    return "wallet_testnet.json" if IS_TESTNET else "wallet_mainnet.json"


def load_wallet() -> List[dict]:
    fn = wallet_filename()
    if not os.path.exists(fn):
        return []
    try:
        with open(fn, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_wallet(utxos: List[dict]):
    fn = wallet_filename()
    with open(fn, "w") as f:
        json.dump(utxos, f, indent=2)


# ======================================================
#                 COMMAND IMPLEMENTATIONS
# ======================================================

def cmd_generate_key():
    priv = PrivateKey.generate()
    print("\n=== NEW KEY ===")
    print("Network:", "testnet" if priv.testnet else "mainnet")
    print("WIF:", priv.to_wif())
    print("Address:", priv.address())
    print("================\n")


def cmd_add_utxo():
    utxos = load_wallet()
    print("\nAdd UTXO (NOTE: not checked on-chain)")
    txid = input("TXID (hex): ").strip()
    vout = int(input("Vout (index): ").strip())
    value = int(input("Value in sats: ").strip())
    addr = input("Address (P2PKH, optional, blank to skip): ").strip()
    label = input("Label (optional): ").strip()

    utxos.append({
        "txid": txid,
        "vout": vout,
        "value": value,
        "address": addr,
        "label": label,
    })
    save_wallet(utxos)
    print("UTXO added.\n")


def cmd_list_utxos():
    utxos = load_wallet()
    if not utxos:
        print("\nNo UTXOs stored in local wallet.\n")
        return
    print("\n=== LOCAL UTXOS (NOT VERIFIED) ===")
    total = 0
    for i, u in enumerate(utxos):
        total += u["value"]
        print(f"[{i}] {u['txid']}:{u['vout']}  value={u['value']} sats  addr={u.get('address','')}  label={u.get('label','')}")
    print(f"Total (local sum): {total} sats")
    print("==================================\n")


def cmd_build_simple_tx():
    print("\nBuild 1-input / 1-output tx (NO on-chain checks)")
    wif = input("Sender WIF: ").strip()
    priv = PrivateKey.from_wif(wif)
    from_addr = priv.address()

    txid = input("Input TXID: ").strip()
    vout = int(input("Input vout: ").strip())
    dest = input("Destination address: ").strip()
    amount = int(input("Amount to send (sats): ").strip())

    # We don't verify that inputs cover amount.
    tx_in = TxIn(txid=txid, vout=vout)
    script_out = p2pkh_script_pubkey(dest)
    tx_out = TxOut(value=amount, script_pubkey=script_out)

    tx = Tx(version=1, tx_ins=[tx_in], tx_outs=[tx_out], locktime=0)

    script_in = p2pkh_script_pubkey(from_addr)
    sign_input(tx, 0, priv, script_in)

    raw = tx.serialize().hex()
    print("\n=== RAW TX (hex) ===")
    print(raw)
    print("\nTXID:", tx.txid())
    print("====================\n")


def cmd_build_from_wallet():
    utxos = load_wallet()
    if not utxos:
        print("\nNo UTXOs in wallet.\n")
        return

    cmd_list_utxos()

    wif = input("Sender WIF (must match the UTXOs' address): ").strip()
    priv = PrivateKey.from_wif(wif)
    sender_addr = priv.address()

    idx_str = input("Enter UTXO indices to use (comma separated, e.g. 0,1): ").strip()
    indices = [int(x) for x in idx_str.split(",") if x.strip() != ""]
    inputs = [utxos[i] for i in indices]

    recipients = []
    while True:
        addr = input("Recipient address (blank to finish): ").strip()
        if not addr:
            break
        amount = int(input("Amount to send (sats): ").strip())
        recipients.append((addr, amount))

    if not recipients:
        print("No recipients specified.\n")
        return

    fee = int(input("Fee in sats: ").strip())

    total_in = sum(u["value"] for u in inputs)
    total_out_without_change = sum(a for _, a in recipients)

    change_addr = input(f"Change address (blank for none, default sender {sender_addr}): ").strip()
    if not change_addr:
        change_addr = sender_addr

    change = total_in - total_out_without_change - fee
    if change < 0:
        print("WARNING: total_out + fee > total_in. Change is negative. Setting change to 0 (chain will reject).")
        change = 0

    # build tx
    tx_ins = [TxIn(txid=u["txid"], vout=u["vout"]) for u in inputs]
    tx_outs = []

    for addr, amount in recipients:
        tx_outs.append(TxOut(value=amount, script_pubkey=p2pkh_script_pubkey(addr)))

    if change > 0:
        tx_outs.append(TxOut(value=change, script_pubkey=p2pkh_script_pubkey(change_addr)))

    tx = Tx(version=1, tx_ins=tx_ins, tx_outs=tx_outs, locktime=0)

    script_in = p2pkh_script_pubkey(sender_addr)
    for i in range(len(tx_ins)):
        sign_input(tx, i, priv, script_in)

    raw = tx.serialize().hex()
    print("\n=== RAW TX (hex) ===")
    print(raw)
    print("\nTXID:", tx.txid())
    print("====================\n")


def cmd_sweep_wif():
    utxos = load_wallet()
    if not utxos:
        print("\nNo UTXOs in wallet.\n")
        return

    wif = input("WIF to sweep: ").strip()
    priv = PrivateKey.from_wif(wif)
    addr = priv.address()

    # pick all utxos with this address
    my_utxos = [u for u in utxos if u.get("address") == addr]
    if not my_utxos:
        print("No UTXOs in wallet for that address.\n")
        return

    print(f"\nSweeping {len(my_utxos)} UTXOs for address {addr}")
    total_in = sum(u["value"] for u in my_utxos)
    print(f"Total in (local sum): {total_in} sats")

    dest = input("Destination address: ").strip()
    fee = int(input("Fee in sats: ").strip())
    amount = total_in - fee
    if amount <= 0:
        print("WARNING: non-positive amount after fee. Will still build tx, but it's invalid for the network.\n")

    tx_ins = [TxIn(txid=u["txid"], vout=u["vout"]) for u in my_utxos]
    tx_outs = [TxOut(value=max(amount, 0), script_pubkey=p2pkh_script_pubkey(dest))]

    tx = Tx(version=1, tx_ins=tx_ins, tx_outs=tx_outs, locktime=0)
    script_in = p2pkh_script_pubkey(addr)
    for i in range(len(tx_ins)):
        sign_input(tx, i, priv, script_in)

    raw = tx.serialize().hex()
    print("\n=== SWEEP RAW TX (hex) ===")
    print(raw)
    print("\nTXID:", tx.txid())
    print("=========================\n")


def cmd_decode_tx():
    raw = input("Raw tx hex: ").strip()
    b = bytes.fromhex(raw)

    offset = 0
    version = little_endian_to_int(b[offset:offset + 4])
    offset += 4

    n_in, offset = read_varint(b, offset)
    tx_ins = []
    for _ in range(n_in):
        txid = b[offset:offset + 32][::-1].hex()
        offset += 32
        vout = little_endian_to_int(b[offset:offset + 4])
        offset += 4
        script_len, offset = read_varint(b, offset)
        script_sig = b[offset:offset + script_len].hex()
        offset += script_len
        seq = little_endian_to_int(b[offset:offset + 4])
        offset += 4
        tx_ins.append((txid, vout, script_sig, seq))

    n_out, offset = read_varint(b, offset)
    tx_outs = []
    for _ in range(n_out):
        value = little_endian_to_int(b[offset:offset + 8])
        offset += 8
        script_len, offset = read_varint(b, offset)
        script_pubkey = b[offset:offset + script_len].hex()
        offset += script_len
        tx_outs.append((value, script_pubkey))

    locktime = little_endian_to_int(b[offset:offset + 4])

    print("\n=== DECODED TX ===")
    print("Version:", version)
    print("Inputs:", n_in)
    for i, (txid, vout, script_sig, seq) in enumerate(tx_ins):
        print(f"  In[{i}]: {txid}:{vout}, seq={seq}")
        print(f"    scriptSig: {script_sig}")
    print("Outputs:", n_out)
    for i, (value, spk) in enumerate(tx_outs):
        print(f"  Out[{i}]: {value} sats")
        print(f"    scriptPubKey: {spk}")
    print("Locktime:", locktime)
    print("==================\n")


# ======================================================
#                      MAIN MENU
# ======================================================

def main_menu():
    while True:
        print("========================================")
        print(" Mini Bitcoin Toolkit",
              "(testnet)" if IS_TESTNET else "(mainnet)")
        print("========================================")
        print("1) Generate key (WIF + address)")
        print("2) Add UTXO to local wallet")
        print("3) List local UTXOs")
        print("4) Build simple 1-in/1-out TX (manual)")
        print("5) Build TX from wallet UTXOs (send-many + change)")
        print("6) Sweep all UTXOs for WIF to address")
        print("7) Decode raw TX")
        print("8) Exit")
        choice = input("Select option: ").strip()

        if choice == "1":
            cmd_generate_key()
        elif choice == "2":
            cmd_add_utxo()
        elif choice == "3":
            cmd_list_utxos()
        elif choice == "4":
            cmd_build_simple_tx()
        elif choice == "5":
            cmd_build_from_wallet()
        elif choice == "6":
            cmd_sweep_wif()
        elif choice == "7":
            cmd_decode_tx()
        elif choice == "8":
            print("Bye.")
            break
        else:
            print("Invalid option.\n")


if __name__ == "__main__":
    # Network selection
    print("Use mainnet or testnet? (m/t) [t]: ", end="")
    net = input().strip().lower()
    if net == "m":
        IS_TESTNET = False
    else:
        IS_TESTNET = True

    main_menu()
