#!/usr/bin/env python3
"""
Tiny Bitcoin API (single-file, no balance checks)

Changes from original:
- Removed all balance checking
- Removed 'local balance' display
- Allows transaction creation even if inputs < outputs + fee
- Negative change is clamped to zero (no change output)
"""

import os
import sys
import requests
import hashlib
import json
import binascii
from ecdsa import SigningKey, SECP256k1
import getpass

# --------------------------
# Base58 / base58check utils
# --------------------------
BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    res = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        res.insert(0, BASE58_ALPHABET[r])
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return (BASE58_ALPHABET[0:1] * pad + bytes(res)).decode()


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s.encode():
        n *= 58
        try:
            n += BASE58_ALPHABET.index(bytes([ch]))
        except ValueError:
            raise ValueError("Invalid base58 character: %r" % chr(ch))
    full = n.to_bytes((n.bit_length() + 7) // 8, 'big') or b'\x00'
    pad = 0
    for ch in s.encode():
        if ch == BASE58_ALPHABET[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + full


def b58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum)


def base58check_decode(s: str) -> bytes:
    b = b58decode(s)
    if len(b) < 4:
        raise ValueError("Invalid base58 string")
    payload, checksum = b[:-4], b[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError("Invalid checksum")
    return payload


# --------------------------
# EC / key / address utils
# --------------------------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ripemd160(b: bytes) -> bytes:
    h = hashlib.new('ripemd160')
    h.update(b)
    return h.digest()


def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))


def privkey_to_wif(privkey_bytes: bytes, compressed: bool = True, testnet: bool = False) -> str:
    prefix = b'\x80' if not testnet else b'\xEF'
    payload = prefix + privkey_bytes
    if compressed:
        payload += b'\x01'
    return b58check_encode(payload)


def wif_to_privkey(wif: str):
    payload = base58check_decode(wif)
    if len(payload) not in (33, 34):
        raise ValueError(f"Invalid WIF payload length: {len(payload)}")
    prefix = payload[0:1]
    testnet = (prefix == b'\xEF')
    if len(payload) == 34 and payload[-1:] == b'\x01':
        compressed = True
        priv = payload[1:-1]
    else:
        compressed = False
        priv = payload[1:]
    if len(priv) != 32:
        raise ValueError("Invalid privkey size in WIF")
    return priv, compressed, testnet


def privkey_to_pubkey(privkey_bytes: bytes, compressed: bool = True) -> bytes:
    sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    return vk.to_string("compressed") if compressed else b'\x04' + vk.to_string()


def pubkey_to_p2pkh_address(pubkey_bytes: bytes, testnet: bool = False) -> str:
    h160 = hash160(pubkey_bytes)
    prefix = b'\x00' if not testnet else b'\x6F'
    return b58check_encode(prefix + h160)


# --------------------------
# Bitcoin script & tx helpers
# --------------------------
def varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    elif n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    else:
        return b'\xff' + n.to_bytes(8, 'little')


def op_push(data: bytes) -> bytes:
    l = len(data)
    if l < 0x4c:
        return bytes([l]) + data
    elif l <= 0xff:
        return b'\x4c' + bytes([l]) + data
    elif l <= 0xffff:
        return b'\x4d' + l.to_bytes(2, 'little') + data
    else:
        return b'\x4e' + l.to_bytes(4, 'little') + data


def address_to_p2pkh_scriptpubkey(address: str) -> bytes:
    payload = base58check_decode(address)
    h160 = payload[1:]
    return b'\x76\xa9' + bytes([20]) + h160 + b'\x88\xac'


def tx_serialize(ver, ins, outs, lock=0) -> bytes:
    r = ver.to_bytes(4, 'little')
    r += varint(len(ins))
    for inp in ins:
        r += inp['txid']
        r += inp['vout'].to_bytes(4, 'little')
        r += varint(len(inp['scriptSig']))
        r += inp['scriptSig']
        r += inp.get('sequence', 0xffffffff).to_bytes(4, 'little')
    r += varint(len(outs))
    for out in outs:
        r += out['value'].to_bytes(8, 'little')
        r += varint(len(out['scriptPubKey']))
        r += out['scriptPubKey']
    r += lock.to_bytes(4, 'little')
    return r


def sighash_all(ver, ins, outs, index, script_code, lock=0) -> bytes:
    ins2 = []
    for i, inp in enumerate(ins):
        sc = script_code if i == index else b''
        ins2.append({
            'txid': inp['txid'],
            'vout': inp['vout'],
            'scriptSig': sc,
            'sequence': inp.get('sequence', 0xffffffff)
        })
    ser = tx_serialize(ver, ins2, outs, lock)
    ser += b'\x01\x00\x00\x00'
    return hashlib.sha256(hashlib.sha256(ser).digest()).digest()


# --------------------------
# API helpers
# --------------------------
def api_get_utxos(api_base: str, address: str):
    url = api_base.rstrip('/') + f'/address/{address}/utxo'
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    data = r.json()
    utxos = []
    for it in data:
        txid = it.get("txid")
        vout = it.get("vout")
        value = it.get("value")
        script = it.get("scriptpubkey")
        utxos.append({
            'txid': txid,
            'vout': int(vout),
            'value': int(value),
            'scriptpubkey': script
        })
    return utxos


def api_broadcast_tx(api_base: str, raw_hex: str):
    url = api_base.rstrip('/') + '/tx'
    r = requests.post(url, data=raw_hex, headers={'Content-Type': 'text/plain'})
    return r.text.strip()


# --------------------------
# Transaction creation (NO BALANCE CHECKS)
# --------------------------
def estimate_tx_size(n_in, n_out):
    return 10 + 148 * n_in + 34 * n_out


def create_signed_p2pkh_tx(wif, from_addr, to_addr, amount_sat, fee_rate, api_base, testnet=False):
    priv, compressed, wif_test = wif_to_privkey(wif)

    utxos = api_get_utxos(api_base, from_addr)
    if not utxos:
        raise ValueError("No UTXOs found")

    # GREEDY selection (NO checking!)
    utxos_sorted = sorted(utxos, key=lambda u: u['value'])
    selected = []
    total_in = 0
    for u in utxos_sorted:
        selected.append(u)
        total_in += u['value']
        # we don't check anything here

    # Build outputs
    num_outputs = 2
    est_size = estimate_tx_size(len(selected), num_outputs)
    fee = est_size * fee_rate
    change = total_in - amount_sat - fee

    outputs = []
    outputs.append({
        'value': amount_sat,
        'scriptPubKey': address_to_p2pkh_scriptpubkey(to_addr)
    })

    # Clamp change
    if change > 0:
        outputs.append({
            'value': change,
            'scriptPubKey': address_to_p2pkh_scriptpubkey(from_addr)
        })

    # Inputs
    tx_ins = []
    for u in selected:
        txid_le = bytes.fromhex(u['txid'])[::-1]
        tx_ins.append({
            'txid': txid_le,
            'vout': u['vout'],
            'scriptSig': b'',
            'scriptpubkey': u['scriptpubkey']
        })

    ver = 1
    locktime = 0

    pubkey = privkey_to_pubkey(priv, compressed)

    # Sign
    for i, inp in enumerate(tx_ins):
        script_code = bytes.fromhex(inp['scriptpubkey'])
        sighash = sighash_all(ver, tx_ins, outputs, i, script_code, locktime)
        sk = SigningKey.from_string(priv, curve=SECP256k1)
        sig = sk.sign_digest_deterministic(sighash, hashfunc=hashlib.sha256)
        sig += b'\x01'
        inp['scriptSig'] = op_push(sig) + op_push(pubkey)

    raw = tx_serialize(ver, tx_ins, outputs, locktime)
    return raw.hex(), fee, selected


# --------------------------
# CLI
# --------------------------
def prompt_yes_no(prompt: str, default=True) -> bool:
    yn = "Y/n" if default else "y/N"
    v = input(f"{prompt} [{yn}]: ").strip().lower()
    if v == '':
        return default
    return v[0] in "y1t"


def main():
    print("Tiny Bitcoin API (no balance checks)")

    net = input("Network (mainnet/testnet) [testnet]: ").strip().lower()
    testnet = (net in ("", "testnet", "t", "test"))

    api_base = input("API base URL: ").strip()
    if not api_base:
        sys.exit(1)

    use_existing = prompt_yes_no("Use existing WIF?", True)

    if use_existing:
        wif = getpass.getpass("Enter WIF: ").strip()
        priv, comp, wif_test = wif_to_privkey(wif)
    else:
        sk = os.urandom(32)
        wif = privkey_to_wif(sk, True, testnet)
        print("Generated WIF:", wif)
        priv, comp, _ = wif_to_privkey(wif)

    pub = privkey_to_pubkey(priv, comp)
    from_addr = pubkey_to_p2pkh_address(pub, testnet)
    print("Sender:", from_addr)

    to_addr = input("Receiver address: ").strip()
    amt = float(input("Amount BTC: ").strip())
    amount_sat = int(round(amt * 1e8))

    fr = input("Fee rate sat/vB [10]: ").strip()
    fee_rate = int(fr) if fr else 10

    raw_hex, fee, sel = create_signed_p2pkh_tx(
        wif, from_addr, to_addr, amount_sat, fee_rate, api_base, testnet
    )

    print("\nTransaction built.")
    print("Raw hex:", raw_hex)
    print("Fee:", fee)

    if prompt_yes_no("Broadcast?"):
        res = api_broadcast_tx(api_base, raw_hex)
        print("Result:", res)
    else:
        print("Not broadcasted.")


if __name__ == "__main__":
    main()
