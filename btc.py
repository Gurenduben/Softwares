#!/usr/bin/env python3
"""
Tiny Bitcoin API (single-file)

Features:
- Create a (P2PKH) wallet (generate private key, WIF, and address)
- Prompt for a sending private key (WIF) or create a new one
- Ask whether network is mainnet or testnet
- Ask for receiving address and API base URL (expects Blockstream-style endpoints)
- Check local balance (via API UTXO list)
- Create, sign (P2PKH), and broadcast transactions
- Simple greedy coin selection and fee estimation for legacy P2PKH

Dependencies:
- requests
- ecdsa

Install:
pip install requests ecdsa

API expectations (Blockstream-style):
- GET  {API_BASE}/address/{address}/utxo
  returns JSON list with items containing at least:
    { "txid": "...", "vout": n, "value": satoshis, "scriptpubkey": "hex" } 
  (some providers use "vout" or "tx_output_n" or "output_n" — script tries common keys)
- POST {API_BASE}/tx  (body = raw hex)  -> returns txid or 200 OK

Blockstream examples:
- Mainnet: https://blockstream.info/api
  UTXO: https://blockstream.info/api/address/<addr>/utxo
  Broadcast: https://blockstream.info/api/tx  (POST raw tx hex)
- Testnet: https://blockstream.info/testnet/api

Security:
- This script handles private keys in memory. Do not paste mainnet private keys on untrusted hosts.
- Test thoroughly on testnet/regtest before using mainnet.

Usage:
- Run the script. It will prompt for the requested inputs.
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
    # leading zeros
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return (BASE58_ALPHABET[0:1] * pad + bytes(res)).decode()


def b58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum)


def base58check_decode(s: str) -> bytes:
    # returns payload (without checksum)
    b = b58decode(s)
    if len(b) < 4:
        raise ValueError("Invalid base58 string")
    payload, checksum = b[:-4], b[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError("Invalid checksum")
    return payload


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s.encode():
        n *= 58
        try:
            n += BASE58_ALPHABET.index(bytes([ch]))
        except ValueError:
            raise ValueError("Invalid base58 character: %r" % chr(ch))
    # convert number to bytes
    full = n.to_bytes((n.bit_length() + 7) // 8, 'big') or b'\x00'
    # restore leading zeros
    pad = 0
    for ch in s.encode():
        if ch == BASE58_ALPHABET[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + full


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


def wif_to_privkey(wif: str) -> (bytes, bool, bool):
    # returns (privkey_bytes, compressed, testnet)
    full = b58decode(wif)
    if len(full) not in (37, 38):  # prefix + 32 + optional 0x01 + 4 checksum handled elsewhere
        # accept without checksum (used earlier)
        pass
    payload = full[:-4]  # remove checksum
    prefix = payload[0:1]
    testnet = prefix == b'\xEF'
    compressed = False
    if len(payload) == 34 and payload[-1:] == b'\x01':
        compressed = True
        priv = payload[1:-1]
    else:
        priv = payload[1:]
    return priv, compressed, testnet


def privkey_to_pubkey(privkey_bytes: bytes, compressed: bool = True) -> bytes:
    sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    px = vk.to_string("compressed") if compressed else b'\x04' + vk.to_string()
    return px


def pubkey_to_p2pkh_address(pubkey_bytes: bytes, testnet: bool = False) -> str:
    h160 = hash160(pubkey_bytes)
    prefix = b'\x00' if not testnet else b'\x6F'
    payload = prefix + h160
    return b58check_encode(payload)


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
    # decode base58, extract hash160 (last 20 bytes of payload)
    payload = base58check_decode(address)
    # payload = prefix (1) + hash160 (20)
    if len(payload) != 21:
        raise ValueError("Invalid address payload size")
    h160 = payload[1:]
    # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    return b'\x76\xa9' + bytes([len(h160)]) + h160 + b'\x88\xac'


def tx_serialize(tx_version: int, tx_ins: list, tx_outs: list, locktime: int = 0) -> bytes:
    # tx_ins: list of dicts: {txid: bytes (32 little-endian), vout: int, scriptSig: bytes, sequence: int}
    # tx_outs: list of dicts: {value: int (satoshi), scriptPubKey: bytes}
    r = tx_version.to_bytes(4, 'little')
    r += varint(len(tx_ins))
    for inp in tx_ins:
        r += inp['txid']  # 32 bytes little-endian
        r += inp['vout'].to_bytes(4, 'little')
        r += varint(len(inp['scriptSig']))
        r += inp['scriptSig']
        r += inp.get('sequence', 0xffffffff).to_bytes(4, 'little')
    r += varint(len(tx_outs))
    for out in tx_outs:
        r += out['value'].to_bytes(8, 'little')
        r += varint(len(out['scriptPubKey']))
        r += out['scriptPubKey']
    r += locktime.to_bytes(4, 'little')
    return r


def sighash_all(tx_version: int, tx_ins: list, tx_outs: list, input_index: int, script_code: bytes, locktime: int = 0) -> bytes:
    # Build a copy of transaction per legacy SIGHASH_ALL algorithm (pre-segwit)
    # For each input, scriptSig is replaced by script_code for the input being signed, and empty for others.
    ins_copy = []
    for i, inp in enumerate(tx_ins):
        sc = script_code if i == input_index else b''
        ins_copy.append({
            'txid': inp['txid'],
            'vout': inp['vout'],
            'scriptSig': sc,
            'sequence': inp.get('sequence', 0xffffffff)
        })
    ser = tx_serialize(tx_version, ins_copy, tx_outs, locktime)
    ser += (1).to_bytes(4, 'little')  # SIGHASH_ALL
    return hashlib.sha256(hashlib.sha256(ser).digest()).digest()


# --------------------------
# Network / API helpers
# --------------------------
def api_get_utxos(api_base: str, address: str):
    # tries a few common JSON field names; returns list of utxo dicts with keys:
    # txid (hex), vout, value (satoshi), scriptpubkey (hex)
    url = api_base.rstrip('/') + f'/address/{address}/utxo'
    r = requests.get(url, timeout=15)
    if r.status_code != 200:
        raise RuntimeError(f"Error fetching UTXOs: {r.status_code} {r.text}")
    data = r.json()
    utxos = []
    for it in data:
        txid = it.get('txid') or it.get('tx_hash') or it.get('tx_hash_hex')
        vout = it.get('vout') or it.get('vout_n') or it.get('tx_output_n') or it.get('output_n')
        value = it.get('value') or it.get('amount') or it.get('satoshis')
        # Some APIs return value in BTC as float; handle that
        if isinstance(value, float):
            value = int(round(value * 1e8))
        script = it.get('scriptpubkey') or it.get('scriptPubKey') or it.get('script') or it.get('script_hex')
        utxos.append({
            'txid': txid,
            'vout': int(vout),
            'value': int(value),
            'scriptpubkey': script
        })
    return utxos


def api_broadcast_tx(api_base: str, rawtx_hex: str):
    url = api_base.rstrip('/') + '/tx'
    r = requests.post(url, data=rawtx_hex, headers={'Content-Type': 'text/plain'}, timeout=15)
    if r.status_code in (200, 201):
        # Blockstream returns txid as body text
        return r.text.strip()
    else:
        # Some providers return JSON error
        try:
            return r.json()
        except Exception:
            raise RuntimeError(f"Broadcast failed: {r.status_code} {r.text}")


# --------------------------
# Coin selection & tx building
# --------------------------
def estimate_tx_size(num_inputs: int, num_outputs: int, compressed: bool = True) -> int:
    # rough legacy P2PKH estimate: 10 + 148 * inputs + 34 * outputs
    return 10 + 148 * num_inputs + 34 * num_outputs


def select_utxos_greedy(utxos: list, target: int):
    # utxos is list of dicts with 'value'
    utxos_sorted = sorted(utxos, key=lambda u: u['value'])
    selected = []
    total = 0
    for u in utxos_sorted:
        selected.append(u)
        total += u['value']
        if total >= target:
            break
    return selected, total


def create_signed_p2pkh_tx(privkey_wif: str, from_address: str, to_address: str, amount_satoshi: int,
                           fee_rate_sat_per_byte: int, api_base: str, testnet: bool = False):
    # decode privkey
    try:
        priv_bytes, compressed, wif_testnet = wif_to_privkey(privkey_wif)
    except Exception:
        # try base58check decode via helper, if fails show message
        # fallback: let user provide raw hex
        raise ValueError("Invalid WIF private key")

    # fetch UTXOs
    utxos = api_get_utxos(api_base, from_address)
    if not utxos:
        raise ValueError("No UTXOs available for address")

    # pick utxos
    # estimate fee: we don't know inputs number yet; iterate increasing inputs until covered
    selected = []
    total_in = 0
    num_outputs = 2  # to_address + change (maybe zero)
    for k in range(1, len(utxos) + 1):
        # try taking k smallest/largest? Use smallest-first greedy above (sorted)
        sel, tot = select_utxos_greedy(utxos, amount_satoshi)  # simple; re-evaluate below
        # estimate size using number of selected utxos
        est_size = estimate_tx_size(len(sel), num_outputs)
        fee = fee_rate_sat_per_byte * est_size
        if tot >= amount_satoshi + fee:
            selected = sel
            total_in = tot
            break
        # otherwise try adding more by raising target and reselecting
        # simple approach: increase required target and select again
        amount_satoshi += 0  # noop; loop will exit when selected covers
        # break if we've used all utxos
        if len(sel) == len(utxos):
            selected = sel
            total_in = tot
            break

    if not selected:
        raise ValueError("Not enough funds")

    # recompute final fee and change
    est_size = estimate_tx_size(len(selected), num_outputs)
    fee = fee_rate_sat_per_byte * est_size
    change = total_in - amount_satoshi - fee
    outputs = []
    # create outputs scriptPubKey
    to_spk = address_to_p2pkh_scriptpubkey(to_address)
    outputs.append({'value': amount_satoshi, 'scriptPubKey': to_spk})
    if change > 0:
        change_spk = address_to_p2pkh_scriptpubkey(from_address)
        outputs.append({'value': change, 'scriptPubKey': change_spk})
    else:
        # if no change, reduce outputs count for exact fee calc (but already used)
        pass

    # prepare inputs as little-endian txid bytes
    tx_ins = []
    for u in selected:
        txid_le = bytes.fromhex(u['txid'])[::-1]
        tx_ins.append({'txid': txid_le, 'vout': int(u['vout']), 'scriptpubkey': u.get('scriptpubkey')})

    tx_version = 1
    locktime = 0

    # Build empty scriptSig for all inputs initially
    for inp in tx_ins:
        inp['scriptSig'] = b''

    # create raw signatures per input
    pubkey = privkey_to_pubkey(priv_bytes, compressed)
    for i, inp in enumerate(tx_ins):
        spk_hex = inp.get('scriptpubkey')
        if spk_hex:
            script_code = bytes.fromhex(spk_hex)
        else:
            # Try to construct from from_address
            script_code = address_to_p2pkh_scriptpubkey(from_address)
        sighash = sighash_all(tx_version, tx_ins, outputs, i, script_code, locktime)
        sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
        sig_der = sk.sign_digest_deterministic(sighash, hashfunc=hashlib.sha256, sigencode=binascii.b2a_hex)  # wrong encode
        # The above line was for deterministic raw hex — but ecdsa.SigningKey.sign_digest_deterministic can output raw bytes when not using sigencode.
        # Use the library default to obtain DER:
        sig_der = sk.sign_digest_deterministic(sighash, hashfunc=hashlib.sha256)
        sig_plus_hashtype = sig_der + b'\x01'  # SIGHASH_ALL
        # scriptSig = <sig+hashtype> <pubkey>
        scriptSig = op_push(sig_plus_hashtype) + op_push(pubkey)
        tx_ins[i]['scriptSig'] = scriptSig

    # Final tx serialization
    raw = tx_serialize(tx_version, tx_ins, outputs, locktime)
    raw_hex = raw.hex()

    # optional: verify that tx balances out
    total_out = sum(o['value'] for o in outputs)
    if total_in != total_out + fee:
        # There might be a mismatch if change was negative; raise
        if total_in < total_out + fee:
            raise ValueError("Internal error: inputs < outputs + fee after signing")
    return raw_hex, fee, selected


# --------------------------
# CLI
# --------------------------
def prompt_yes_no(prompt: str, default: bool = True) -> bool:
    yn = "Y/n" if default else "y/N"
    val = input(f"{prompt} [{yn}]: ").strip().lower()
    if val == '':
        return default
    return val[0] in 'y1t'


def main():
    print("Tiny Bitcoin API - create, sign, broadcast P2PKH transactions")
    print("You will be asked for the sending private key (WIF) or you can generate a new wallet.")
    # network
    net = input("Network (mainnet/testnet) [testnet]: ").strip().lower()
    testnet = True if net in ('', 'testnet', 't', 'test') else False

    # API base
    print("\nEnter API base URL. Expected Blockstream-style endpoints.")
    print("Examples:")
    print(" - Mainnet: https://blockstream.info/api")
    print(" - Testnet: https://blockstream.info/testnet/api")
    api_base = input("API base URL (e.g. https://blockstream.info/testnet/api): ").strip()
    if not api_base:
        print("API base required. Exiting.")
        sys.exit(1)

    # private key input or generation
    use_existing = prompt_yes_no("Do you have an existing private key (WIF) to use?", default=True)
    if use_existing:
        # hide private key input
        wif = getpass.getpass("Enter the sending private key (WIF): ").strip()
        try:
            priv, compressed, wif_test = wif_to_privkey(wif)
        except Exception as e:
            print("Invalid WIF. Error:", e)
            sys.exit(1)
        if (wif_test and not testnet) or (not wif_test and testnet):
            print("Warning: WIF network (testnet/mainnet) doesn't match selected network.")
    else:
        # generate new private key
        sk = os.urandom(32)
        compressed = True
        wif = privkey_to_wif(sk, compressed=compressed, testnet=testnet)
        pub = privkey_to_pubkey(sk, compressed=compressed)
        addr = pubkey_to_p2pkh_address(pub, testnet=testnet)
        print("\nGenerated new wallet:")
        print(" WIF (keep secret!) :", wif)
        print(" Address             :", addr)
        print(" (This private key is displayed now. Save it securely.)")
        # ask user if they want to use this key as sender
        use_gen = prompt_yes_no("Use the generated wallet as the sender?", default=True)
        if use_gen:
            # set variables
            priv, compressed, _ = wif_to_privkey(wif)
        else:
            print("Please run again with an existing WIF private key.")
            sys.exit(0)

    # derive from_address from private key
    pubkey = privkey_to_pubkey(priv, compressed=compressed)
    from_address = pubkey_to_p2pkh_address(pubkey, testnet=testnet)
    print("\nSender address:", from_address)

    # receiving address and amount
    to_address = input("Receiving address: ").strip()
    if not to_address:
        print("Receiving address required.")
        sys.exit(1)
    amt_str = input("Amount to send (BTC, e.g. 0.001): ").strip()
    try:
        amount_btc = float(amt_str)
    except:
        print("Invalid amount")
        sys.exit(1)
    amount_satoshi = int(round(amount_btc * 1e8))

    # fee rate
    fr = input("Fee rate (sat/vB) [10]: ").strip()
    fee_rate = int(fr) if fr else 10

    print("\nFetching UTXOs and balance...")
    try:
        utxos = api_get_utxos(api_base, from_address)
    except Exception as e:
        print("Failed to fetch UTXOs:", e)
        sys.exit(1)
    total_balance = sum([u['value'] for u in utxos])
    print(f"Local balance for {from_address}: {total_balance} sat ({total_balance/1e8} BTC)")
    print(f"Attempting to send {amount_satoshi} sat to {to_address} with fee rate {fee_rate} sat/vB")

    try:
        raw_hex, fee, selected = create_signed_p2pkh_tx(wif, from_address, to_address, amount_satoshi, fee_rate, api_base, testnet=testnet)
    except Exception as e:
        print("Failed to create/sign transaction:", e)
        sys.exit(1)

    print("\nTransaction created.")
    print(" Selected UTXOs:")
    for u in selected:
        print("  -", u['txid'], "vout", u['vout'], "value", u['value'])
    print(" Fee (est):", fee, "sat")
    print(" Raw tx (hex):", raw_hex)
    if not prompt_yes_no("Broadcast transaction now?", default=False):
        print("Transaction not broadcasted.")
        sys.exit(0)
    try:
        res = api_broadcast_tx(api_base, raw_hex)
        print("Broadcast result:", res)
    except Exception as e:
        print("Broadcast failed:", e)
        sys.exit(1)


if __name__ == '__main__':
    main()
