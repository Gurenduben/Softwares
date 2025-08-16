from coincurve import PublicKey
import sys

# secp256k1 order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Midpoint private key (standard halfway value)
mid_priv = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
mid_pubkey = PublicKey.from_valid_secret(mid_priv.to_bytes(32, 'big')).format(compressed=False)

def parse_uncompressed(pubkey_hex):
    if not pubkey_hex.startswith('04') or len(pubkey_hex) != 130:
        raise ValueError("Public key must be uncompressed format (130 hex chars, starts with 04)")
    return bytes.fromhex(pubkey_hex)

def multiply_pubkey(pubkey_bytes, scalar):
    pk = PublicKey(pubkey_bytes)
    return pk.multiply(scalar.to_bytes(32, 'big')).format(compressed=False)

def main():
    print("🔁 Scalar Multiplication on secp256k1")
    target_hex = input("Enter target uncompressed public key (hex): ").strip()

    try:
        target = parse_uncompressed(target_hex)
    except Exception as e:
        print(f"❌ Error parsing target: {e}")
        sys.exit(1)

    k = int(input("Enter scalar multiplier k: ").strip())
    if k <= 1 or k >= n:
        print("❌ Scalar must be >1 and < curve order.")
        sys.exit(1)

    current = mid_pubkey
    steps = 0
    visited = set()

    print("🔄 Starting loop from midpoint...")
    while True:
        if current == target:
            print(f"\n🎯 Reached target public key after {steps} multiplications.")
            recovered_d = pow(k, steps, n)
            print(f"🔐 Recovered private key: {hex(recovered_d)[2:].zfill(64)}")
            break

        coord = current.hex()
        if coord in visited:
            print("🔁 Cycle detected before reaching target. Aborting.")
            sys.exit(1)
        visited.add(coord)

        current = multiply_pubkey(current, k)
        steps += 1

if __name__ == '__main__':
    main()

