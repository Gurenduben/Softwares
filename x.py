import time
from coincurve.keys import PrivateKey

def main():
    # Input private key (decimal string)
    priv_dec = int(input("Enter starting private key (decimal): ").strip())
    total_keys = int(input("How many keys to generate: ").strip())

    start_time = time.time()

    with open("keys.txt", "w") as f:  # overwrite each run
        for i in range(total_keys):
            priv_int = priv_dec + i
            priv_bytes = priv_int.to_bytes(32, "big")

            # Create public key
            pub = PrivateKey(priv_bytes).public_key

            # Write both private & public key formats
            f.write(f"Private (dec)   = {priv_int}\n")
            f.write(f"Private (hex)   = {priv_bytes.hex()}\n")
            f.write(f"Public (comp)   = {pub.format(compressed=True).hex()}\n")
            f.write(f"Public (uncomp) = {pub.format(compressed=False).hex()}\n\n")

            # Progress + ETA
            elapsed = time.time() - start_time
            avg_time = elapsed / (i + 1)
            remaining = avg_time * (total_keys - (i + 1))

            print(
                f"[{i+1}/{total_keys}] wrote key {priv_int} | "
                f"elapsed: {elapsed:.1f}s | ETA: {remaining:.1f}s",
                end="\r"
            )

    total_time = time.time() - start_time
    print(
        f"\n✅ Finished writing {total_keys:,} keypairs to keys.txt "
        f"(starting from {priv_dec}) in {total_time:.2f} seconds"
    )

if __name__ == "__main__":
    main()

