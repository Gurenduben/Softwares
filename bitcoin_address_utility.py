import hashlib
import base58
import ecdsa
import qrcode
from typing import Optional, List, Dict, Tuple
import tkinter as tk
from tkinter import ttk, messagebox
import os
from dataclasses import dataclass
import secrets
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import time
import gc
from datetime import datetime

@dataclass
class KeyCollectionItem:
    """Represents an item in the key collection"""
    address: Optional['AddressBase'] = None
    encrypted_key_pair: Optional['Bip38KeyPair'] = None

@dataclass
class AddressBase:
    """Base class for Bitcoin addresses"""
    address_bytes: bytes
    version_byte: int = 0  # Default to Bitcoin mainnet

    @property
    def address_base58(self) -> str:
        """Convert address bytes to base58check format"""
        return base58.b58encode_check(bytes([self.version_byte]) + self.address_bytes).decode()

    @property
    def hash160_hex(self) -> str:
        """Get the Hash160 (RIPEMD160(SHA256())) representation"""
        return self.address_bytes.hex()

    @classmethod
    def from_base58(cls, address: str) -> 'AddressBase':
        """Create AddressBase from base58check address"""
        decoded = base58.b58decode_check(address)
        return cls(decoded[1:], decoded[0])

class KeyPair:
    """Bitcoin keypair handling class"""
    def __init__(self, private_key: Optional[bytes] = None, compressed: bool = True):
        if private_key is None:
            private_key = secrets.token_bytes(32)
        self.private_key = private_key
        self.compressed = compressed
        self._init_keys()

    def _init_keys(self):
        """Initialize the key pair"""
        signing_key = ecdsa.SigningKey.from_string(self.private_key, curve=ecdsa.SECP256k1)
        verifying_key = signing_key.get_verifying_key()
        
        # Get public key bytes
        if self.compressed:
            pub_key_bytes = bytes([2 + (verifying_key.pubkey.point.y() & 1)]) + \
                           verifying_key.pubkey.point.x().to_bytes(32, 'big')
        else:
            pub_key_bytes = bytes([4]) + \
                           verifying_key.pubkey.point.x().to_bytes(32, 'big') + \
                           verifying_key.pubkey.point.y().to_bytes(32, 'big')
        
        self.public_key = pub_key_bytes

    @property
    def private_key_wif(self) -> str:
        """Get the Wallet Import Format representation of the private key"""
        version = bytes([128])
        suffix = bytes([1]) if self.compressed else b''
        return base58.b58encode_check(version + self.private_key + suffix).decode()

    @property
    def address(self) -> str:
        """Get the Bitcoin address"""
        sha256_hash = hashlib.sha256(self.public_key).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        return AddressBase(ripemd160_hash).address_base58

class AdvancedKeyTools:
    """Advanced Bitcoin key manipulation tools"""
    
    @staticmethod
    def split_key(private_key: bytes, n: int, m: int) -> Tuple[bytes, List[bytes]]:
        """Split a private key into n shares, requiring m shares to reconstruct"""
        if m > n:
            raise ValueError("Required shares (m) cannot be greater than total shares (n)")
            
        coefficients = [secrets.token_bytes(32) for _ in range(m-1)]
        shares = []
        
        for i in range(1, n+1):
            x = i.to_bytes(1, 'big')
            y = private_key
            
            for j, coeff in enumerate(coefficients, 1):
                term = int.from_bytes(hmac.new(coeff, x, hashlib.sha256).digest(), 'big')
                y_int = int.from_bytes(y, 'big')
                y_int = (y_int + term) % ecdsa.SECP256k1.order
                y = y_int.to_bytes(32, 'big')
                
            shares.append(y)
            
        checksum = hashlib.sha256(private_key + b''.join(shares)).digest()
        return checksum, shares

    @staticmethod
    def combine_shares(shares: List[bytes], checksum: bytes) -> bytes:
        """Combine key shares to reconstruct the original private key"""
        if len(shares) < 2:
            raise ValueError("Need at least 2 shares to reconstruct")
            
        result = 0
        for i, share_i in enumerate(shares):
            basis = 1
            for j, share_j in enumerate(shares):
                if i != j:
                    basis *= j+1
                    basis *= pow(j+1 - (i+1), -1, ecdsa.SECP256k1.order)
            result = (result + (int.from_bytes(share_i, 'big') * basis)) % ecdsa.SECP256k1.order
            
        private_key = result.to_bytes(32, 'big')
        
        validation_checksum = hashlib.sha256(private_key + b''.join(shares)).digest()
        if validation_checksum != checksum:
            raise ValueError("Invalid shares or checksum")
            
        return private_key

    @staticmethod
    def create_multisig(public_keys: List[bytes], required_signatures: int) -> Tuple[str, bytes]:
        """Create a multi-signature Bitcoin address"""
        if required_signatures > len(public_keys):
            raise ValueError("Required signatures cannot exceed number of public keys")
            
        redeem_script = bytes([0x50 + required_signatures])
        
        for pub_key in public_keys:
            redeem_script += bytes([len(pub_key)]) + pub_key
            
        redeem_script += bytes([0x50 + len(public_keys)])
        redeem_script += bytes([0xAE])
        
        script_hash = hashlib.new('ripemd160', hashlib.sha256(redeem_script).digest()).digest()
        version = bytes([5])
        
        return base58.b58encode_check(version + script_hash).decode(), redeem_script

    @staticmethod
    def create_vanity_address(prefix: str, max_tries: int = 100000) -> Optional[KeyPair]:
        """Generate a vanity Bitcoin address"""
        prefix = prefix.lower()
        for _ in range(max_tries):
            keypair = KeyPair()
            address = keypair.address[1:1+len(prefix)]
            if address.lower() == prefix:
                return keypair
        return None

    @staticmethod
    def time_lock_key(private_key: bytes, unlock_time: int) -> Tuple[str, bytes]:
        """Create a time-locked Bitcoin script"""
        signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
        public_key = signing_key.get_verifying_key().to_string()
        
        redeem_script = unlock_time.to_bytes(4, 'little')
        redeem_script += bytes([0xb1])  # OP_CHECKLOCKTIMEVERIFY
        redeem_script += bytes([0x75])  # OP_DROP
        redeem_script += bytes([len(public_key)]) + public_key
        redeem_script += bytes([0xac])  # OP_CHECKSIG
        
        script_hash = hashlib.new('ripemd160', hashlib.sha256(redeem_script).digest()).digest()
        version = bytes([5])
        
        return base58.b58encode_check(version + script_hash).decode(), redeem_script

class BitcoinAddressGUI:
    """Main GUI class for Bitcoin Address Utility"""
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Bitcoin Address Utility")
        
        # Set up window close handler
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        self.setup_gui()
        self.setup_advanced_tools()
        self.setup_paste_functions()
        self.entropy = []
        self.start_entropy_collection()

    def setup_gui(self):
        """Setup the main GUI components"""
        # Create frames
        input_frame = ttk.LabelFrame(self.window, text="Input/Output")
        input_frame.pack(padx=10, pady=5, fill="x")

        # Create input fields
        self.private_key_wif = ttk.Entry(input_frame, width=60)
        self.private_key_hex = ttk.Entry(input_frame, width=60)
        self.public_key_hex = ttk.Entry(input_frame, width=60)
        self.address = ttk.Entry(input_frame, width=60)

        # Add labels and entries
        ttk.Label(input_frame, text="Private Key (WIF):").grid(row=0, column=0, sticky="w")
        self.private_key_wif.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(input_frame, text="Private Key (Hex):").grid(row=1, column=0, sticky="w")
        self.private_key_hex.grid(row=1, column=1, padx=5, pady=2)

        ttk.Label(input_frame, text="Public Key (Hex):").grid(row=2, column=0, sticky="w")
        self.public_key_hex.grid(row=2, column=1, padx=5, pady=2)

        ttk.Label(input_frame, text="Bitcoin Address:").grid(row=3, column=0, sticky="w")
        self.address.grid(row=3, column=1, padx=5, pady=2)

        # Add coin type selector
        self.coin_type = ttk.Combobox(input_frame, 
                                     values=["Bitcoin", "Testnet", "Namecoin", "Litecoin"])
        self.coin_type.set("Bitcoin")
        self.coin_type.grid(row=4, column=1, padx=5, pady=2, sticky="w")
        ttk.Label(input_frame, text="Coin Type:").grid(row=4, column=0, sticky="w")

        # Add basic buttons
        button_frame = ttk.Frame(self.window)
        button_frame.pack(pady=5)

        ttk.Button(button_frame, text="Generate New Address", 
                  command=self.generate_new_address).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Copy Address", 
                  command=self.copy_address).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Generate QR Code", 
                  command=self.generate_qr).pack(side="left", padx=5)
                  
        # Add clear button
        style = ttk.Style()
        style.configure("Clear.TButton", foreground="red", padding=5)
        ttk.Button(button_frame, text="Clear All", 
                  command=self.clear_all_data,
                  style="Clear.TButton").pack(side="left", padx=5)

    def setup_paste_functions(self):
        """Setup unified paste functionality"""
        paste_frame = ttk.LabelFrame(self.window, text="Paste Functions")
        paste_frame.pack(padx=10, pady=5, fill="x")
        
        ttk.Button(paste_frame, text="Paste Key/Address", 
                  command=self.paste_and_process).pack(side="left", padx=5, pady=5)
        
        self.compressed_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(paste_frame, text="Use Compressed Format", 
                       variable=self.compressed_var).pack(side="left", padx=5, pady=5)

    def setup_advanced_tools(self):
        """Setup advanced key manipulation tools GUI"""
        advanced_frame = ttk.LabelFrame(self.window, text="Advanced Tools")
        advanced_frame.pack(padx=10, pady=5, fill="x")
        
        # Multi-signature tool
        ttk.Label(advanced_frame, text="Multi-signature:").grid(row=0, column=0, sticky="w")
        self.n_sigs = ttk.Entry(advanced_frame, width=5)
        self.n_sigs.grid(row=0, column=1, padx=5)
        ttk.Label(advanced_frame, text="of").grid(row=0, column=2)
        self.m_sigs = ttk.Entry(advanced_frame, width=5)
        self.m_sigs.grid(row=0, column=3, padx=5)
        ttk.Button(advanced_frame, text="Create Multi-sig", 
                  command=self.create_multisig).grid(row=0, column=4, padx=5)
        
        # Key splitting tool
        ttk.Label(advanced_frame, text="Split Key:").grid(row=1, column=0, sticky="w")
        ttk.Button(advanced_frame, text="Split Current Key", 
                  command=self.split_current_key).grid(row=1, column=1, columnspan=2, padx=5)
        
        # Vanity address generator
        ttk.Label(advanced_frame, text="Vanity Address:").grid(row=2, column=0, sticky="w")
        self.vanity_prefix = ttk.Entry(advanced_frame, width=10)
        self.vanity_prefix.grid(row=2, column=1, columnspan=2, padx=5)
        ttk.Button(advanced_frame, text="Generate", 
                  command=self.generate_vanity).grid(row=2, column=3, padx=5)
        
        # Time-lock tool
        ttk.Label(advanced_frame, text="Time Lock:").grid(row=3, column=0, sticky="w")
        self.unlock_time = ttk.Entry(advanced_frame, width=20)
        self.unlock_time.grid(row=3, column=1, columnspan=2, padx=5)
        ttk.Button(advanced_frame, text="Create Time-Lock", 
                  command=self.create_timelock).grid(row=3, column=3, padx=5)

    def clear_all_data(self):
        """Clear all data fields and reset the form"""
        try:
            if not messagebox.askyesno("Confirm Clear", 
                                     "Are you sure you want to clear all keys and data?"):
                return

            # Clear all entry fields
            self.private_key_wif.delete(0, tk.END)
            self.private_key_hex.delete(0, tk.END)
            self.public_key_hex.delete(0, tk.END)
            self.address.delete(0, tk.END)
            
            # Reset coin type to Bitcoin
            self.coin_type.set("Bitcoin")
            
            # Clear advanced tools
            if hasattr(self, 'n_sigs'):
                self.n_sigs.delete(0, tk.END)
            if hasattr(self, 'm_sigs'):
                self.m_sigs.delete(0, tk.END)
            if hasattr(self, 'vanity_prefix'):
                self.vanity_prefix.delete(0, tk.END)
            if hasattr(self, 'unlock_time'):
                self.unlock_time.delete(0, tk.END)
                
            # Reset compressed format checkbox
            if hasattr(self, 'compressed_var'):
                self.compressed_var.set(True)
                
            # Clear clipboard
            self.window.clipboard_clear()
            
            # Clear entropy collection
            self.entropy.clear()
            
            # Clear sensitive memory
            self.clear_sensitive_memory()
            
            messagebox.showinfo("Success", "All keys and data have been cleared")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear data: {str(e)}")

    def clear_sensitive_memory(self):
        """Clear sensitive data from memory"""
        try:
            if hasattr(self, 'entropy'):
                self.entropy = []
            gc.collect()
        except Exception:
            pass

    def on_closing(self):
        """Handle window closing"""
        try:
            self.clear_sensitive_memory()
            self.window.destroy()
        except:
            self.window.destroy()

    def generate_new_address(self):
        """Generate a new Bitcoin address"""
        try:
            keypair = KeyPair(compressed=True)
            self.private_key_wif.delete(0, tk.END)
            self.private_key_wif.insert(0, keypair.private_key_wif)
            
            self.private_key_hex.delete(0, tk.END)
            self.private_key_hex.insert(0, keypair.private_key.hex())
            
            self.public_key_hex.delete(0, tk.END)
            self.public_key_hex.insert(0, keypair.public_key.hex())
            
            self.address.delete(0, tk.END)
            self.address.insert(0, keypair.address)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate address: {str(e)}")

    def copy_address(self):
        """Copy the Bitcoin address to clipboard"""
        self.window.clipboard_clear()
        self.window.clipboard_append(self.address.get())
        messagebox.showinfo("Success", "Address copied to clipboard!")

    def generate_qr(self):
        """Generate QR code for the address"""
        address = self.address.get()
        if not address:
            messagebox.showerror("Error", "Generate an address first!")
            return
            
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(address)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white")
        qr_image.show()

    def paste_and_process(self):
        """Process any pasted key format and attempt to show private key"""
        try:
            # Get clipboard content
            clipboard_content = self.window.clipboard_get().strip()
            
            if not clipboard_content:
                raise ValueError("Clipboard is empty")

            # Clear all fields first
            self.clear_all_fields()
            
            # Try different formats
            try:
                # Try WIF format first
                self.process_wif(clipboard_content)
                return
            except:
                pass

            try:
                # Try hex private key
                self.process_hex_private(clipboard_content)
                return
            except:
                pass

            try:
                # Try public key
                self.process_public_key(clipboard_content)
            except:
                try:
                    # Try address
                    self.process_address(clipboard_content)
                except:
                    raise ValueError("Invalid key format")

        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to process key: {str(e)}")

    def clear_all_fields(self):
        """Clear all input fields"""
        self.private_key_wif.delete(0, tk.END)
        self.private_key_hex.delete(0, tk.END)
        self.public_key_hex.delete(0, tk.END)
        self.address.delete(0, tk.END)

    def process_wif(self, wif: str):
        """Process WIF private key"""
        key_bytes = base58.b58decode_check(wif)
        
        # Handle compressed and uncompressed WIF formats
        if len(key_bytes) == 33 and key_bytes[0] == 128:  # Uncompressed WIF
            private_key = key_bytes[1:]
            compressed = False
        elif len(key_bytes) == 34 and key_bytes[0] == 128:  # Compressed WIF
            private_key = key_bytes[1:-1]
            compressed = True
        else:
            raise ValueError("Invalid WIF format")
            
        # Create key pair and update all fields
        keypair = KeyPair(private_key, compressed or self.compressed_var.get())
        self.update_all_fields(keypair)
        messagebox.showinfo("Success", "Successfully processed WIF private key")

    def process_hex_private(self, hex_key: str):
        """Process hexadecimal private key"""
        if len(hex_key) != 64:  # 32 bytes = 64 hex chars
            raise ValueError("Invalid private key length")
            
        private_key = bytes.fromhex(hex_key)
        keypair = KeyPair(private_key, self.compressed_var.get())
        self.update_all_fields(keypair)
        messagebox.showinfo("Success", "Successfully processed hex private key")

    def process_public_key(self, pub_key: str):
        """Process public key"""
        if not (len(pub_key) == 66 or len(pub_key) == 130):
            raise ValueError("Invalid public key length")
            
        public_key = bytes.fromhex(pub_key)
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        
        self.public_key_hex.insert(0, pub_key)
        self.address.insert(0, AddressBase(ripemd160_hash).address_base58)
        messagebox.showinfo("Success", "Successfully processed public key\nNote: Private key cannot be derived from public key")

    def process_address(self, address: str):
        """Process Bitcoin address"""
        addr = AddressBase.from_base58(address)
        self.address.insert(0, address)
        messagebox.showinfo("Success", "Successfully processed Bitcoin address\nNote: Private key cannot be derived from address")

    def update_all_fields(self, keypair: KeyPair):
        """Update all fields with key pair information"""
        self.private_key_wif.insert(0, keypair.private_key_wif)
        self.private_key_hex.insert(0, keypair.private_key.hex())
        self.public_key_hex.insert(0, keypair.public_key.hex())
        self.address.insert(0, keypair.address)

    def create_multisig(self):
        """Create multi-signature address"""
        try:
            n = int(self.n_sigs.get())
            m = int(self.m_sigs.get())
            
            # Get public keys from file or entry
            public_keys = []  # Add UI for inputting public keys
            
            address, redeem_script = AdvancedKeyTools.create_multisig(public_keys, m)
            
            messagebox.showinfo("Multi-signature Address", 
                              f"Address: {address}\nRedeem Script: {redeem_script.hex()}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def split_current_key(self):
        """Split current private key"""
        try:
            if not self.private_key_hex.get():
                raise ValueError("Generate or input a private key first")
                
            private_key = bytes.fromhex(self.private_key_hex.get())
            checksum, shares = AdvancedKeyTools.split_key(private_key, 3, 2)  # Example: 2-of-3
            
            share_window = tk.Toplevel(self.window)
            share_window.title("Key Shares")
            
            for i, share in enumerate(shares, 1):
                ttk.Label(share_window, text=f"Share {i}:").pack()
                share_entry = ttk.Entry(share_window, width=80)
                share_entry.insert(0, share.hex())
                share_entry.pack()
                
            ttk.Label(share_window, text="Checksum:").pack()
            checksum_entry = ttk.Entry(share_window, width=80)
            checksum_entry.insert(0, checksum.hex())
            checksum_entry.pack()
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def generate_vanity(self):
        """Generate vanity address"""
        prefix = self.vanity_prefix.get()
        if not prefix:
            messagebox.showerror("Error", "Enter desired prefix")
            return
            
        # Show progress dialog
        progress = tk.Toplevel(self.window)
        progress.title("Generating Vanity Address")
        ttk.Label(progress, text="Searching...").pack()
        progress.update()
        
        try:
            keypair = AdvancedKeyTools.create_vanity_address(prefix)
            if keypair:
                self.private_key_wif.delete(0, tk.END)
                self.private_key_wif.insert(0, keypair.private_key_wif)
                self.address.delete(0, tk.END)
                self.address.insert(0, keypair.address)
                messagebox.showinfo("Success", "Vanity address generated!")
            else:
                messagebox.showerror("Error", "Could not find matching address")
        finally:
            progress.destroy()

    def create_timelock(self):
        """Create time-locked address"""
        try:
            unlock_time = int(self.unlock_time.get())
            if not self.private_key_hex.get():
                raise ValueError("Generate or input a private key first")
                
            private_key = bytes.fromhex(self.private_key_hex.get())
            address, redeem_script = AdvancedKeyTools.time_lock_key(private_key, unlock_time)
            
            messagebox.showinfo("Time-locked Address", 
                              f"Address: {address}\nRedeem Script: {redeem_script.hex()}\n"
                              f"Unlocks at: {time.ctime(unlock_time)}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def start_entropy_collection(self):
        """Start collecting entropy from system events"""
        def add_entropy(event):
            self.entropy.append(f"{event.x},{event.y},{time.time()}")
            
        self.window.bind('<Motion>', add_entropy)
        self.window.bind('<Key>', lambda e: self.entropy.append(f"key_{e.char}_{time.time()}"))

    def run(self):
        """Start the GUI application"""
        self.window.mainloop()

def main():
    app = BitcoinAddressGUI()
    app.run()

if __name__ == "__main__":
    main()