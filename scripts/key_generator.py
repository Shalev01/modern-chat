import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key_pair(username: str, key_size: int = 2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def create_directories():
    Path("private_keys").mkdir(exist_ok=True)
    Path("public_keys").mkdir(exist_ok=True)

def save_keys(username: str, private_pem: bytes, public_pem: bytes):
    private_file = Path("private_keys") / f"{username}.private.pem"
    public_file = Path("public_keys") / f"{username}.public.pem"
    
    with open(private_file, 'wb') as f:
        f.write(private_pem)
    
    with open(public_file, 'wb') as f:
        f.write(public_pem)
    
    private_file.chmod(0o600)
    
    print(f"Generated keys for {username}")
    print(f"  Private: {private_file}")
    print(f"  Public:  {public_file}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_keys.py <username1> [username2] ...")
        print("Example: python generate_keys.py alice bob charlie")
        sys.exit(1)
    
    usernames = sys.argv[1:]
    
    create_directories()
    
    for username in usernames:
        private_pem, public_pem = generate_key_pair(username)
        save_keys(username, private_pem, public_pem)

if __name__ == "__main__":
    main()