import argparse
import base64
import json
import os
import sys
from getpass import getpass
from typing import Dict, Any


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import InvalidToken
import secrets


iterations = 200_000

def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    raw = kdf.derive(password_bytes)
    key = base64.urlsafe_b64encode(raw)
    return key


def encrypt_data(key: bytes, data: Dict) -> bytes:
    json_text = json.dumps(data)
    raw_bytes = json_text.encode("utf-8")

    f = Fernet(key)
    encrypted = f.encrypt(raw_bytes)

    return encrypted

def decrypt_data(key: bytes, encrypted: bytes) -> Dict[str, Any]:
    f = Fernet(key)
    try:
        decrypted_bytes = f.decrypt(encrypted)
    except InvalidToken:
        print("Wrong password or corrupted vault.")
        sys.exit(1)

    json_text = decrypted_bytes.decode("utf-8")
    data = json.loads(json_text)
    return data


def save_vault(path: str, salt: bytes, encrypted: bytes) -> None:
    payload = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "data": base64.b64encode(encrypted).decode("ascii")
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)



def load_vault(path: str) -> tuple[bytes, bytes]:
    if not os.path.exists(path):
        raise FileNotFoundError("Vault file not found")

    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    salt = base64.b64decode(payload["salt"])
    encrypted = base64.b64decode(payload["data"])
    return salt, encrypted


def init_vault(path: str, password: str) -> None:
    if os.path.exists(path):
        print("Vault already exists.")
        sys.exit(1)

    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)

    empty_data = {}
    encrypted = encrypt_data(key, empty_data)

    save_vault(path, salt, encrypted)
    print("Vault created successfully.")
    
    
def open_vault(path: str, password: str) -> Dict[str, Any]:
    salt, encrypted = load_vault(path)
    key = derive_key(password, salt)
    data = decrypt_data(key, encrypted)
    return data


def write_vault(path: str, password: str, data: Dict[str, Any]) -> None:
    salt, _ = load_vault(path)
    key = derive_key(password, salt)
    encrypted = encrypt_data(key, data)
    save_vault(path, salt, encrypted)

def cmd_init(args):
    pw = getpass("Create master password: ")
    pw2 = getpass("Confirm master password: ")
    if pw != pw2:
        print("Passwords do not match.")
        sys.exit(1)
    init_vault(args.file, pw)


def cmd_add(args):
    pw = getpass("Master password: ")
    vault = open_vault(args.file, pw)

    name = args.name
    if name in vault and not args.force:
        print("Entry already exists. Use --force to overwrite.")
        return

    user = args.user or input("Username: ")
    secret = args.password or getpass("Password: ")
    note = args.note or ""

    vault[name] = {"user": user, "password": secret, "note": note}
    write_vault(args.file, pw, vault)
    print(f"Saved '{name}'")


def cmd_get(args):
    pw = getpass("Master password: ")
    vault = open_vault(args.file, pw)

    entry = vault.get(args.name)
    if not entry:
        print("Entry not found.")
        return

    print(json.dumps(entry, indent=2))


def cmd_list(args):
    pw = getpass("Master password: ")
    vault = open_vault(args.file, pw)

    for name in vault:
        print(name)


def cmd_delete(args):
    pw = getpass("Master password: ")
    vault = open_vault(args.file, pw)

    if args.name not in vault:
        print("Entry not found.")
        return

    confirm = input(f"Delete '{args.name}'? (y/N): ").lower()
    if confirm == "y":
        del vault[args.name]
        write_vault(args.file, pw, vault)
        print("Deleted.")


def build_parser():
    p = argparse.ArgumentParser(description="Encrypted CLI Password Vault")
    p.add_argument("-f", "--file", default="vault.json", help="Vault file path")

    sub = p.add_subparsers(dest="command", required=True)

    i = sub.add_parser("init")
    i.set_defaults(func=cmd_init)

    a = sub.add_parser("add")
    a.add_argument("-n", "--name", required=True)
    a.add_argument("-u", "--user")
    a.add_argument("-p", "--password")
    a.add_argument("--note")
    a.add_argument("--force", action="store_true")
    a.set_defaults(func=cmd_add)

    g = sub.add_parser("get")
    g.add_argument("-n", "--name", required=True)
    g.set_defaults(func=cmd_get)

    l = sub.add_parser("list")
    l.set_defaults(func=cmd_list)

    d = sub.add_parser("delete")
    d.add_argument("-n", "--name", required=True)
    d.set_defaults(func=cmd_delete)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
