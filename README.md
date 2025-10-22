# ASPXAuth Forge

**Generate legacy ASP.NET `.ASPXAUTH` authentication cookies**  
for authorized security testing, red-team labs, or research environments.

> **Legal & Ethical Notice**  
> This tool must **only** be used against systems you are explicitly authorized to test.  
> The author and repository owner assume no responsibility for misuse.

---

## What It Does

Classic ASP.NET applications (Framework 2.x–4.x) often rely on **Forms Authentication**
and issue a cookie named `.ASPXAUTH`.  
This cookie contains an encrypted and HMAC-signed “ticket” describing the user, roles,
expiration, and other metadata.

`aspxauth_forge.py` lets you **generate compatible cookies** when you already know
(or have recovered) the app’s `validationKey` and `decryptionKey` from its `web.config`.

It’s primarily intended for:
- Red-team operators reproducing legacy auth behavior in lab environments  
- Developers performing compatibility testing or forensic reconstruction  
- Pentesters validating weak machineKey configurations (authorized scope)

---

## Features

| Capability | Description |
|-------------|--------------|
| AES-CBC (zero IV) + HMAC-SHA256 | Matches legacy FormsAuth crypto |
| Custom username / roles / groups | Controlled via `--username`, `--roles`, or `--user-data` |
| Configurable ticket lifetime | `--lifetime-hours` sets the internal expiration checked by the server |
| Optional `Set-Cookie` output | Generates a ready-to-paste `Set-Cookie` header |
| Safety gate | Refuses to print cookie material unless `--i-know-what-im-doing` is set |
| Dry-run mode | Validates key and data handling without emitting secrets |
| Cross-platform | Pure Python 3.9+, no .NET dependency |

---

## Installation

```bash
python3 -m pip install pycryptodome
