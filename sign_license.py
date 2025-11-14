# sign_license.py — offline keygen for Curator Finder
# Usage:
#   python sign_license.py EMAIL DEVICE_ID DAYS [DEVICE_ID_2 ...]
#
# Example:
#   python sign_license.py buyer@example.com 3f9c8a2d1e6b4ab... 365
#   python sign_license.py buyer@example.com 3f9c... 365 9a1b...   # 2 devices

import json, base64, time, sys
from nacl.signing import SigningKey

def compact(d): return json.dumps(d, separators=(",",":"), ensure_ascii=False)

def main():
    if len(sys.argv) < 4:
        print("Usage: python sign_license.py EMAIL DEVICE_ID DAYS [DEVICE_ID_2 ...]")
        sys.exit(1)
    email = sys.argv[1]
    days  = int(sys.argv[3])
    devices = [sys.argv[2]] + sys.argv[4:] if len(sys.argv) > 4 else [sys.argv[2]]

    payload = {
        "v": 1,
        "email": email,
        "exp": int(time.time()) + days*24*3600,
        "machine": devices[0] if len(devices)==1 else devices
    }
    msg = compact(payload).encode("utf-8")

    # keep license_private.key SAFE and OUT of your repo
    sk = SigningKey(open("license_private.key","rb").read())
    sig = sk.sign(msg).signature

    token = {"payload": payload, "sig": base64.b64encode(sig).decode()}
    fn = f"license_{email.replace('@','_')}.json"
    open(fn, "w", encoding="utf-8").write(json.dumps(token, indent=2))
    print("Wrote", fn)

if __name__ == "__main__":
    main()
