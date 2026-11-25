"""Weekly sync of the Client Matter Table (Google Sheet) into data/matters.enc.json.

The site and repo are public, so the matter list is committed only in encrypted form:
PBKDF2-SHA256 derives an AES-256-GCM key from MATTERS_PASSPHRASE, and the dashboard
decrypts it in the browser with the same passphrase (WebCrypto).

Env:
  GOOGLE_SERVICE_ACCOUNT_JSON  service-account key JSON (the sheet is shared with it, Viewer)
  MATTERS_PASSPHRASE           passphrase the dashboard asks for
  MATTERS_SHEET_ID             optional override of the spreadsheet ID
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from hashlib import pbkdf2_hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google.auth.transport.requests import Request
from google.oauth2 import service_account

SHEET_ID   = os.environ.get('MATTERS_SHEET_ID') or '1IRjFL880DF2CbByjhynMCiiYiYKG32pLicxT0Ywa4jo'
SHEET_TAB  = 'Client Matters'
OUTPUT     = 'data/matters.enc.json'
ITERATIONS = 600_000
SCOPES     = ['https://www.googleapis.com/auth/spreadsheets.readonly']

b64   = lambda b: base64.b64encode(b).decode()
unb64 = base64.b64decode


def fetch_rows():
    info  = json.loads(os.environ['GOOGLE_SERVICE_ACCOUNT_JSON'])
    creds = service_account.Credentials.from_service_account_info(info, scopes=SCOPES)
    creds.refresh(Request())
    rng = urllib.parse.quote(f"'{SHEET_TAB}'!A:Z")
    req = urllib.request.Request(
        f'https://sheets.googleapis.com/v4/spreadsheets/{SHEET_ID}/values/{rng}',
        headers={'Authorization': f'Bearer {creds.token}'},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r).get('values', [])


def to_matters(rows):
    if not rows:
        raise SystemExit('Sheet is empty.')
    head = [h.strip().lower() for h in rows[0]]

    def col(*names):
        return next((i for i, h in enumerate(head) if h in names), -1)

    ci = col('client no.', 'client no', 'client number', 'client')
    mi = col('matter no.', 'matter no', 'matter number', 'matter')
    cn = col('client name')
    md = col('matter description', 'description', 'matter name')
    if min(ci, mi, md) < 0:
        raise SystemExit(f'Missing a required column; found headers: {rows[0]}')

    cell = lambda r, i: (r[i].strip() if 0 <= i < len(r) else '')
    out = []
    for r in rows[1:]:
        c, m = cell(r, ci), cell(r, mi)
        if c and m:
            out.append([c, m, cell(r, cn), cell(r, md)])
    if not out:
        raise SystemExit('No matters found in sheet.')
    return out


def derive(passphrase, salt):
    return pbkdf2_hmac('sha256', passphrase.encode(), salt, ITERATIONS, 32)


def load_existing(passphrase):
    """Return (salt, matters) from the current file, or (None, None)."""
    try:
        with open(OUTPUT) as f:
            env = json.load(f)
        salt = unb64(env['salt'])
        plain = AESGCM(derive(passphrase, salt)).decrypt(unb64(env['iv']), unb64(env['ct']), None)
        return salt, json.loads(plain)['matters']
    except Exception:
        return None, None


def main():
    passphrase = os.environ.get('MATTERS_PASSPHRASE', '')
    if not passphrase or not os.environ.get('GOOGLE_SERVICE_ACCOUNT_JSON'):
        print('Matter sync secrets not configured; skipping.')
        return

    matters = to_matters(fetch_rows())
    salt, previous = load_existing(passphrase)
    if previous == matters:
        print(f'{len(matters)} matters; unchanged.')
        return

    # Keep the salt stable so browsers that saved the derived key keep working.
    salt = salt or os.urandom(16)
    iv   = os.urandom(12)
    now  = datetime.now(timezone.utc).isoformat()
    plain = json.dumps({'updated': now, 'matters': matters}, ensure_ascii=False).encode()
    ct = AESGCM(derive(passphrase, salt)).encrypt(iv, plain, None)

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, 'w') as f:
        json.dump({'v': 1, 'kdf': 'PBKDF2-SHA256', 'iter': ITERATIONS,
                   'salt': b64(salt), 'iv': b64(iv), 'ct': b64(ct), 'updated': now}, f, indent=2)
        f.write('\n')
    print(f'{len(matters)} matters written to {OUTPUT}.')


if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as e:
        sys.exit(f'Sheets API error {e.code}: {e.read().decode()[:500]}')
