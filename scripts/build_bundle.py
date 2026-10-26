"""Write and sign the advisory bundle. The private key stays outside the tree."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from sec_scanner.advisory import canonical_bytes, package_file_map  # noqa: E402
from sec_scanner.advisory_rules import document  # noqa: E402

DEFAULT_KEY = Path.home() / ".local" / "share" / "sec-scanner" / "advisory-ed25519.pem"
DATA = SRC / "sec_scanner" / "data"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign the PHP advisory bundle")
    parser.add_argument("--key", type=Path, default=DEFAULT_KEY)
    parser.add_argument("--generate", action="store_true")
    args = parser.parse_args(argv)
    key_path = args.key.expanduser()
    if args.generate:
        if key_path.exists():
            print(f"refusing to replace {key_path}", file=sys.stderr)
            return 2
        _generate(key_path)
    if not key_path.is_file():
        print(f"signing key is missing: {key_path}", file=sys.stderr)
        return 2
    private = _load(key_path)
    payload = canonical_bytes(document())
    signature = private.sign(payload)
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "bundle.json").write_bytes(payload)
    (DATA / "bundle.sig").write_text(signature.hex() + "\n", encoding="utf-8")
    public = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    (DATA / "public_key.pem").write_bytes(public)
    manifest = canonical_bytes({"files": package_file_map(DATA.parent)})
    (DATA / "manifest.json").write_bytes(manifest)
    (DATA / "manifest.sig").write_text(private.sign(manifest).hex() + "\n", encoding="utf-8")
    print(f"signed {DATA / 'bundle.json'}")
    print(f"signed {DATA / 'manifest.json'}")
    return 0


def _generate(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    # The key is stored unencrypted because this machine's file mode is the lock.
    # A passphrase would only move the secret into the shell history.
    pem = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    path.write_bytes(pem)
    os.chmod(path, 0o600)
    print(f"wrote {path}")


def _load(path: Path) -> Ed25519PrivateKey:
    raw = path.read_bytes()
    key = load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("signing key is not Ed25519")
    return key


if __name__ == "__main__":
    raise SystemExit(main())
