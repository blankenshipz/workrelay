"""Compatibility attestation command; use workrelay.attestor."""
from workrelay.attestor import main

if __name__ == "__main__":
    raise SystemExit(main())
