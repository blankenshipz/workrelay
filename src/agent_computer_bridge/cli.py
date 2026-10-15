"""Compatibility command module; durable ledger identifiers remain unchanged."""
from workrelay.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
