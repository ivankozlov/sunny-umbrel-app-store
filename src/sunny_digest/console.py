"""Owner console commands; bootstrap output is not an application log."""
from __future__ import annotations

import argparse
import getpass
import json
import os

from .authn import WebAuthnAuthorizer
from .migrate_vault import legacy_inventory, write_manifest
from .storage import Paths, atomic_write_json
from .web import IPCClient


def main(args):
    if os.getuid() != 1000:
        raise PermissionError("use the guardian container as uid 1000")
    paths = Paths.from_env()
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("bootstrap", "configure-origin", "migration-check", "repair-manifest"))
    parser.add_argument("--origin")
    parser.add_argument("--rp-id")
    options = parser.parse_args(args)
    if options.command == "configure-origin":
        validator = WebAuthnAuthorizer(trusted_origin=options.origin, rp_id=options.rp_id)
        path = paths.config_dir / "security-origin.json"
        if path.exists() or (paths.private_dir / "vault.json").exists():
            raise RuntimeError("origin is already fixed; recovery requires a reviewed procedure")
        atomic_write_json(path, {"origin": validator.trusted_origin, "rp_id": validator.rp_id})
        print("Origin configured. Restart guardian before bootstrap.")
    elif options.command == "migration-check":
        print(json.dumps({"legacy": legacy_inventory(paths),
                          "vault_exists": (paths.private_dir / "vault.json").exists()}, ensure_ascii=False))
    elif options.command == "repair-manifest":
        # This privileged local recovery never replaces a passkey or removes
        # plaintext. It reconstructs browser hints from the encrypted canon.
        from .guardian import Guardian
        from pathlib import Path
        guardian = Guardian(paths, scratch=Path(os.environ.get("SUNNY_SCRATCH_DIR", "/run/guardian-private")))
        try:
            guardian.vault.unlock(getpass.getpass("Vault passphrase: "))
            guardian._check_runtime_state()
            write_manifest(paths, guardian.vault)
        finally:
            guardian.vault.close()
        print("Browser hints repaired; guardian remains locked. Complete passkey verification in the HTTPS UI.")
    else:
        result = IPCClient(str(paths.runtime_dir / "ipc/admin/admin.sock")).request("console_bootstrap")
        print(result["token"])
    return 0
