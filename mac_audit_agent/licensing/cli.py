from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path

from .activation import ActivationError
from .manager import LicenseManager
from .verifier import LicenseVerificationError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="msaa licensing", description="MSAA signed product licensing and activation.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "device-code", "doctor"):
        command = subparsers.add_parser(name)
        command.add_argument("--json", action="store_true")
    importer = subparsers.add_parser("import", help="Verify and install a signed offline license.")
    importer.add_argument("path", type=Path)
    importer.add_argument("--json", action="store_true")
    activate = subparsers.add_parser("activate", help="Exchange an activation code for a signed license over HTTPS.")
    activate.add_argument("--code", help="Activation code. Omit to use a hidden interactive prompt.")
    activate.add_argument("--endpoint", help="HTTPS endpoint override for the bundled Liquidsky activation service.")
    activate.add_argument("--json", action="store_true")
    checkout = subparsers.add_parser("checkout", help="Create a Stripe Checkout Session for this installation.")
    checkout.add_argument("--endpoint", help="HTTPS endpoint override for the bundled Liquidsky Stripe service.")
    checkout.add_argument("--email", default="", help="Optional email to prefill in Stripe Checkout.")
    checkout.add_argument("--licensed-to", default="", help="Optional organization or customer display name.")
    checkout.add_argument("--json", action="store_true")
    feature = subparsers.add_parser("feature", help="Explain whether a feature is available.")
    feature.add_argument("name")
    feature.add_argument("--json", action="store_true")
    return parser


def _emit(value: dict, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, indent=2, sort_keys=True))
        return
    for key, item in value.items():
        if isinstance(item, (dict, list, tuple)):
            print(f"{key.replace('_', ' ').title()}: {json.dumps(item, sort_keys=True)}")
        else:
            print(f"{key.replace('_', ' ').title()}: {item}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manager = LicenseManager()
        if args.command == "status":
            status = manager.status()
            result = {**status.to_dict(), "product_access": manager.product_access(status)}
        elif args.command == "device-code":
            result = {"product_id": manager.policy.product_id, "device_fingerprint": manager.device_fingerprint(), "secret": False}
        elif args.command == "doctor":
            result = manager.doctor()
        elif args.command == "import":
            result = manager.import_offline(args.path).to_dict()
        elif args.command == "activate":
            code = args.code or getpass.getpass("MSAA activation code (input hidden): ")
            result = manager.activate_online(code, endpoint=args.endpoint).to_dict()
        elif args.command == "checkout":
            result = manager.begin_stripe_checkout(
                endpoint=args.endpoint,
                customer_email=args.email,
                licensed_to=args.licensed_to,
            )
        else:
            result = manager.feature_decision(args.name)
    except (ActivationError, LicenseVerificationError, OSError, TypeError, ValueError) as exc:
        result = {"status": "REJECTED", "error_code": getattr(exc, "code", "LIC_OPERATION_FAILED"), "message": str(exc), "core_protection_active": True}
        _emit(result, as_json=bool(args.json))
        return 2
    _emit(result, as_json=bool(args.json))
    state = str(result.get("state", result.get("status", "")))
    return 0 if state in {"VALID", "EXPIRING", "PASS", ""} or bool(result.get("available")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
