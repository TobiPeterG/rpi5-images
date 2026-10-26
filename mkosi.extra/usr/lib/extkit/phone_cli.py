"""phone CLI."""

import argparse

from . import phone_service
from .config import load_phone_config as load_config


def main(argv=None):
    parser = argparse.ArgumentParser(description='Enroll a phone and send artifacts for review and signing.')
    parser.add_argument("--config", default="/etc/extkit-phone.conf")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("discover", help="list visible signers and Secure Boot enrollment status")
    enrollment = commands.add_parser("check-enrollment", help="check for a user key in the live Secure Boot db")
    enrollment.add_argument("--quiet", action="store_true")
    commands.add_parser("setup", help="set up phone signing if no user key is enrolled")
    send = commands.add_parser("send", help="send an extension, UKI addon or boot signing request for on-phone review")
    send.add_argument("input", nargs="+", help="one boot.img/.bootsign/.addonsign, or one or more .extsign requests")
    send.add_argument("--kind", choices=("auto", "extension", "boot", "addon"), default="auto")
    send.add_argument("--output", help="destination for the signed extension or addon.")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    if args.command == "discover":
        return phone_service.command_discover(config)
    if args.command == "check-enrollment":
        return phone_service.command_check_enrollment(config, args.quiet)
    if args.command == "setup":
        return phone_service.command_setup(config)
    outcomes = phone_service.send(config, args.input, kind=args.kind, output=args.output)
    phone_service.retry_receipts(config, outcomes)
    return int(any(not outcome.artifact.complete for outcome in outcomes))
