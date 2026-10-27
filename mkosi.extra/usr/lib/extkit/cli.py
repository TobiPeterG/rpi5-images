"""CLI parsing and explicit command dispatch only."""

import argparse
import subprocess
import sys
from pathlib import Path

from . import activation
from . import addon_commands
from . import addons
from . import boot_check
from . import boot_updates
from . import build as build_workflow
from . import config as configuration
from . import extensions
from . import metadata
from . import overlay
from . import signing
from .console import print
from .errors import ExtkitError


def main(argv=None):
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config", type=Path, default=Path("/etc/extkit.conf"))
    parser = argparse.ArgumentParser(
        description='Inspect live changes and build authenticated systemd extensions.', parents=[pre_parser])
    sub = parser.add_subparsers(dest="command")
    for command in ("status", "diff", "stage", "unstage", "build", "enable",
                    "disable", "inspect", "compare", "policy", "sync", "sign", "boot-check"):
        p = sub.add_parser(command)
        p.add_argument("--type", dest="kind", choices=('sysext', 'confext'))
        if command == "build":
            p.add_argument("name")
        elif command in ("enable", "disable"):
            p.add_argument("targets", nargs="+")
        elif command in ("inspect", "sign"):
            if command == 'sign':
                p.add_argument('name', nargs='?')
            else:
                p.add_argument('name')
            p.add_argument("version", nargs="?")
            if command == "sign":
                p.add_argument("--untrusted", action="store_true", help="sign every image not accepted by the current kernel trust policy")
        elif command == "compare":
            p.add_argument("--content", action="store_true", help="stream complete changed file bytes")
            p.add_argument("name")
            p.add_argument("versions", nargs="*", type=int)
        elif command == "policy":
            p.add_argument("name")
            p.add_argument("updates", choices=metadata.UPDATE_POLICIES)
        if command == "diff":
            p.add_argument("--staged", action="store_true")
            p.add_argument("--content", action="store_true", help="stream complete base/live bytes as hexadecimal.")
        if command in ("diff", "stage", "unstage"):
            p.add_argument("paths", nargs="*")
        if command == "build":
            p.add_argument("--updates", choices=metadata.UPDATE_POLICIES)
            p.add_argument("--no-sign", action="store_true", help="prepare images now and sign them later with extkit sign")
        if command in ("build", "policy"):
            p.add_argument("--preserve-content-labels", action="store_true",
                           help="keep SELinux labels on content files and symlinks")
    sub.add_parser("list").add_argument("--type", dest="kind", choices=('sysext', 'confext'))
    sub.add_parser("boot-update-check", help="show factory boot images staged by systemd-sysupdate")
    boot_update = sub.add_parser("boot-update", help="verify and send a staged factory boot image for phone signing")
    boot_update.add_argument("version", nargs="?", help="staged version, defaults to newest update")
    addon = sub.add_parser("addon", help="build, phone-sign and install command-line UKI addons")
    actions = addon.add_subparsers(dest="action", required=True)
    build = actions.add_parser("build")
    build.add_argument("name")
    content = build.add_mutually_exclusive_group(required=True)
    content.add_argument("--cmdline", help="exact additional kernel command-line parameters")
    content.add_argument("--machine-id", nargs="?", const="current", help="persist this ID, defaults to live /etc/machine-id")
    build.add_argument("--architecture", choices=addons.MACHINES)
    build.add_argument("--no-sign", action="store_true")
    for action in ("sign", "enable", "inspect"):
        item = actions.add_parser(action)
        item.add_argument("name")
        item.add_argument("version", nargs="?", type=int)
        if action == "sign":
            item.add_argument("--no-enable", action="store_true")
    actions.add_parser("disable").add_argument("name")
    actions.add_parser("list")
    args = parser.parse_args(argv)
    try:
        config = configuration.load_config(args.config)
    except (ExtkitError, OSError) as exc:
        parser.error(str(exc))
    if getattr(args, 'kind', None) is not None and args.kind not in config.kinds:
        parser.error(f'extension type is not configured: {args.kind}')
    show_help_after_status = args.command is None
    if show_help_after_status:
        args.command = "status"
        args.kind = None
    if args.command in ("enable", "disable"):
        targets = overlay.normalize_shell_glob(args.targets)
        if targets == ["*"]:
            args.name, args.version = "*", None
        elif args.command == "enable" and len(targets) in (1, 2):
            args.name, args.version = targets[0], targets[1] if len(targets) == 2 else None
        elif args.command == "disable" and len(targets) == 1:
            args.name, args.version = targets[0], None
        else:
            parser.error("enable expects NAME [VERSION] or '*'. Disable expects NAME or '*'")
    if args.command == "compare" and len(args.versions) == 1:
        parser.error("compare expects NAME or NAME VERSION VERSION [VERSION ...]")
    if args.command in ("sync", "boot-check") and args.kind is None:
        parser.error(f"{args.command} requires --type")
    handlers = {
        'sign': signing.command_sign,
        'boot-check': boot_check.command_boot_check,
        'sync': activation.command_sync,
        'build': build_workflow.command_build,
        'policy': build_workflow.command_policy,
        'diff': extensions.command_diff,
        'stage': extensions.command_stage,
        'unstage': extensions.command_unstage,
        'enable': extensions.command_enable,
        'disable': extensions.command_disable,
        'inspect': extensions.command_inspect,
        'compare': extensions.command_compare,
        'status': extensions.command_status,
        'list': extensions.command_list,
        'addon': addon_commands.command_addon,
        'boot-update-check': boot_updates.command_boot_update_check,
        'boot-update': boot_updates.command_boot_update,
    }
    try:
        handlers[args.command](config, args)
        if show_help_after_status:
            print()
            parser.print_help()
    except (ExtkitError, OSError, subprocess.SubprocessError) as exc:
        print(f"extkit: {exc}", file=sys.stderr, color="red")
        raise SystemExit(1)
