"""Terminal commands for selecting, inspecting and activating local extensions."""

import os
import stat
import sys
from pathlib import Path

from . import addon_commands
from . import boot_updates
from . import diff
from . import images
from . import overlay
from . import quarantine
from . import status
from . import store
from . import validation
from .config import ExtkitConfig
from .console import print
from .diff import image_entries
from .errors import fail
from .filesystem import state_transaction
from .status import mounted_extensions


def command_diff(config: ExtkitConfig, args):
    staged = set(store.staged_paths(config, args.kind))
    show_staged = getattr(args, "staged", False)
    candidates = staged if show_staged else set(overlay.changed_paths(config, args.kind)) - staged
    paths = overlay.select_paths(args.paths, candidates, "staged" if show_staged else "unstaged")
    with overlay.base_tree(config) as base:
        for path in paths:
            try:
                diff.show_diff(config, base, overlay.relative_path(config, path, args.kind), content=getattr(args,"content",False))
            except ValueError as exc:
                print(f"Skipped {path}: {exc}", file=sys.stderr, color="yellow")


@state_transaction
def _stage(config: ExtkitConfig, args):
    paths = overlay.select_paths(args.paths, overlay.changed_paths(config, args.kind), "changed")
    deletions = set(store.load_deletions(config))
    selection = set(store.load_selection(config))
    staged = 0
    skipped = []
    for path in paths:
        relative = overlay.relative_path(config, path, args.kind)
        try:
            overlay.live_file(config, relative)
        except ValueError as exc:
            if not overlay.is_whiteout(config, relative):
                skipped.append((path, exc))
                continue
            deletions.add(path)
            selection.discard(path)
        else:
            selection.add(path)
            deletions.discard(path)
        staged += 1
    store.save_index(config, selection, deletions)
    print(f"Staged {staged} path(s). {len(selection) + len(deletions)} total. Content will be read at build time", color="green")
    for path, skipped_error in skipped:
        print(f"Skipped {path}: {skipped_error}", file=sys.stderr, color="yellow")


@state_transaction
def _unstage(config: ExtkitConfig, args):
    selection = set(store.load_selection(config))
    deletions = set(store.load_deletions(config))
    for path in overlay.select_paths(args.paths, store.staged_paths(config, args.kind), "staged"):
        selection.discard(path)
        deletions.discard(path)
    store.save_index(config, selection, deletions)
    print(f"{len(selection) + len(deletions)} staged path(s) remain")


@state_transaction
def command_enable(config: ExtkitConfig, args):
    if args.name == "*":
        if args.version is not None:
            fail("a version cannot be specified when enabling '*'")
        candidates = []
        for kind in (args.kind,) if args.kind else config.kinds:
            newest: dict[str, tuple[str, Path]] = {}
            directory = store.store_dir(config, kind)
            for image in directory.glob("*.raw") if directory.exists() else []:
                parsed = store.split_image_name(image)
                if parsed is None:
                    continue
                name, version = parsed
                current = newest.get(name)
                if current is None or store.version_key(version) > store.version_key(current[0]):
                    newest[name] = (version, image)
            for name, (_, image) in sorted(newest.items()):
                link = store.enabled_dir(config, kind) / f"{name}.raw"
                if not link.exists() and not link.is_symlink():
                    candidates.append((kind, name, image))
        if not candidates:
            fail("no disabled extensions found")
        for kind, name, image in candidates:
            link = store.enable_image(config, kind, name, image)
            print(f"Enabled on next boot: {link} -> {image}", color="green")
        return
    validation.checked_name(args.name)
    candidates = store.requested_images(config, args.name, args.version, args.kind)
    for kind, image in candidates:
        link = store.enable_image(config, kind, args.name, image)
        print(f"Enabled on next boot: {link} -> {image}", color="green")


@state_transaction
def command_disable(config: ExtkitConfig, args):
    if args.name == "*":
        candidates = []
        for kind in (args.kind,) if args.kind else config.kinds:
            directory = store.enabled_dir(config, kind)
            for link in sorted(directory.glob("*.raw")) if directory.exists() else []:
                if link.is_symlink() and link.resolve().is_relative_to(store.store_dir(config, kind)):
                    candidates.append((kind, link))
        if not candidates:
            fail("no managed enabled extensions found")
        for kind, link in candidates:
            link.unlink()
            print(f"Disabled on next boot: {kind}/{link.stem}", color="green")
        return
    validation.checked_name(args.name)
    candidates = []
    for kind in (args.kind,) if args.kind else config.kinds:
        link = store.enabled_dir(config, kind) / f"{args.name}.raw"
        if link.is_symlink() and link.resolve().is_relative_to(store.store_dir(config, kind)):
            candidates.append((kind, link))
    if not candidates:
        fail(f"no managed enabled images for {args.name}")
    for kind, link in candidates:
        link.unlink()
        print(f"Disabled on next boot: {kind}/{args.name}", color="green")


def command_inspect(config: ExtkitConfig, args):
    for kind, image in store.requested_images(config, args.name, args.version, args.kind):
        print(f"{kind} {image.name}:")
        with images.image_tree(config, image) as tree:
            for relative, path in sorted(image_entries(tree).items()):
                print(f"  {describe_entry(path, relative)}")


def command_compare(config: ExtkitConfig, args):
    validation.checked_name(args.name)
    pairs: list[tuple[str, Path, Path]] = []
    for kind in (args.kind,) if args.kind else config.kinds:
        versions = store.image_versions(config, kind, args.name)
        if args.versions:
            requested = [int(value) for value in args.versions]
            if all(version in versions for version in requested):
                pairs.extend(
                    (kind, versions[old_version], versions[new_version])
                    for old_version, new_version in zip(requested, requested[1:])
                )
        elif len(args.versions) == 0 and len(versions) >= 2:
            newest = sorted(versions)[-2:]
            pairs.append((kind, versions[newest[0]], versions[newest[1]]))
    if not pairs:
        fail("compare needs at least two existing versions")
    for kind, old, new in pairs:
        print(f"{kind}: {old.name} -> {new.name}")
        with images.image_tree(config, old) as old_tree, images.image_tree(config, new) as new_tree:
            diff.show_image_difference(old_tree, new_tree, old.name, new.name,
                                       content=getattr(args, "content", False),
                                       content_command=f"extkit compare {args.name} {store.split_image_name(old)[1]} {store.split_image_name(new)[1]} --type {kind} --content")


def command_status(config: ExtkitConfig, args):
    index = store.load_index(config)
    selection, deletions = set(index['selected']), set(index['deleted'])
    changed = set(overlay.changed_paths(config, args.kind))
    staged = sorted(path for path in selection | deletions if args.kind is None or overlay.kind_for(config, overlay.relative_path(config, path)) == args.kind)
    print("Staged:")
    for path in staged:
        print(f"  {path}" + (" (deleted)" if path in deletions else ""))
    print("Unstaged:")
    for path in sorted(changed - selection - deletions):
        print(f"  {path}")
    print("Extensions:")
    quarantine.print_quarantine(config, args.kind)
    for kind in config.kinds:
        if args.kind is not None and kind != args.kind:
            continue
        mounted = mounted_extensions(config, kind)
        mounted_text = "unknown" if mounted is None else ", ".join(sorted(mounted)) or "none"
        print(f"  {kind}:")
        print(f"    mounted: {mounted_text}")
        states = status.collect(config, kind, mounted=mounted)
        if not states:
            print('    images: none')
            continue
        print('    images:')
        for item in states:
            details = (f'updates: {item.policy}. signature: {item.signature.presence.value}. '
                       f'trust: {item.signature.trust.value}')
            if item.enabled:
                mounted_text = ('unknown (name active. Exact version not identified)' if item.name_mounted else
                                'unknown' if item.mounted is None else 'yes' if item.mounted else 'no')
                print(f'      {item.image.name}: enabled since {item.enabled_since}. '
                      f'{details}. mounted: {mounted_text}')
            else:
                print(f'      {item.image.name}: disabled. {details}')
    if args.kind is None:
        print("UKI addons:")
        addon_commands.print_addon_status(config, indent="  ")
    if config.boot_settings is not None and args.kind is None:
        boot_updates.command_boot_update_check(config, args)


def command_list(config: ExtkitConfig, args):
    for kind in config.kinds:
        if args.kind is not None and kind != args.kind:
            continue
        for item in status.collect(config, kind, include_policy=False):
            state = 'enabled' if item.enabled else 'disabled'
            print(f'{kind}\t{item.name}\t{item.image.name}\t{state}\t'
                  f'signature: {item.signature.presence.value}\ttrust: {item.signature.trust.value}')


def describe_entry(path, relative):
    info = path.lstat()
    mode = stat.filemode(info.st_mode)
    if path.is_symlink():
        return f"l {mode} /{relative} -> {os.readlink(path)}"
    if stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(0, 0):
        return f"w {mode} /{relative} (deletion whiteout)"
    if path.is_dir():
        return f"d {mode} /{relative}"
    if path.is_file():
        return f"f {mode} {info.st_size:>9} /{relative}"
    return f"? {mode} /{relative}"


def command_stage(config: ExtkitConfig, args):
    args.paths = overlay.normalize_shell_glob(args.paths)
    return _stage(config, args)


def command_unstage(config: ExtkitConfig, args):
    args.paths = overlay.normalize_shell_glob(args.paths)
    return _unstage(config, args)
