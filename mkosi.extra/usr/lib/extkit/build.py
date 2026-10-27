"""Reserve a version, build outside state locks, then revalidate and publish."""

import os
import stat
import tempfile
from contextlib import ExitStack
from pathlib import Path

from . import filesystem, images, metadata, overlay, process, selinux, signing, store, validation
from .config import ExtkitConfig
from .console import print
from .errors import InstallationError, PublicationError, fail


def _publish(config: ExtkitConfig, drafts, outputs, requests, previous, index, built, deleted):
    # Copy bytes on the destination filesystem before taking the state lock.
    with ExitStack() as staging:
        prepared = []
        for kind, output in outputs.items():
            for source, destination in ((drafts[kind], output), (requests[kind], output.with_suffix('.extsign'))):
                temporary = staging.enter_context(filesystem.staged_copy(source, destination))
                prepared.append((temporary, destination))
        created = []
        with filesystem.locked_state(config.state):
            for kind in outputs:
                name = store.split_image_name(outputs[kind])[0]
                if store.image_versions(config, kind, name) != previous[kind]:
                    raise InstallationError('extension versions changed during build. Retry without losing staged paths')
            try:
                for temporary, destination in prepared:
                    if destination.exists() or destination.is_symlink():
                        raise InstallationError(f'refusing to overwrite build output: {destination}')
                    created.append(destination)
                    filesystem.publish_file(temporary, destination)
                if index is not None:
                    if store.load_index(config) == index:
                        store.save_index(config, set(index['selected']) - built, set(index['deleted']) - deleted)
                    else:
                        print('WARNING: staging changed during build. Keeping the current staging index.', color='yellow')
            except BaseException as error:
                if isinstance(error, PublicationError) and error.destination == store.selection_file(config):
                    # The new index is already visible.
                    print('WARNING: Build outputs and the updated staging index are visible, '
                          'but index durability could not be confirmed. Keep the outputs. '
                          'Inspect extkit status before retrying.', color='yellow')
                    raise
                for destination in reversed(created):
                    destination.unlink(missing_ok=True)
                raise


def _build(config: ExtkitConfig, args, policy_only=False):
    validation.checked_name(args.name)
    signing.warn_if_signing_key_unenrolled(config)
    with filesystem.locked_state(config.state):
        previous = {kind: store.image_versions(config, kind, args.name) for kind in config.kinds}
        index = None if policy_only else store.load_index(config)
        selected = [] if index is None else index['selected']
        deleted = [] if index is None else index['deleted']
        if not policy_only and not selected and not deleted:
            fail('selection is empty')
        grouped: dict[str, list[Path]] = {kind: [] for kind in config.kinds}
        removals: dict[str, list[Path]] = {kind: [] for kind in config.kinds}
        for paths, groups in ((selected, grouped), (deleted, removals)):
            for value in paths:
                relative = overlay.relative_path(config, value)
                groups[overlay.kind_for(config, relative)].append(relative)
        kinds = [kind for kind in config.kinds if (args.kind is None or args.kind == kind)
                 and (bool(previous[kind]) if policy_only else bool(grouped[kind] or removals[kind]))]
        if not kinds:
            fail(f'no matching built images for {args.name}' if policy_only else f'selection has no {args.kind} paths')
        enabled = {kind: store.activation_stamp(config, kind, args.name) for kind in kinds}
        reservation, version = store.reserve_version(config, args.name)
    try:
        policies = {}
        for kind in kinds:
            latest = previous[kind].get(max(previous[kind])) if previous[kind] else None
            requested = getattr(args, 'updates', None)
            inherited = metadata.embedded_update_policy(config, kind, latest)[0] if latest and not requested else 'persistent'
            policies[kind] = requested or inherited
        outputs = {kind: store.store_dir(config, kind) / f'{args.name}_{version}.raw' for kind in kinds}
        workdir = config.state / 'work'
        workdir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='extkit-', dir=workdir) as work:
            drafts, requests = {}, {}
            for kind in kinds:
                tree = Path(work) / kind / 'tree'
                tree.mkdir(parents=True)
                preserve = getattr(args, 'preserve_content_labels', False)
                inherited_tree = Path(work) / kind / 'inherited'
                if previous[kind] and preserve:
                    inherited_tree.mkdir()
                    images.copy_image_tree(config, previous[kind][max(previous[kind])], inherited_tree)
                    for directory, names, _ in os.walk(inherited_tree, followlinks=False):
                        for name in names:
                            source = Path(directory) / name
                            if not source.is_symlink():
                                (tree / source.relative_to(inherited_tree)).mkdir(parents=True, exist_ok=True)
                elif previous[kind]:
                    images.copy_image_tree(config, previous[kind][max(previous[kind])], tree)
                metadata_dir = 'usr/lib' if kind == 'sysext' else 'etc'
                metadata_file = tree / metadata_dir / 'extension-release.d' / f'extension-release.{args.name}'
                if preserve:
                    for relative in grouped[kind] + removals[kind]:
                        (tree / relative).parent.mkdir(parents=True, exist_ok=True)
                    metadata.release_metadata(config, tree, args.name, kind, str(version), policies[kind])
                    selinux.label_paths(tree, [tree])
                    if previous[kind]:
                        process.run(['cp', '-a', f'{inherited_tree}/.', str(tree)], check=True)
                for relative in grouped[kind]:
                    overlay.copy_selected(overlay.live_file(config, relative), tree / relative)
                whiteouts = []
                for relative in removals[kind]:
                    target = tree / relative
                    overlay.remove_path(target)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    os.mknod(target, stat.S_IFCHR, os.makedev(0, 0))
                    whiteouts.append(target)
                metadata.release_metadata(config, tree, args.name, kind, str(version), policies[kind])
                selinux.label_paths(tree, [metadata_file, *whiteouts] if preserve else [tree])
                draft = Path(work) / f'{kind}.raw'
                process.run([config.erofs_tool, str(draft), str(tree)], check=True)
                drafts[kind] = draft
            for kind in kinds:
                ddi = Path(work) / f'{kind}-ddi.raw'
                request = Path(work) / f'{kind}.extsign'
                images.prepare_ddi(config, drafts[kind], ddi, request, args.name, str(version), kind)
                drafts[kind], requests[kind] = ddi, request
            _publish(config, drafts, outputs, requests, previous, index,
                     {'/' + str(path) for kind in kinds for path in grouped[kind]},
                     {'/' + str(path) for kind in kinds for path in removals[kind]})
        for kind, output in outputs.items():
            print(f'Built unsigned disabled {kind} image: {output}', color='green')
        return outputs, version, enabled
    finally:
        store.release_reservation(config, reservation)


def command_build(config: ExtkitConfig, args):
    outputs, version, enabled = _build(config, args)
    signing.offer_build_signing(config, outputs, args.name, str(version), enabled,
                               no_sign=getattr(args, 'no_sign', False))


def command_policy(config: ExtkitConfig, args):
    outputs, version, enabled = _build(config, args, policy_only=True)
    signing.offer_build_signing(config, outputs, args.name, str(version), enabled)
