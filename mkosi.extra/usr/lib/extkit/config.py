"""Immutable configuration."""

import configparser
import math
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, NoReturn

from .errors import ConfigurationError


def fail(message) -> NoReturn:
    raise ConfigurationError(message)


@dataclass(frozen=True)
class BootUpdateConfig:
    staging_directory: Path

    def __post_init__(self):
        if not self.staging_directory.is_absolute():
            raise ConfigurationError('StagingDirectory must be absolute')


@dataclass(frozen=True)
class AddonConfig:
    boot_directory: Path = Path('/boot')
    architecture: str | None = None
    db_glob: str = '/sys/firmware/efi/efivars/db-*'

    def __post_init__(self):
        if not self.boot_directory.is_absolute():
            raise ConfigurationError('Addons BootDirectory must be absolute')
        if self.architecture not in (None, 'arm64', 'x86-64'):
            raise ConfigurationError('unsupported addon Architecture')


@dataclass(frozen=True)
class ExtkitConfig:
    state: Path
    root: Path
    base_directory: Path | None
    base_device: Path | None
    base_fstype: str
    overlay_uppers: tuple[tuple[Path, Path], ...]
    runtime_directory: Path
    enabled_dirs: Mapping[str, Path]
    runtime_dirs: Mapping[str, Path]
    erofs_tool: str
    erofs_fsck_tool: str
    phone_configuration: Path
    repart_tool: str
    boot_settings: BootUpdateConfig | None
    addon_settings: AddonConfig
    kinds: Mapping[str, tuple[str, ...]]
    excluded_trees: tuple[tuple[str, ...], ...]

    def __post_init__(self):
        for name in ('enabled_dirs', 'runtime_dirs', 'kinds'):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))
        object.__setattr__(self, 'overlay_uppers', tuple(self.overlay_uppers))
        if not self.phone_configuration.is_absolute():
            raise ConfigurationError('Phone Configuration must be absolute')


def _load_config(path):
    config = configparser.ConfigParser(interpolation=None)
    if not config.read(path):
        fail(f"configuration file not found: {path}")
    paths = config["Paths"]
    state = Path(paths["StateDirectory"])
    root = Path(paths["RootDirectory"])
    overlay_uppers = []
    for line in paths.get("OverlayUpperDirectories", "").splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 2:
            fail(f"expected 'UPPERDIR ROOT-PREFIX' in OverlayUpperDirectories: {line!r}")
        upper, prefix = map(Path, fields)
        if not upper.is_absolute() or not prefix.is_absolute():
            fail(f"overlay upperdir and root prefix must be absolute: {line!r}")
        if ".." in upper.parts or ".." in prefix.parts:
            fail(f"overlay upperdir and root prefix must not contain '..': {line!r}")
        overlay_uppers.append((upper, prefix))
    base_directory = Path(paths["BaseDirectory"]) if paths.get("BaseDirectory") else None
    base_device = Path(paths["BaseDevice"]) if paths.get("BaseDevice") else None
    base_fstype = paths["BaseFileSystem"]
    runtime_directory = Path(paths["RuntimeDirectory"])
    enabled_dirs = {
        "sysext": Path(paths["EnabledSysextDirectory"]),
        "confext": Path(paths["EnabledConfextDirectory"]),
    }
    runtime_dirs = {
        "sysext": Path(paths.get("RuntimeSysextDirectory", "/run/extensions")),
        "confext": Path(paths.get("RuntimeConfextDirectory", "/run/confexts")),
    }
    extensions = config["Extensions"]
    kinds = {}
    assigned_prefixes = set()
    for line in extensions.get("Kinds", "").splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 2:
            fail(f"expected 'TYPE PATH [PATH...]' in Kinds: {line!r}")
        kind, *prefix_values = fields
        if kind not in enabled_dirs:
            fail(f"unsupported extension type in Kinds: {kind!r}")
        if kind in kinds:
            fail(f"duplicate extension type in Kinds: {kind!r}")
        prefixes = []
        for value in prefix_values:
            prefix = Path(value)
            if not prefix.is_absolute() or ".." in prefix.parts or len(prefix.parts) != 2:
                fail(f"kind paths must be absolute top-level paths: {value!r}")
            name = prefix.parts[1]
            if name in assigned_prefixes:
                fail(f"kind path is assigned more than once: {value!r}")
            assigned_prefixes.add(name)
            prefixes.append(name)
        kinds[kind] = tuple(prefixes)
    if not kinds:
        fail("configure at least one Kinds entry")
    excluded = []
    for value in extensions.get("ExcludedTrees", "").splitlines():
        value = value.strip()
        if not value:
            continue
        path_value = Path(value)
        if not path_value.is_absolute() or ".." in path_value.parts:
            fail(f"excluded tree must be an absolute path: {value!r}")
        relative = path_value.relative_to("/")
        excluded.append(relative.parts)
    excluded_trees = tuple(excluded)
    erofs_tool = config["Build"]["ErofsTool"]
    erofs_fsck_tool = config["Build"].get("ErofsFsckTool", "fsck.erofs")
    phone_configuration = Path(config.get('Phone', 'Configuration', fallback='/etc/extkit-phone.conf'))
    boot_settings = (BootUpdateConfig(Path(config.get('BootUpdates', 'StagingDirectory',
                     fallback=str(state / 'boot-updates')))) if config.has_section('BootUpdates') else None)
    addon_settings = AddonConfig(
        boot_directory=Path(config.get('Addons', 'BootDirectory', fallback='/boot')),
        architecture=config.get('Addons', 'Architecture', fallback=None),
        db_glob=config.get('Addons', 'UefiDbGlob', fallback='/sys/firmware/efi/efivars/db-*'),
    )
    repart_tool = config["Build"].get("RepartTool", "systemd-repart")
    for name, configured_path in (("StateDirectory", state), ("RootDirectory", root),
                        ("RuntimeDirectory", runtime_directory),
                        *enabled_dirs.items(), *runtime_dirs.items()):
        if not configured_path.is_absolute():
            fail(f"{name} must be an absolute path: {configured_path}")
    if not base_directory and not base_device:
        fail("configure either BaseDirectory or BaseDevice")
    for name, optional_path in (("BaseDirectory", base_directory), ("BaseDevice", base_device)):
        if optional_path is not None and not optional_path.is_absolute():
            fail(f"{name} must be an absolute path: {optional_path}")
    if not overlay_uppers:
        fail("configure at least one OverlayUpperDirectories entry")

    return ExtkitConfig(
        state=state, root=root,
        base_directory=base_directory, base_device=base_device, base_fstype=base_fstype,
        overlay_uppers=tuple(overlay_uppers), runtime_directory=runtime_directory,
        enabled_dirs=enabled_dirs, runtime_dirs=runtime_dirs,
        erofs_tool=erofs_tool, erofs_fsck_tool=erofs_fsck_tool,
        phone_configuration=phone_configuration, repart_tool=repart_tool,
        boot_settings=boot_settings, addon_settings=addon_settings,
        kinds=kinds, excluded_trees=excluded_trees,
    )


@dataclass(frozen=True)
class PhoneConfig:
    boot_directory: Path = Path('/boot')
    service_type: str = '_extkit-sign._tcp'
    db_glob: str = '/sys/firmware/efi/efivars/db-*'
    extension_owner: uuid.UUID = uuid.UUID('48bdddca-5476-4ef5-8171-ceb413e1a549')
    connect_timeout: float = 10
    pairing_timeout: float = 120
    signing_timeout: float = 1800
    poll_interval: float = 2

    def __post_init__(self):
        if not self.boot_directory.is_absolute():
            raise ConfigurationError('BootDirectory must be absolute')
        for name in ('connect_timeout', 'pairing_timeout', 'signing_timeout', 'poll_interval'):
            value = getattr(self, name)
            if not math.isfinite(value) or value <= 0:
                raise ConfigurationError(f'{name} must be a finite positive number')


def _load_phone_config(path):
    parser = configparser.ConfigParser(interpolation=None)
    if not parser.read(path):
        raise ConfigurationError(f'configuration not found: {path}')
    section = parser['Network']
    return PhoneConfig(
        boot_directory=Path(section.get('BootDirectory', '/boot')),
        service_type=section.get('ServiceType', '_extkit-sign._tcp'),
        db_glob=section.get('UefiDbGlob', '/sys/firmware/efi/efivars/db-*'),
        extension_owner=uuid.UUID(section.get('ExtensionOwnerGuid', str(PhoneConfig.extension_owner))),
        **{field: section.getfloat(key, default) for field,key,default in (
            ('connect_timeout','ConnectTimeoutSeconds',10),('pairing_timeout','PairingTimeoutSeconds',120),
            ('signing_timeout','SigningTimeoutSeconds',1800),('poll_interval','PollIntervalSeconds',2))},
    )


def load_config(path: Path) -> ExtkitConfig:
    try:
        return _load_config(path)
    except (KeyError, ValueError, configparser.Error) as error:
        if isinstance(error, ConfigurationError):
            raise
        raise ConfigurationError(f'invalid ExtKit configuration {path}: {error}') from error


def load_phone_config(path: Path) -> PhoneConfig:
    try:
        return _load_phone_config(path)
    except (KeyError, ValueError, configparser.Error) as error:
        if isinstance(error, ConfigurationError):
            raise
        raise ConfigurationError(f'invalid phone configuration {path}: {error}') from error
