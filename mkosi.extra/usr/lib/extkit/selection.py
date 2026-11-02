"""Path patterns, command selection and display policies."""

from dataclasses import dataclass
import fnmatch
from functools import cache
import glob
from pathlib import Path

from .errors import fail


def parse_pattern(value):
    pattern = Path(value)
    if '..' in pattern.parts or (not pattern.is_absolute() and len(pattern.parts) != 1):
        fail(f'expected an absolute path pattern or a single name pattern: {value!r}')
    return pattern.relative_to('/').parts if pattern.is_absolute() else ('**', *pattern.parts)


def match_depth(pattern, parts, minimum=0):
    """Find a matching path prefix."""
    @cache
    def visit(pattern_index, path_index):
        if pattern_index == len(pattern):
            return path_index if path_index >= minimum else None
        if pattern[pattern_index] == '**':
            result = visit(pattern_index + 1, path_index)
            return result if result is not None else (
                visit(pattern_index, path_index + 1) if path_index < len(parts) else None)
        if (path_index < len(parts) and
                fnmatch.fnmatchcase(parts[path_index], pattern[pattern_index])):
            return visit(pattern_index + 1, path_index + 1)
        return None
    return visit(0, 0)


def excluded_path(config, relative):
    """Exclusions are literal subtrees."""
    return any(relative.parts[:len(prefix)] == prefix for prefix in config.excluded_trees)


def ignored_depth(patterns, parts):
    depths = [depth for pattern in patterns
              if (depth := match_depth(pattern, parts)) is not None]
    return min(depths, default=None)


def ignored_path(config, relative):
    return ignored_depth(config.ignored_paths, relative.parts) is not None


def normalize_shell_glob(patterns):
    """Recognize an unquoted '*' after the shell expanded it in the current directory."""
    expanded = glob.glob('*')
    if patterns and len(patterns) == len(expanded) and set(patterns) == set(expanded):
        return ['*']
    return patterns


@dataclass(frozen=True)
class Selector:
    source: str
    pattern: tuple[str, ...]
    named_prefixes: tuple[tuple[str, ...], ...]

    @classmethod
    def parse(cls, value):
        parts = parse_pattern(value)
        # Literal names identify selections inside ignored subtrees.
        return cls(value, parts, tuple(parts[:index + 1] for index, part in enumerate(parts)
                                      if not glob.has_magic(part)))

    def matches(self, parts):
        return match_depth(self.pattern, parts) is not None

    def targets_ignored(self, parts, depth):
        return any(match_depth(prefix, parts, minimum=depth) is not None
                   for prefix in self.named_prefixes)


def parse_selectors(patterns):
    """Parse before a transaction changes the working directory's contents."""
    return tuple(Selector.parse(value) for value in normalize_shell_glob(patterns) or ['*'])


def select_paths(selectors, candidates, description, *, ignored_patterns=()):
    """Select paths, hiding ignores unless a selector names them."""
    selected = []
    for path in sorted(set(candidates)):
        parts = Path(path).relative_to('/').parts
        depth = ignored_depth(ignored_patterns, parts)
        if any(selector.matches(parts) and
               (depth is None or selector.targets_ignored(parts, depth))
               for selector in selectors):
            selected.append(path)
    if not selected and any(selector.source != '*' for selector in selectors):
        fail(f"no {description} files match: {' '.join(selector.source for selector in selectors)}")
    return selected
