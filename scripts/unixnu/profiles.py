"""Layered ARM64, SoC, OS, and device configuration."""
from copy import deepcopy
from pathlib import Path

from .config import load_toml
from .util import Error


def merge(base, overlay):
    result = deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def load(ctx, allow_fetch=False):
    from . import feeds
    board = ctx.raw_board.get('board', {})
    soc_name, os_name = board.get('soc_source'), board.get('os_profile')
    if not soc_name or not os_name:
        raise Error('schema_version = 2 requires [board] soc_source and os_profile')
    if Path(os_name).name != os_name or os_name in ('.', '..'):
        raise Error('[board] os_profile must be a profile directory name')
    ctx.soc = feeds.resolve_soc(ctx, soc_name, allow_fetch)
    ctx.profile_roots = {'arch': ctx.root / 'profiles/arch/arm64', 'soc': ctx.soc.path,
                         'os': ctx.root / 'profiles/os' / os_name, 'device': ctx.device}
    ctx.profile_files = [ctx.profile_roots['arch'] / 'profile.toml', ctx.soc.path / 'soc.toml',
                         ctx.profile_roots['os'] / 'profile.toml', ctx.device / 'board.toml']
    result = {}
    for path in ctx.profile_files:
        result = merge(result, load_toml(path))
    return result


def resolve_path(ctx, value, modules=None):
    """Resolve profile-prefixed paths and component:ID/path references."""
    if value.startswith('component:'):
        identifier, sep, relative = value[len('component:'):].partition('/')
        if not sep:
            raise Error(f'component path needs ID/path: {value}')
        modules = modules if modules is not None else getattr(ctx, 'modules', {})
        module = next((m for m in modules.values() if m.name == identifier), None)
        if not module or module.path is None:
            raise Error(f'component source unavailable: {identifier}; run unixnu fetch')
        return module.path / relative
    prefix, separator, relative = value.partition(':')
    if separator and prefix in ctx.profile_roots:
        return ctx.profile_roots[prefix] / relative
    path = Path(value)
    return path if path.is_absolute() else ctx.device / path
