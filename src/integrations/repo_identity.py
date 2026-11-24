#!/usr/bin/env python3
"""
Repository identity helpers for feedback storage and lookup.

Feedback and scan results are scoped to one repository. Lookups must use an
exact match on a canonical identifier so that feedback recorded for one
repository (e.g. ``acme/docs-app`` or ``other-org/app``) is never applied to
another (``acme/app``).
"""

import re
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

_SCHEME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*://')
_SCP_RE = re.compile(r'^(?:[^@/\s]+@)?([^:/\s]+):(?!//)(.+)$')


def _split_remote(repo: str) -> Optional[Tuple[str, str]]:
    """Return (host, path) for a remote URL, or None for local paths."""
    if _SCHEME_RE.match(repo):
        parts = urlsplit(repo)
        if parts.scheme.lower() == 'file' or not parts.hostname:
            return None
        host = parts.hostname
        if parts.port:
            host = f"{host}:{parts.port}"
        path = parts.path
    else:
        match = _SCP_RE.match(repo)
        if not match:
            return None
        host, path = match.group(1), match.group(2)

    path = path.strip('/')
    if path.endswith('.git'):
        path = path[:-4].rstrip('/')
    if not path:
        return None
    return host, path


def canonical_repository(repo: str) -> str:
    """
    Canonical identifier for a repository.

    Remote URLs become ``host/owner/repo`` in lower case, with scheme,
    credentials, trailing slash and ``.git`` removed, e.g.
    ``https://github.com/Acme/App.git`` -> ``github.com/acme/app``.
    Anything else (e.g. a local scan directory) is returned unchanged apart
    from surrounding whitespace and trailing slashes.
    """
    repo = (repo or '').strip()
    remote = _split_remote(repo)
    if remote is None:
        return repo.rstrip('/') or repo
    host, path = remote
    return f"{host}/{path}".lower()


def repository_aliases(repo: str) -> List[str]:
    """
    Exact ``repository`` column values that identify the same repository.

    New rows store :func:`canonical_repository`. Rows written before that
    stored the URL as given (e.g. ``https://github.com/acme/app``), so those
    spellings of the *same* repository are included for backwards
    compatibility. No other repository can match.
    """
    raw = (repo or '').strip()
    aliases = [canonical_repository(raw), raw]
    remote = _split_remote(raw)
    if remote is not None:
        host, path = remote
        for scheme in ('https', 'http'):
            base = f"{scheme}://{host}/{path}"
            aliases.extend([base, f"{base}/", f"{base}.git"])
    seen = set()
    return [a for a in aliases if a and not (a in seen or seen.add(a))]
