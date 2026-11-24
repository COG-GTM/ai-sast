#!/usr/bin/env python3
"""
Repository identity helpers for feedback lookups.

Feedback rows are scoped to one repository. A repository is identified by its
full path (host/owner/repo), never by a name fragment, so rows written for
other owners or for repositories whose names contain this one are not returned.
"""

import re
from typing import List

_SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')


def normalize_repo_identifier(repo_url: str) -> str:
    """
    Normalize a repository URL to a lowercase ``host/owner/repo`` key.

    Examples:
        https://github.com/Org/App.git -> github.com/org/app
        git@github.com:org/app.git     -> github.com/org/app
        org/app                        -> org/app
    """
    value = (repo_url or '').strip()
    value = _SCHEME_RE.sub('', value)
    value = value.split('?', 1)[0].split('#', 1)[0]

    host, sep, path = value.partition('/')
    if '@' in host:
        host = host.rsplit('@', 1)[1]
    if ':' in host and not host.rsplit(':', 1)[1].isdigit():
        host = host.replace(':', '/', 1)
    value = f"{host}{sep}{path}"

    value = re.sub(r'/+', '/', value).strip('/')
    if value.endswith('.git'):
        value = value[:-4].rstrip('/')
    return value.lower()


def repository_match_values(repo_url: str) -> List[str]:
    """
    Exact, lowercase ``repository`` column values that identify ``repo_url``.

    Covers the stored forms of the same repository (with or without scheme,
    trailing slash or ``.git``). Compare with ``LOWER(repository) IN (...)``
    using bound parameters; never use LIKE, which matches other repositories.
    """
    key = normalize_repo_identifier(repo_url)
    if not key:
        return []
    return [
        f"{prefix}{key}{suffix}"
        for prefix in ('', 'https://', 'http://')
        for suffix in ('', '/', '.git')
    ]
