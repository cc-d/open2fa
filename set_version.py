#!/usr/bin/env python3
"""
Sets the version in both pyproject.toml and version.py to the same version.

Usage:
    ./set_version.py <version>
"""
import sys
import os
import os.path as osp

REPO_DIR = osp.dirname(osp.abspath(__file__))
LIB_DIR = osp.join(REPO_DIR, 'open2fa')


def main(v: str):
    """sets both pyproject.toml and version.py to the same version"""
    with open(osp.join(LIB_DIR, 'version.py'), 'w') as f:
        f.write('__version__ = "{}"\n'.format(v))
        print('Set version in version.py to', v)
    with open(osp.join(REPO_DIR, 'pyproject.toml'), 'r') as f:
        lines = f.readlines()
        for i, line in enumerate(lines):
            if line.startswith('version = "'):
                lines[i] = 'version = "{}"\n'.format(v)
                break
    with open(osp.join(REPO_DIR, 'pyproject.toml'), 'w') as f:
        f.writelines(lines)
    print('Set version in pyproject.toml to', v)


if __name__ == '__main__':
    from open2fa.version import __version__ as _v

    cv = str(_v)
    v = _v.split('.')
    print('Current version:', cv)
    inp = input('Increment version Number (1,2,3): ')
    if inp not in ('1', '2', '3'):
        print('Invalid input')
        sys.exit(1)

    inp = int(inp) - 1
    v[inp] = str(int(v[inp]) + 1)
    v = '.'.join(v)
    print('New version:', v)
    main(v)
