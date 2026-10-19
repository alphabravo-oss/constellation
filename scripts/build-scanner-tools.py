#!/usr/bin/env python3
"""Rebuild pinned scanner tools with reviewed dependency locks and a patched Go compiler."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess


def source_directory(metadata, source):
    if metadata.get('Path') != source['module'] or metadata.get('Version') != source['version'] or metadata.get('Sum') != source['sum']:
        raise ValueError('downloaded source does not match the reviewed module checksum')
    return Path(metadata['Dir'])


def build(lock_dir, work, output, go='go'):
    lock = json.loads((lock_dir/'sources.json').read_text())
    env = dict(os.environ, GOWORK='off', GOTOOLCHAIN='local', CGO_ENABLED='0', GOOS='linux', GOFLAGS='')
    actual = subprocess.check_output([go, 'env', 'GOVERSION'], env=env, text=True).strip()
    if actual != lock['go']:
        raise ValueError('scanner tools require '+lock['go']+', got '+actual)
    output.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    for source in lock['tools']:
        name = source['name']
        metadata = json.loads(subprocess.check_output([go, 'mod', 'download', '-json', source['module']+'@'+source['version']], env=env, text=True))
        directory = work/name
        # Fresh per-tool source prevents stale local edits entering the build.
        if directory.exists():
            shutil.rmtree(directory)
        shutil.copytree(source_directory(metadata, source), directory)
        for file in directory.rglob('*'):
            if file.is_file():
                file.chmod(file.stat().st_mode | 0o200)
        for filename in ['go.mod', 'go.sum']:
            shutil.copyfile(lock_dir/name/filename, directory/filename)
        version = source['version']+'-'+lock['patchRevision']
        if name == 'cosign':
            prefix = 'sigs.k8s.io/release-utils/version.'
            flags = '-s -w -X '+prefix+'gitVersion='+version+' -X '+prefix+'gitCommit='+source['commit']+' -X '+prefix+'gitTreeState=dirty'
        else:
            flags = '-s -w -X main.version='+version.removeprefix('v')+' -X main.gitCommit='+source['commit']+' -X main.gitDescription='+version
        (output/name).unlink(missing_ok=True)
        subprocess.run([go, 'build', '-p', '1', '-mod=readonly', '-trimpath', '-tags', 'containers_image_openpgp,exclude_graphdriver_btrfs', '-ldflags', flags, '-o', str(output/name), './cmd/'+name], cwd=directory, env=env, check=True)
        print('Built '+name+' '+version, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--locks', type=Path, default=Path(__file__).resolve().parents[1]/'deploy/docker/scanner-tools')
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    build(args.locks.resolve(), args.work.resolve(), args.output.resolve(), args.go)
