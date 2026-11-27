#!/usr/bin/env python3
"""Replay 28 generated SYNTHETIC fixture cases through Zeek and check real logs.

Python standard library only. Docker is offline, read-only, unprivileged and
pinned to Zeek 9.0.1; --zeek optionally selects an installed local binary.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from generate_fixtures import CLIENT, SERVER, generate

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
IMAGE = 'zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def validate(case, directory):
    label = case['id']
    notice = rows(directory / 'notice.log')
    files = rows(directory / 'files.log')
    http = rows(directory / 'http.log')
    conn = rows(directory / 'conn.log')
    require(len(http) == len(conn) == len(files) == 1, f'{label}: expected one HTTP transaction/connection/file')
    f, h, c = files[0], http[0], conn[0]
    require(f['seen_bytes'] == case['body_bytes'], f'{label}: file byte count')
    require(h['response_body_len'] == case['body_bytes'], f'{label}: HTTP byte count')
    require(c['id.orig_h'] == CLIENT and c['id.resp_h'] == SERVER and
            c['id.orig_p'] == 41000 and c['id.resp_p'] == 80, f'{label}: peer identity')
    require(h['uid'] == c['uid'] and h['resp_fuids'] == [f['fuid']] and
            f['uid'] == c['uid'], f'{label}: UID/FUID linkage')
    for kind in ('stream', 'chunk'):
        companion = rows(directory / (kind + '.jsonl'))
        require(len(companion) == len(files), f'{label}: {kind} file cardinality')
        require({r['fuid'] for r in companion} == {f['fuid']}, f'{label}: {kind} FUID')
        for item in companion:
            require(item['bytes'] == item['seen'] == case['body_bytes'], f'{label}: {kind} lost bytes')
            if kind == 'chunk':
                require(item['contiguous'], f'{label}: chunk offset gap')
    health_rows = rows(directory / 'health.jsonl')
    require(len(health_rows) == 1, f'{label}: health missing')
    health = health_rows[0]
    require(health['active_contexts'] == health['retained_prefix_bytes'] == health['admission_drops'] == 0,
            f'{label}: nonzero final health state')
    require(health['notices'] == len(notice) == int(case['notice']), f'{label}: Notice count')
    require(health['peak_retained_prefix_bytes'] <= 432, f'{label}: retained more than modeled header')
    if case['notice']:
        n = notice[0]
        require(n['note'] == 'PEFileDisguise::DocumentImageMismatch', f'{label}: Notice type')
        require(n['msg'] == 'PE content advertised with a document or image filename', f'{label}: Notice message')
        require(f['missing_bytes'] == f['overflow_bytes'] == 0 and f['timedout'] is False,
                f'{label}: positive file quality')
        require(n['uid'] == c['uid'] and n['fuid'] == f['fuid'], f'{label}: Notice identity')
        require(n['id.orig_h'] == n['src'] == CLIENT and n['id.resp_h'] == n['dst'] == SERVER and
                n['id.orig_p'] == 41000 and n['id.resp_p'] == n['p'] == 80, f'{label}: Notice peer')
        evidence = {}
        for field in n['sub'].split(';'):
            key, value = field.split('=', 1)
            require(key not in evidence, f'{label}: duplicate Notice evidence key')
            evidence[key] = value
        want = dict(fuid=f['fuid'], uid=c['uid'], filename_hex=case['filename_hex'],
                    filename_source='content-disposition', format=case['format'],
                    observed_bytes=str(case['body_bytes']), declared_bytes=str(case['body_bytes']),
                    orig_p='41000/tcp', resp_p='80/tcp')
        require(evidence == want, f'{label}: Notice evidence mismatch: {evidence!r}')
        require(case['completion_min'] <= n['ts'] <= case['end'], f'{label}: premature/late Notice timestamp')
        require(f['total_bytes'] == case['body_bytes'], f'{label}: total file bytes')
    if label == 'long-overlay':
        callbacks = rows(directory / 'callbacks.jsonl')
        require(len(callbacks) == 1 and callbacks[0]['fuid'] == f['fuid'], 'long-overlay: callback identity')
        require(1 <= callbacks[0]['callbacks'] <= 4, 'long-overlay: policy callback budget')
        require(callbacks[0]['bytes'] < case['body_bytes'] // 8, 'long-overlay: policy did not detach')
        require(health['peak_retained_prefix_bytes'] == 416, 'long-overlay: required prefix bound')
        for kind in ('stream', 'chunk'):
            require(rows(directory / (kind + '.jsonl'))[0]['callbacks'] >= 100,
                    f'long-overlay: {kind} companion stopped prematurely')
    return dict(id=label, notices=len(notice), body_bytes=case['body_bytes'],
                uid=c['uid'], fuid=f['fuid'], health=health)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='Fresh output directory outside the repository')
    parser.add_argument('--zeek', help='Optional local Zeek binary instead of pinned Docker image')
    args = parser.parse_args()
    output = args.output.resolve()
    root = PACKAGE.parent
    if output == root or root in output.parents:
        parser.error('--output must be outside the repository')
    if output.exists():
        parser.error('--output must not already exist')
    if not args.zeek:
        inspected = subprocess.run(['docker', 'image', 'inspect', IMAGE], capture_output=True, text=True)
        if inspected.returncode:
            parser.error('Pinned image not present. Provision explicitly with: docker pull ' + IMAGE)
    output.mkdir(parents=True)
    manifest = generate(output / 'fixtures')
    commands = []

    def engine(directory, scripts, pcap=None):
        directory.mkdir()
        if args.zeek:
            command = [str(Path(args.zeek).resolve())] if '/' in args.zeek else [args.zeek]
            policy = str(PACKAGE / 'Zeek' / 'main.zeek')
            loaded = [str(HERE / s) for s in scripts]
            capture = str(pcap) if pcap else None
        else:
            command = ['docker', 'run', '--rm', '--pull=never', '--network=none', '--read-only',
                       '--cap-drop=ALL', '--security-opt=no-new-privileges',
                       '--user', f'{os.getuid()}:{os.getgid()}',
                       '--mount', f'type=bind,src={PACKAGE},dst=/package,readonly',
                       '--mount', f'type=bind,src={output},dst=/results',
                       '--workdir', '/results/' + directory.relative_to(output).as_posix(), IMAGE, 'zeek']
            policy = '/package/Zeek/main.zeek'
            loaded = ['/package/tests/' + s for s in scripts]
            capture = '/results/' + pcap.relative_to(output).as_posix() if pcap else None
        command += ['-b']
        if capture:
            command += ['-r', capture]
        command += ['base/protocols/conn', policy] + loaded + ['LogAscii::use_json=T']
        commands.append(command)
        result = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=120)
        (directory / 'stdout.txt').write_text(result.stdout)
        (directory / 'stderr.txt').write_text(result.stderr)
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        require(result.returncode == 0, f'Zeek exit {result.returncode}: {result.stderr}')
        require(not result.stderr.strip(), f'Unexpected Zeek diagnostic: {result.stderr}')
        return result

    primitive = engine(output / 'filename-probe', ['filename-precedence.zeek'])
    lines = primitive.stdout.splitlines()
    require(len(lines) == 8 and all(line.startswith('PASS ') for line in lines), 'filename primitive probes failed')
    results = []
    for case in manifest:
        directory = output / case['id']
        engine(directory, ['observers/callbacks.zeek', 'observers/stream.zeek', 'observers/chunk.zeek'],
               output / 'fixtures' / (case['id'] + '.pcap'))
        results.append(validate(case, directory))
        print('PASS', case['id'], flush=True)
    require(len(results) == 28 and sum(r['notices'] for r in results) == 9, 'aggregate mismatch')
    summary = dict(provenance='synthetic model fixtures replayed through real Zeek; not native captures',
                   cases=len(results), notices=sum(r['notices'] for r in results), primitive_checks=len(lines),
                   engine=args.zeek or IMAGE, results=results,
                   source_sha256={str(p.relative_to(PACKAGE)): hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in sorted((PACKAGE / 'Zeek').glob('*.zeek'))})
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(f"PASS {len(results)} synthetic cases; {summary['notices']} Notices; {len(lines)} filename probes")


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, OSError, subprocess.SubprocessError) as error:
        print('FAIL:', error, file=sys.stderr)
        sys.exit(1)
