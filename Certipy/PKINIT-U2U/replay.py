#!/usr/bin/env python3
"""Dependency-free, local offline Zeek replay. No SSH, keys, or controller imports."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def package_path(root, name):
    """Resolve a package member, rejecting external paths and symlink escapes."""
    if not isinstance(name, str) or not name or '\\' in name or any(x in ('', '.', '..') for x in name.split('/')):
        raise ValueError('Invalid package-relative path')
    path = (root / name).resolve()
    if Path(name).is_absolute() or not path.is_relative_to(root.resolve()):
        raise ValueError('Path escapes package')
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_package(root):
    """Bind every replay input before starting any engine process."""
    config = json.loads((root / 'cases.json').read_text(encoding='utf-8'))
    if config['schema_version'] != 1:
        raise ValueError('Unsupported case schema')
    bindings = [(config['detector'], config['detector_sha256']),
                (config['event_fixture'], config['event_fixture_sha256'])]
    bindings += [(x['pcap'], x['sha256']) for x in config['cases']]
    for name, expected in bindings:
        if digest(package_path(root, name)) != expected:
            raise ValueError('SHA-256 mismatch: ' + name)
    for group in ('cases', 'event_cases'):
        names = set()
        for case in config[group]:
            name = case['case']
            if not re.fullmatch(r'[a-z0-9][a-z0-9-]*', name) or name in names:
                raise ValueError('Invalid or duplicate case name')
            names.add(name)
            if type(case['expected']) is not int or case['expected'] < 0:
                raise ValueError('Invalid expected count')
    return config


def json_rows(path):
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError('Expected JSON objects in ' + path.name)
    return rows


def read_result(work, expected, exit_code, stdout, stderr):
    """Return counts, not identity-bearing Zeek records or environment paths."""
    observed = len(json_rows(work / 'pkinit_u2u.log'))
    notices = sum(row.get('note') == 'PKINIT_U2U::Self_Targeted_Ticket'
                  for row in json_rows(work / 'notice.log'))
    errors = sum(row.get('level') == 'ERROR' for row in json_rows(work / 'reporter.log'))
    return {'expected': expected, 'observed': observed, 'notices': notices,
            'exit_code': exit_code, 'stdout_empty': not stdout, 'stderr_empty': not stderr,
            'reporter_error_count': errors,
            'passed': exit_code == 0 and not stdout and not stderr and errors == 0
                      and observed == expected and notices == expected}


def run_case(root, config, case, output, zeek, constructed=False):
    work = output / (('event-' if constructed else '') + case['case'])
    work.mkdir()
    capture = config['cases'][0] if constructed else case
    pcap = package_path(root, capture['pcap'])
    argv = [zeek, '-Cr', str(pcap), str(package_path(root, config['detector'])), 'LogAscii::use_json=T']
    if constructed:
        argv += [str(package_path(root, config['event_fixture'])), 'PKINIT_U2U::regression_case=' + case['case']]
    process = subprocess.run(argv, cwd=work, capture_output=True, text=True, timeout=60)
    (work / 'stdout.txt').write_text(process.stdout, encoding='utf-8')
    (work / 'stderr.txt').write_text(process.stderr, encoding='utf-8')
    result = read_result(work, case['expected'], process.returncode, process.stdout, process.stderr)
    result.update({'case': case['case'], 'pcap_sha256': digest(pcap),
                   'classification': 'constructed_event_regression' if constructed else case['classification']})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zeek', default='zeek', help='Local Zeek executable (tested with 9.0.0)')
    parser.add_argument('--output', type=Path, default=Path('replay-results'), help='New directory for logs and receipt; must not exist')
    parser.add_argument('--events', action='store_true', help='Also run 31 constructed event regressions; these are not authentic traffic tests')
    parser.add_argument('--case', action='append', default=[], help='Select named case(s); repeatable; event cases also need --events')
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent
    output = args.output.resolve()
    try:
        if output.exists():
            raise ValueError('Output directory already exists; choose a new directory')
        config = load_package(root)
        jobs = [(case, False) for case in config['cases']]
        if args.events:
            jobs += [(case, True) for case in config['event_cases']]
        if set(args.case) - {case['case'] for case, _ in jobs}:
            raise ValueError('Unknown case or event case without --events')
        if args.case:
            jobs = [(case, event) for case, event in jobs if case['case'] in args.case]
        version = subprocess.run([args.zeek, '--version'], capture_output=True, text=True, timeout=15, check=True)
        zeek_version = version.stdout.strip() or version.stderr.strip()
        if not zeek_version:
            raise ValueError('Zeek returned no version')
        output.mkdir(parents=True, exist_ok=False)
        rows = [run_case(root, config, case, output, args.zeek, constructed) for case, constructed in jobs]
        receipt = {'schema_version': 1, 'zeek_version': zeek_version,
                   'detector_sha256': digest(package_path(root, config['detector'])),
                   'event_fixture_sha256': digest(package_path(root, config['event_fixture'])),
                   'cases_manifest_sha256': digest(root / 'cases.json'), 'runner_sha256': digest(Path(__file__).resolve()),
                   'cases': rows, 'passed': bool(rows) and all(row['passed'] for row in rows)}
        text = json.dumps(receipt, indent=2) + '\n'
        (output / 'receipt.json').write_text(text, encoding='utf-8')
        print(text, end='')
        return 0 if receipt['passed'] else 1
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('Replay failed: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
