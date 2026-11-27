#!/usr/bin/env python3
"""Measure one real engine child inside a fresh Linux container wrapper.

Do not reuse this wrapper process for several engines: ru_maxrss is cumulative
across terminated children. Docker startup and Docker CLI memory are excluded.
"""
import argparse
import json
from pathlib import Path
import resource
import subprocess
import sys
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--timeout',type=float,default=120)
    parser.add_argument('engine',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    command=args.engine[1:] if args.engine[:1]==['--'] else args.engine
    if not command or args.timeout<=0 or args.output.exists():
        parser.error('command, positive timeout and a fresh output file are required')
    before=resource.getrusage(resource.RUSAGE_CHILDREN)
    children_before={'user_seconds':before.ru_utime,'system_seconds':before.ru_stime,'maxrss_kib':before.ru_maxrss}
    if children_before!={'user_seconds':0.0,'system_seconds':0.0,'maxrss_kib':0}:
        parser.error('wrapper already waited for a child; per-engine RSS would be ambiguous')
    stdout=args.output.with_suffix('.engine.stdout')
    stderr=args.output.with_suffix('.engine.stderr')
    start=time.perf_counter()
    timed_out=False
    engine_exit=None
    with stdout.open('wb') as out,stderr.open('wb') as err:
        try:
            result=subprocess.run(command,stdout=out,stderr=err,timeout=args.timeout)
            engine_exit=result.returncode
        except subprocess.TimeoutExpired:
            timed_out=True
    wall=time.perf_counter()-start
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    metrics={'argv':command,'engine_exit':engine_exit,'timed_out':timed_out,'wall_seconds':wall,
             'child_user_seconds':after.ru_utime-before.ru_utime,'child_system_seconds':after.ru_stime-before.ru_stime,
             'child_maxrss_kib':after.ru_maxrss,'rss_unit':'KiB (Linux getrusage children; fresh wrapper)',
             'children_before':children_before,'stdout_bytes':stdout.stat().st_size,'stderr_bytes':stderr.stat().st_size,
             'scope':'One engine child and its waited descendants; wrapper/Docker startup and DockerCLI RSS excluded'}
    args.output.write_text(json.dumps(metrics,indent=2)+'\n')
    print(json.dumps(metrics,indent=2))
    return 124 if timed_out else engine_exit


if __name__=='__main__':
    sys.exit(main())
