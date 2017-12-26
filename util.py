import sys
import datetime

NORMAL = 0
WARN = 1
ERROR = 2


def log(msg, level=NORMAL, end='\n'):
    if level == NORMAL:
        pre = '[ ]'
        sys.stdout.write(f'{pre} {msg}{end}')
    if level == WARN:
        pre = '[W]'
        sys.stdout.write(f'{pre} {msg}{end}')
    if level == ERROR:
        pre = '[E]'
        sys.stdout.write(f'{pre} {msg}{end}')
        exit(1)


# Parse UNIX timestamp as something readable.
def pp_time(timestamp):
    if timestamp is not None:
        ts = datetime.datetime.fromtimestamp(
            timestamp
        ).strftime('%Y-%m-%d %H:%M:%S')
    return (ts or 'N/A', timestamp or 'N/A')
