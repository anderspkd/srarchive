import sys
import datetime

NORMAL = 0
WARN = 1
ERROR = 2


def log(msg, level=NORMAL, end='\n'):
    f = sys.stdout
    if level == NORMAL:
        pre = '[ ]'
        f.write(f'{pre} {msg}{end}')
    elif level == WARN:
        pre = '[W]'
        f.write(f'{pre} {msg}{end}')
    elif level == ERROR:
        pre = '[E]'
        f.write(f'{pre} {msg}{end}')
        exit(1)
    else:
        f.write(f'[F] unknown logging level {level}\n')
        exit(1)
    f.flush()


# Parse UNIX timestamp as something readable.
def pp_time(timestamp):
    if timestamp is not None:
        ts = datetime.datetime.fromtimestamp(
            timestamp
        ).strftime('%Y-%m-%d %H:%M:%S')
    return (ts or 'N/A', timestamp or 'N/A')
