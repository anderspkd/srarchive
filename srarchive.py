#!/usr/bin/env python3

import argparse
import requests
import re
import time
import os
import sys
import json
import datetime

# Logging. NORMAL is the default. ERROR will make the script exit.
NORMAL = 0
WARN = 1
ERROR = 2
_LOG = sys.stderr
DEBUG = False


def debug(msg):
    if DEBUG:
        log(msg)


def log(msg, level=NORMAL, end='\n'):
    if level == NORMAL:
        pre = '[ ]'
        _LOG.write(f'{pre} {msg}{end}')
    elif level == WARN:
        pre = '[W]'
        _LOG.write(f'{pre} {msg}{end}')
    elif level == ERROR:
        pre = '[E]'
        _LOG.write(f'{pre} {msg}{end}')
        exit(1)
    else:
        log(f'Unknown log level: {level}', ERROR)
    _LOG.flush()


# Parse and return a UNIX timestamp as something suitable for
# printing.
def pp_time(timestamp):
    if timestamp is not None:
        ts = datetime.datetime.fromtimestamp(
            timestamp
        ).strftime('%Y-%m-%d %H:%M:%S')
    return (ts or 'N/A', timestamp or 'N/A')


class AuthenticationError(Exception):
    pass


# A "bot" than can authenticate and perform GET and POST requests.
class Bot:

    def __init__(self, username, password, api_id, api_secret, user_agent):
        debug(f'Bot initialized on username={username}, password=..., api_id={api_id}, api_secret=..., user_agent={user_agent}')
        self.usr = username
        self.pwd = password
        self.id = api_id
        self.sec = api_secret
        self.headers = {'User-Agent': user_agent}

    def post(self, url, **kwargs):
        debug(f'Bot POST: url={url}, args={kwargs}, headers={self.headers}')
        r = requests.post(url, headers=self.headers, **kwargs)
        debug(f'Bot POST: response={r}')
        return r

    def get(self, url, **kwargs):
        debug(f'Bot GET: url={url}, args={kwargs}, headers={self.headers}')
        r = requests.get(url, headers=self.headers, **kwargs)
        debug(f'Bot GET: response={r}')
        return r

    def auth(self):
        auth = requests.auth.HTTPBasicAuth(self.id, self.sec)
        data = {
            'grant_type': 'password',
            'username': self.usr,
            'password': self.pwd
        }
        resp = self.post(
            'https://www.reddit.com/api/v1/access_token',
            auth=auth,
            data=data
        )
        token = resp.json().get('access_token')
        debug(f'Access token={token}')

        if token is None:
            raise AuthenticationError(f'Could not authenticate: {resp.json()}')

        self.headers['Authorization'] = f'bearer {token}'


# Arguments
parser = argparse.ArgumentParser(description='Retreives the content of a subreddit.')
parser.add_argument('-u', help='reddit username', metavar='username', dest='username')
parser.add_argument('-p', help='reddit password', metavar='password', dest='password')
parser.add_argument('-i', help='reddit API ID', metavar='id', dest='api_id')
parser.add_argument('-s', help='reddit API secret', metavar='secret', dest='api_secret')
parser.add_argument('-a', help='useragent for bot', metavar='useragent', dest='useraget')
parser.add_argument('-o', help='output listings to file', metavar='filename', dest='output')
parser.add_argument('-n', help='dont output anything', metavar='no output', dest='no_output', action='store_const', const=True, default=False)
parser.add_argument('--debug',     help='output more information ftso. debugging', dest='debug', action='store_const', const=True, default=False)
parser.add_argument('--pprint',    help='pretty print format string', metavar='fmtstr', dest='fmtstr')
parser.add_argument('--json',      help='output as json', dest='json', action='store_const', const=True, default=False)
parser.add_argument('--resume',    help='name or time to resume at', metavar='name/time')
parser.add_argument('--stop',      help='name or time to stop at', metavar='name/time')
parser.add_argument('--auth-file', help='file with authentication info', metavar='filename')
parser.add_argument('--sleep',     help='time to sleep between requests', type=float, metavar='float')
parser.add_argument('--force',     help='dont prompt for file append', action='store_const', const=True, default=False)
parser.add_argument('subreddit',   help='subreddit to archive')

if len(sys.argv) == 1:
    parser.print_help()
    exit(0)

args = parser.parse_args()

URL = f'https://oauth.reddit.com/r/{args.subreddit}'
SLEEP_T = 1 if args.sleep is None else args.sleep
DEBUG = args.debug

# Format argument(s)
if args.json and args.fmtstr is not None:
    log('Cannot set both json and pprint', ERROR)

if args.json:
    log('will output json formatted data')

    def p(entry):
        return json.dumps(entry)

elif args.fmtstr:
    log(f'will output using format string: "{args.fmtstr}"')

    def p(entry):
        return args.fmtstr.format(**entry)

else:
    log('will output using "str"')

    def p(entry):
        return str(entry)

# Output arguments
out_f = args.output

if args.no_output:

    def output(*args, **kwargs):
        pass

elif out_f is None or out_f == '-':
    log('output goes to stdout')

    def output(thing):
        sys.stdout.write(p(thing) + '\n')

elif os.path.exists(out_f):

    if not args.force:
        c = input(f'[W] file {out_f} exists. Append to file? (y/n) ')
    else:
        c = 'y'

    if c.lower() == 'y':
        log(f'Appending to file "{args.output}"', WARN)
        out_f = open(out_f, 'a')
    else:
        log(f'Wont append to "{args.output}". Exiting', ERROR)

    def output(thing):
        out_f.write(p(thing) + '\n')

else:

    log(f'Writing to file: "{out_f}"')

    out_f = open(out_f, 'w')

    def output(thing):
        out_f.write(p(thing) + '\n')

# Resume/stop arguments. We only perform some very rough validation of
# a timestamp/fullname.
pt = re.compile('^[0-9]+$')
pn = re.compile('^t3_([a-z0-9]+)$')
resume = {}
stop_at = {}
if args.resume is not None:
    if pt.match(args.resume):
        resume = {'t': int(args.resume)}
    elif pn.match(args.resume):
        resume = {'n': args.resume}
    else:
        log(f'invalid value for resume: {args.resume}', ERROR)
    log(f'will resume at "{args.resume}"')

if args.stop is not None:
    if pt.match(args.stop):
        stop_at = {'t': int(args.stop)}
    elif pn.match(args.stop):
        stop_at = {'n': args.stop}
    else:
        log(f'Invalid value for before: {args.stop}', ERROR)
    log(f'Will stop at "{args.stop}"')

# Authentication
if args.auth_file is None:
    if None in (args.api_id, args.api_secret, args.username, args.password, args.useragent):
        log('Missing authentication info', ERROR)
    else:
        usr = args.username
        pwd = args.password
        api_id = args.api_id
        api_sec = args.api_secret
        user_agent = args.useragent
else:
    with open(args.auth_file) as f:
        c = json.loads(f.read().strip())
        usr = c['username']
        pwd = c['password']
        api_id = c['api_id']
        api_sec = c['api_secret']
        user_agent = c['useragent']

# Create a bot object and authenticate
try:
    bot = Bot(usr, pwd, api_id, api_sec, user_agent)
    bot.auth()
    log(f'Authenticated')
except AuthenticationError as e:
    log(e, ERROR)


if DEBUG:
    debug(f'Trying /api/v1/me ...')
    r = bot.get('https://oauth.reddit.com/api/v1/me')


# iterator stuff
GIMME_DATA = 123


# Helper function that yields data obtained from the reddit API
# (via. url). GIMME_DATA signals that a new request needs to be made.
def get_listings(url):
    while True:
        data = yield GIMME_DATA
        stuff = bot.get(url, params=data).json()
        if 'error' in stuff:
            log(f'Could not fetch data. Reddit says: "{stuff["message"]}"', ERROR)
        else:
            stuff = stuff['data']
        for k in stuff['children']:
            yield k['data']
        time.sleep(SLEEP_T)


n_entries = 0
s_entries = 0
skip_new = 't' in resume
done = False
data = None

stop_at_n = stop_at.get('n')
stop_at_t = stop_at.get('t', 0)

try:
    # Keep track of how far (timestamp/fullname) we are.
    progress = None

    # If we're resuming from a timestamp, we will skip getting entries
    # via. /new (even if they could be found here).
    if not skip_new:
        log(f'getting entries using {args.subreddit}/new')

        if 'n' in resume:
            data = {'after': resume['n']}
        else:
            data = {}

        data['limit'] = 100

        it = get_listings(URL + '/new')
        for k in it:
            # if `get_listings' asks for data two times in a row, then
            # nothing more can be found via. /new.
            if k == GIMME_DATA:
                k = it.send(data)
            if k == GIMME_DATA:
                break
            else:
                n_entries += 1
                progress = (k['name'], int(k['created_utc']))
                output(k)
                log(f'archiving ... {n_entries}', end='\r')
                data['after'] = progress[0]
                resume['t'] = progress[1]
                if stop_at_n == k['name'] or stop_at_t >= k['created_utc']:
                    done = True
                    break
        log(f'entries found (/new): {n_entries}')

    if not done:
        query_str = 'timestamp:{stop}..{start}'
        step_s = 86_400  # step one day at a time

        # small hack to avoid printing a meaningless message
        if 't' in stop_at:
            created_on = stop_at['t']
        else:
            created_on = int(bot.get(URL + '/about').json()['data']['created'])
            log(f'subreddit "r/{args.subreddit}" created on {pp_time(created_on)[0]}')

        t_start = resume.get('t', int(time.time()))
        t_stop = stop_at.get('t', t_start)

        log(f'getting entries using {args.subreddit}/search')

        data = {
            'q': query_str.format(start=t_start, stop=t_stop),
            'limit': 100,
            'syntax': 'cloudsearch',
            'sort': 'new',
            'restrict_sr': 1
        }

        # If we're resuming from a fullname, then we need to remove
        # the timestamp query. Otherwise nothing will (probably) be
        # returned.
        if 'n' in resume:
            data['after'] = resume['n']
            del data['q']

        it = get_listings(URL + '/search')
        for k in it:
            if k == GIMME_DATA:
                k = it.send(data)
            # No entries found in the time interval
            if k == GIMME_DATA:
                t_start = t_stop
                t_stop = t_start - step_s
                data['q'] = query_str.format(start=t_start, stop=t_stop)
                step_s *= 2  # double time interval each time nothing is found
                if created_on >= t_start:
                    break
                continue
            else:
                # Remove the fullname that we resumed from, so that we
                # can start to search by timestamps instead.
                if 'after' in data:
                    del data['after']
                step_s = 86_400
                s_entries += 1
                progress = (k['name'], int(k['created_utc']))
                log(f'archiving ... {s_entries}', end='\r')
                output(k)
                # We stop if we're (1) at a time/fullname that the
                # stop argument told us to stop at, or (2) we're past
                # the subreddit's creation date.
                if stop_at_n == progress[0] or stop_at_t >= progress[1] or created_on >= progress[1]:
                    break
                t_start = progress[1]
                t_stop = t_start - step_s
                data['q'] = query_str.format(start=t_start, stop=t_stop)
        log(f'entries found (/search): {s_entries}')

    if out_f is not None and out_f != '-':
        out_f.close()

except KeyboardInterrupt:
    log('interrupted', WARN)
    log(f'progress info: {progress}')

    # Might need to close the file we're writing to.
    if out_f is not None and out_f != '-':
        try:
            out_f.close()
        except Exception:
            pass

log(f'total entries found: {s_entries + n_entries}')
log(f'bye :-)')
