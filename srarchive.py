#!/usr/bin/env python

import argparse
import re
import time
import os
import sys
import json

from util import log, ERROR, pp_time, WARN
import bot as _bot

# Arguments
parser = argparse.ArgumentParser(
    description='Retreives entire content of subreddit.'
)
parser.add_argument('-u', metavar='username', dest='username',
                    help='reddit username')
parser.add_argument('-p', metavar='password', dest='password',
                    help='reddit password')
parser.add_argument('-i', metavar='id', dest='api_id',
                    help='reddit API ID')
parser.add_argument('-s', metavar='secret', dest='api_secret',
                    help='reddit API secret')
parser.add_argument('-a', metavar='useragent', dest='useraget',
                    help='useragent for bot')
parser.add_argument('-o', metavar='filename', dest='output',
                    help='output listings to file')
parser.add_argument('-n', metavar='no output', dest='no_output',
                    help='dont output anything', action='store_const',
                    const=True, default=False)
parser.add_argument('--pprint', metavar='fmtstr', dest='fmtstr',
                    help='pretty print format string')
parser.add_argument('--json', dest='json', action='store_const', const=True,
                    default=False, help='output as json')
parser.add_argument('--resume', metavar='name/time',
                    help='name or time to resume at')
parser.add_argument('--stop', metavar='name/time',
                    help='name or time to stop at')
parser.add_argument('--auth-file', metavar='filename',
                    help='file with authentication info')
parser.add_argument('--sleep', help='time to sleep between requests',
                    type=float)
parser.add_argument('--force', help='dont prompt for file append',
                    action='store_const', const=True, default=False)
parser.add_argument('subreddit', help='subreddit to archive')

args = parser.parse_args()

URL = f'https://oauth.reddit.com/r/{args.subreddit}'
SLEEP_T = 1 if args.sleep is None else args.sleep
out_f = args.output

if args.json and args.fmtstr is not None:
    log('Cannot set both json and pprint', ERROR)

if args.json:
    log('Outputting json formatted data')

    def p(entry):
        return json.dumps(entry)
elif args.fmtstr:
    log(f'Outputting using format string: "{args.fmtstr}"')

    def p(entry):
        return args.fmtstr.format(**entry)
else:
    log('Outputting using "str"')

    def p(entry):
        return str(entry)

if args.no_output:

    def output(*args, **kwargs):
        pass

elif out_f is None or out_f == '-':
    log('outputting to stdout')

    def output(thing):
        sys.stdout.write(p(thing) + '\n')

elif os.path.exists(out_f):

    if not args.force:
        c = input(f'[W] file {out_f} exists. Append to end (y/n)? ')
    else:
        c = 'y'

    if c.lower() == 'y':
        log(f'Append to file "{args.output}"', WARN)
        out_f = open(out_f, 'a')
    else:
        log(f'Wont append to "{args.output}". Exiting', ERROR)

    def output(thing):
        out_f.write(p(thing) + '\n')

else:
    out_f = open(out_f, 'w')

    def output(thing):
        out_f.write(p(thing) + '\n')

# Used to validate `resume' and `before' args
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
        log(f'Invalid value for resume: {args.resume}', ERROR)
    log(f'Will resume at "{args.resume}"')

if args.stop is not None:
    if pt.match(args.stop):
        stop_at = {'t': int(args.stop)}
    elif pn.match(args.stop):
        stop_at = {'n': args.stop}
    else:
        log(f'Invalid value for before: {args.stop}', ERROR)
    log(f'Will stop at "{args.stop}"')

# Parse authentication information
if args.auth_file is None:
    if None in (args.api_id, args.api_secret, args.username, args.password):
        parser.print_help()
        exit(1)
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


try:
    bot = _bot.Bot(usr, pwd, api_id, api_sec, user_agent)
    bot.auth()
    log(f'Authenticated')
except _bot.AuthenticationError as e:
    log(e, ERROR)


# iterator stuff
GIMME_DATA = 123


# Helper to get data via new and search functions. Stops if no data
# is found or data (as passed by the caller) is None.
def get_listings(url):
    while True:
        data = yield GIMME_DATA
        stuff = bot.get(url, params=data).json()['data']
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

    progress = None

    if not skip_new:
        # get listings via /new

        log(f'getting entries using {args.subreddit}/new')

        if 'n' in resume:
            data = {'after': resume['n']}
        else:
            data = {}

        data['limit'] = 100

        it = get_listings(URL + '/new')
        for k in it:
            if k == GIMME_DATA:
                k = it.send(data)
            if k == GIMME_DATA:
                log(f'entries found (/new): {n_entries:5}')
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

    if not done:
        # get listings via /search
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
                step_s *= 2
                if t_start < created_on:
                    break
                continue
            else:
                if 'after' in data:
                    # if we where resuming from some point, we can
                    # delete it now.
                    del data['after']
                step_s = 86_400
                s_entries += 1
                progress = (k['name'], int(k['created_utc']))
                log(f'archiving ... {s_entries}', end='\r')
                output(k)
                if stop_at_n == progress[0] or stop_at_t >= progress[1]:
                    break
                if progress[1] <= created_on:
                    break
                t_start = progress[1]
                t_stop = t_start - step_s
                data['q'] = query_str.format(start=t_start, stop=t_stop)
        log(f'entries (/search): {s_entries:5}')

    if out_f is not None and out_f != '-':
        out_f.close()

except KeyboardInterrupt:
    log('interrupted', WARN)
    log(f'progress info: {progress}')

log(f'total entries found: {s_entries + n_entries}')
log(f'bye :-)')
