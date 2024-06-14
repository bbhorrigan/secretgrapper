#!/usr/bin/python3

import requests
import re
import json
import time
import argparse
import mmap
import argcomplete
import config
import tokens
import os
import urllib.parse
from functools import partial
from datetime import datetime
from termcolor import colored
from urllib.parse import urlparse
from multiprocessing.dummy import Pool
from crontab import CronTab

def get_filename_for_query(query):
    query_name = query.replace(" ", "_") if query else "default"
    return f'rawGitUrls_{query_name}.txt'

def create_empty_binary_file(name):
    with open(name, 'wb') as f:
        f.write(1 * b'\0')

def init_file(name):
    if not os.path.exists(name) or os.path.getsize(name) == 0:
        with open(name, 'wb') as f:
            f.write(b'\0')
    with open(name, 'a+') as f:
        if f.tell() == 0:
            f.write("Initialized\n")
            f.flush()

def clean(result):
    clean_token = re.sub(tokens.CLEAN_TOKEN_STEP1, '', result.group(0))
    return re.sub(tokens.CLEAN_TOKEN_STEP2, '', clean_token)

def monitor():
    cmd = f'/usr/bin/python3 {path_script}/gitGraber.py -q "{args.query}"'
    my_cron = CronTab(user=True)
    job = my_cron.new(command=build_cron_command(cmd))
    job.minute.every(30)
    my_cron.write()

def build_cron_command(cmd):
    if args.discord and config.DISCORD_WEBHOOKURL:
        return build_cron_command_base(cmd, '-d')
    elif args.slack and config.SLACK_WEBHOOKURL:
        return build_cron_command_base(cmd, '-s')
    elif args.telegram and config.TELEGRAM_CONFIG.get("token") and config.TELEGRAM_CONFIG.get("chat_id"):
        return build_cron_command_base(cmd, '-tg')

def build_cron_command_base(cmd, platform_flag):
    command = f'{cmd} {platform_flag} -k {args.keywordsFile}'
    if args.wordlist:
        command += f' -w {args.wordlist}'
    return command

def check_token(content, tokens_map, tokens_combo):
    tokens_found = {}
    for token in tokens_map:
        regex_pattern = re.compile(token.getRegex())
        result = re.search(regex_pattern, content)
        if result:
            clean_token = clean(result)
            if not any(blacklisted in clean_token for blacklisted in token.getBlacklist()):
                tokens_found[clean_token] = token.getName()
    for combo in tokens_combo:
        result = check_combo_tokens(content, combo)
        if result:
            tokens_found[result] = combo.getName()
    return tokens_found

def check_combo_tokens(content, combo):
    result = [''] * len(combo.getTokens())
    for t in combo.getTokens():
        match = re.search(re.compile(t.getRegex()), content)
        if not match:
            return None
        result[t.getDisplayOrder() - 1] = clean(match)
    return ":".join(result)

def notify_discord(message):
    post_notification(config.DISCORD_WEBHOOKURL, message)

def notify_slack(message):
    post_notification(config.SLACK_WEBHOOKURL, json.dumps({'text': ':new:' + message}))

def notify_telegram(message):
    telegram_url = f"https://api.telegram.org/bot{config.TELEGRAM_CONFIG['token']}/sendMessage"
    post_notification(telegram_url, json.dumps({'text': message, 'chat_id': config.TELEGRAM_CONFIG['chat_id']}))

def post_notification(url, data):
    if url:
        requests.post(url, data=data, headers={"Content-Type": "application/json"})
    else:
        print(f'Please define the webhook URL for {url} to enable notifications')
        exit()

def write_to_wordlist(content, wordlist):
    with open(wordlist, 'a+') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as s:
            filename = content.split('/')[-1]
            if s.find(bytes(filename, 'utf-8')) == -1:
                f.write(filename + '\n')

def display_results(result, token_result, raw_git_url, url_infos):
    possible_token_string = f'[!] POSSIBLE {token_result[result]} TOKEN FOUND (keyword used: {githubQuery})'
    commit_string = f'[+] Commit {url_infos[2]} : {url_infos[3]} by {url_infos[4]}'
    url_string = f'[+] RAW URL : {raw_git_url}'
    token_string = f'[+] Token : {result.strip()}'
    repo_string = f'[+] Repository URL : {url_infos[1]}'
    org_string = f'\n[+] User Organizations : {",".join(url_infos[5])}' if url_infos[5] else ''
    result_strings = [possible_token_string, commit_string, url_string, token_string, repo_string, org_string]
    for line in result_strings:
        print(colored(line, 'green' if 'POSSIBLE' in line else ''))
    return '\n'.join(result_strings)

def parse_results(content, limit_days=None):
    data = json.loads(content)
    content_raw = {}
    with open(config.GITHUB_URL_FILE, 'a+', encoding='utf-8') as f:
        for item in data.get('items', []):
            process_github_item(item, content_raw, limit_days, f)
    return content_raw

def process_github_item(item, content_raw, limit_days, file):
    git_url = item['url']
    repo_name = item['repository']['full_name']
    org_url = item['repository']['owner']['organizations_url']
    raw_git_url = json.loads(do_request_github(git_url).text)['download_url']
    commit_info = get_commit_info(git_url, repo_name)
    if not is_commit_within_limit(commit_info['date'], limit_days):
        return
    if not is_url_in_file(file, raw_git_url):
        add_to_file_and_dict(file, raw_git_url, content_raw, commit_info, org_url)

def get_commit_info(git_url, repo_name):
    commit_hash = git_url.split('ref=')[1]
    commit_url = f"{config.GITHUB_API_COMMIT_URL}{repo_name}/commits/{commit_hash}"
    commit_data = json.loads(do_request_github(commit_url, True).text)
    commit_date = commit_data['commit']['author']['date']
    return {
        'date': commit_date,
        'relative_date': calculate_relative_date(commit_date),
        'author': commit_data['commit']['author']['email']
    }

def is_commit_within_limit(commit_date, limit_days):
    if not limit_days:
        return True
    current_timestamp = int(time.time())
    timestamp_commit = int(time.mktime(datetime.strptime(commit_date, '%Y-%m-%dT%H:%M:%SZ').timetuple()))
    compare_commit_date = (current_timestamp - timestamp_commit) / 3600
    return compare_commit_date <= limit_days * 24

def is_url_in_file(file, url):
    with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:
        return s.find(bytes(url, 'utf-8')) != -1

def add_to_file_and_dict(file, url, content_dict, commit_info, org_url):
    file.write(url + '\n')
    content_dict[url] = [
        do_request_github(url),
        f"{config.GITHUB_BASE_URL}/{repo_name}",
        commit_info['relative_date'],
        commit_info['date'],
        commit_info['author'],
        get_orgs(org_url)
    ]

def get_orgs(org_url):
    if org_url not in checked_orgs:
        checked_orgs[org_url] = [org['login'] for org in json.loads(do_request_github(org_url, True).text)]
    return checked_orgs[org_url]

def calculate_relative_date(commit_date):
    current_timestamp = int(time.time())
    timestamp_commit = int(time.mktime(datetime.strptime(commit_date, '%Y-%m-%dT%H:%M:%SZ').timetuple()))
    compare_commit_date = (current_timestamp - timestamp_commit) / 3600
    if compare_commit_date > 24:
        return f'({round(compare_commit_date / 24)} days ago)'
    return f'({round(compare_commit_date)} hours ago)'

def init_github_token():
    return [{"token": token, "remaining": 1, "reset": time.time()} for token in config.GITHUB_TOKENS]

def get_github_token(url):
    min_time_token = 0
    path = urlparse(url).path
    if path not in config.GITHUB_TOKENS_STATES:
        config.GITHUB_TOKENS_STATES[path] = init_github_token()
    return find_valid_token(path, min_time_token)

def find_valid_token(path, min_time_token):
    for token_state in config.GITHUB_TOKENS_STATES[path]:
        if token_state['remaining'] > 0:
            return token_state['token']
        if min_time_token == 0 or min_time_token['reset'] > token_state['reset']:
            min_time_token = token_state
    sleep_time = min_time_token['reset'] - int(time.time()) + 1
    if sleep_time > 0:
        print(f'[i] Sleeping {sleep_time} sec')
        time.sleep(sleep_time)
    return min_time_token['token']

def update_github_token(url, token, response):
    path = urlparse(url).path
    for i, token_state in enumerate(config.GITHUB_TOKENS_STATES[path]):
        if token == token_state['token']:
            token_state = update_token_state(token_state, response)
            config.GITHUB_TOKENS_STATES[path][i] = token_state

def update_token_state(token_state, response):
    if response.status_code != 200:
        token_state['remaining'] = 0
    elif 'X-RateLimit-Remaining' in response.headers:
        token_state['remaining'] = int(response.headers['X-RateLimit-Remaining'])
    if 'X-RateLimit-Reset' in response.headers:
        token_state['reset'] = int(response.headers['X-RateLimit-Reset'])
    elif 'Retry-After' in response.headers:
        token_state['reset'] = int(time.time()) + 1 + int(response.headers['Retry-After'])
    return token_state

def do_request_github(url, authd=True, verbose=False):
    headers = {'Accept': 'application/vnd.github.v3.text-match+json'}
    if authd:
        token = get_github_token(url)
        headers['Authorization'] = f'token {token}'
    for _ in range(config.GITHUB_MAX_RETRY):
        if verbose:
            print(colored(f'[i] Github query : {url}', 'yellow'))
        response = requests.get(url, headers=headers)
        if verbose:
            print(f'[i] Status code : {response.status_code}')
        if authd:
            update_github_token(url, token, response)
        if response.status_code == 200:
            return response
        handle_github_response(response, token)

def handle_github_response(response, token):
    if response.status_code == 403:
        handle_rate_limit_exceeded(response, token)
    else:
        print(colored(f'[!] Unexpected HTTP response {response.status_code}', 'red'))
        print(colored(response.text, 'red'))

def handle_rate_limit_exceeded(response, token):
    response_json = response.json()
    if "API rate limit exceeded" in response_json['message']:
        print(colored(f'[i] API rate limit exceeded for token {token}', 'yellow'))
    elif "abuse detection mechanism" in response_json['message']:
        print(colored(f'[i] Abuse detection reached for token {token}', 'yellow'))
    else:
        print(colored('[!] Unexpected response', 'red'))
        print(colored(response.text, 'red'))

def do_search_github(keyword, args, token_map, token_combos):
    url = f"{config.GITHUB_API_URL}{urllib.parse.quote(githubQuery + ' ' + keyword.strip())}{config.GITHUB_SEARCH_PARAMS}"
    print(url)
    response = do_request_github(url, True, True)
    if response:
        content = parse_results(response.text, args.limit_days)
        if content:
            process_github_content(content, token_map, token_combos, args)

def process_github_content(content, token_map, token_combos, args):
    for raw_git_url in content.keys():
        tokens_result = check_token(content[raw_git_url][0].text, token_map, token_combos)
        for token in tokens_result.keys():
            display_message = display_results(token, tokens_result, raw_git_url, content[raw_git_url])
            send_notifications(display_message, args)
            if args.wordlist:
                write_to_wordlist(raw_git_url, args.wordlist)

def send_notifications(message, args):
    if args.discord:
        notify_discord(message)
    if args.slack:
        notify_slack(message)
    if args.telegram:
        notify_telegram(message)

def search_github(keywords_file, args):
    token_map, token_combos = tokens.initTokensMap()
    with open(keywords_file) as f:
        keywords = f.read().split("\n")
    pool = Pool(int(args.max_threads))
    pool.map(partial(do_search_github, args=args, token_map=token_map, token_combos=token_combos), keywords)
    pool.close()
    pool.join()

parser = argparse.ArgumentParser()
argcomplete.autocomplete(parser)
parser.add_argument('-t', '--threads', default="3", help='Max threads to speed the requests on Github (take care about the rate limit)')
parser.add_argument('-k', '--keyword', default="wordlists/keywords.txt", help='Specify a keywords file (-k keywordsfile.txt)')
parser.add_argument('-q', '--query', help='Specify your query (-q "myorg")')
parser.add_argument('-d', '--discord', action='store_true', help='Enable discord notifications', default=False)
parser.add_argument('-s', '--slack', action='store_true', help='Enable slack notifications', default=False)
parser.add_argument('-tg', '--telegram', action='store_true', help='Enable telegram notifications', default=False)
parser.add_argument('-m', '--monitor', action='store_true', help='Monitors your query by adding a cron job for every 30 mins', default=False)
parser.add_argument('-w', '--wordlist', help='Create a wordlist that fills dynamically with discovered filenames on GitHub')
parser.add_argument('-l', '--limit', dest='limit_days', type=int, help='Limit the results to commits less than N days old', default=None)
args = parser.parse_args()

if not args.query:
    print('No query (-q or --query) is specified, default query will be used')
    args.query = ' '
    githubQuery = args.query

keywords_file = args.keywordsFile
githubQuery = args.query
path_script = os.path.dirname(os.path.realpath(__file__))
config.GITHUB_TOKENS_STATES = {}
checked_orgs = {}

if args.wordlist:
    init_file(args.wordlist)
if args.monitor:
    monitor()
else:
    pass

config.GITHUB_URL_FILE = get_filename_for_query(args.query)
init_file(config.GITHUB_URL_FILE)

search_github(keywords_file, args)
