import html
import re
import sys

import click
import requests

import onion

@click.group()
def main():
    pass

@main.command()
def fetch():
    res = requests.get('https://www.tomdalling.com/toms-data-onion/')
    res.raise_for_status()
    sys.stdout.write(extract_pre(res.text))

def extract_pre(text):
    match = re.search(r'<pre>\n?(.*?)</pre>', text, re.DOTALL | re.IGNORECASE)
    if match:
        return html.unescape(match[1])
    raise ValueError('missing pre tag')

@main.command()
def peel():
    sys.stdout.write(onion.read_payload(sys.stdin).decode('ascii'))

@main.command()
def wrap():
    onion.write_payload(sys.stdout, sys.stdin.read().encode('ascii'))

if __name__ == '__main__':
    main()
