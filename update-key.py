#!/bin/bash python3
import sys
import time
import json
import requests
import subprocess
import atexit

from os import path
from time import sleep
from socket import gethostname
from getpass import getpass, getuser

auth_code = None


def get_bool(prompt):
    return input(prompt).lower() == 'y'


def get_parameters():
    if len(sys.argv) != 2:
        print(f'Usage: \n\t{__file__} [user]')
        return sys.exit(1)

    hostname = '%s@%s' % (getuser(), gethostname())

    uname = sys.argv[1]
    pwd = getpass(f'Password for [{uname}]: ')

    return hostname, uname, pwd


def update_auth_code(uname):
    global auth_code
    auth_code = input(f'Two-Factor Authorization ({uname}): ')


def send_gh_req(uname, pwd, cbs, i=0, **kwargs):
    global auth_code

    headers = kwargs.get('headers', {})
    headers.update({
        "X-GitHub-OTP": auth_code,
    })

    resp = requests.request(
        **kwargs,
        headers=headers,
        auth=(uname, pwd)
    )

    if resp.status_code == 401:
        otp_status = resp.headers.get('X-GitHub-OTP')
        if otp_status is not None:
            # Prevent infinite recursion if something is going wrong
            if i > 2:
                return None

            update_auth_code(uname)
            return send_gh_req(uname, pwd, cbs, i + 1, **kwargs)
    else:
        cb = cbs.get(resp.status_code)
        if cb is not None:
            return cb(resp)
        else:
            print("Unknown response")
            print(resp.status_code)
            return None
    return None


def get_old_pat_id(hostname, uname, pwd):
    print("\nSearching for matching token ID on GitHub")

    def code_200(resp):
        user_tokens = resp.json()
        matching_tokens = list(
            filter(lambda key: key.get('note') == f"SSH for {hostname}", user_tokens)
        )

        if len(matching_tokens) == 1:
            print(f'Found matching token ["SSH for {hostname}"]')
            return matching_tokens[0].get('id')
        return None

    cbs = {
        200: code_200
    }

    return send_gh_req(
        uname, pwd, cbs,
        method='GET',
        url='https://api.github.com/authorizations',
        json={
            "scopes": ["admin:public_key"],
            "note": f"SSH for {hostname}"
        }
    )


def remove_old_pat(uname, pwd, pat_id):
    print('\nRemoving access token')

    def code_204(resp):
        sleep(2)
        return True

    cbs = {
        204: code_204
    }

    return send_gh_req(
        uname, pwd, cbs,
        method='DELETE',
        url=f'https://api.github.com/authorizations/{pat_id}',
    )


def create_pat(hostname, uname, pwd):
    print('\nCreating access token')

    def code_201(resp):
        sleep(2)
        body = resp.json()
        return body.get('id'), body.get('token')

    def code_422(resp):
        body = resp.json()
        for err in body.get('errors', []):
            if err.get('code') == 'already_exists':
                print(f'\nPAT for [{hostname}] already exists')

                continue_remove = get_bool('Would you like to unregister it on GitHub?\n'
                                           'This will remove all associated SSH keys. (y/n) ')
                if not continue_remove:
                    print('Can\'t upload new key if there is a pre-existing key that matches')
                    return sys.exit(1)

                old_pat_id = get_old_pat_id(hostname, uname, pwd)
                remove_old_pat(uname, pwd, old_pat_id)

                return create_pat(hostname, uname, pwd)

    cbs = {
        201: code_201,
        422: code_422
    }

    return send_gh_req(
        uname, pwd, cbs,
        method='POST',
        url=f'https://api.github.com/authorizations',
        json={
            "scopes": ["admin:public_key"],
            "note": f"SSH for {hostname}"
        }
    )


def remove_old_key(pat, hostname):
    print("\nChecking for matching ssh keys on GitHub")
    resp = requests.get(
        url='https://api.github.com/user/keys',
        headers={
            "Authorization": f"token {pat}"
        }
    )

    body = resp.json()
    if resp.status_code == 200:
        user_keys = body
        matching_keys = list(
            filter(lambda key: key.get('title') == hostname, user_keys)
        )

        if len(matching_keys) == 1:
            print(f'Found key with matching hostname [{hostname}]')
            continue_remove = input('Would you like to unregister it on GitHub (y/n)? ').lower()
            if continue_remove != 'y':
                print('Can\'t upload new key if there is a pre-existing key that matches')
                return sys.exit(1)

            matching_key = matching_keys[0]
            resp = requests.delete(
                url=matching_key.get('url'),
                headers={
                    "Authorization": f"token {pat}"
                }
            )

            if resp.status_code != 204:
                print('Unknown response to deleting key')
                print(resp.status_code)
        else:
            print('No matching ssh keys.')


def generate_local_key():
    ssh_path = path.expanduser('~/.ssh/id_rsa')

    print("\nGenerating key")
    subprocess.run(['ssh-keygen', '-q', '-t', 'rsa', '-b', '4096', '-f', ssh_path, '-N', ''])
    print("Adding identity to SSH-Agent")
    subprocess.run(['ssh-add', ssh_path])

    with open(f'{ssh_path}.pub', 'r') as public_key:
        ssh_value = public_key.read().strip()

    if ssh_value != '':
        return ssh_value
    return None


def upload_new_key(pat, hostname, public_key):
    print("\nUploading key")
    resp = requests.post(
        url='https://api.github.com/user/keys',
        headers={
            "Authorization": f"token {pat}"
        },
        json={
            'title': hostname,
            'key': public_key
        }
    )

    body = resp.json()
    if resp.status_code == 201:
        return body.get('id')
    else:
        print('Failure uploading key')
        print(resp.status_code)
        print(body.get('errors'))
        return None


def update_ssh_key(pat, hostname):
    public_key = generate_local_key()
    if public_key is None:
        print("Failed to create local key")
        return None

    remove_old_key(pat, hostname)
    return upload_new_key(pat, hostname, public_key)


def main():
    hostname, uname, pwd = get_parameters()

    pat_id, pat = create_pat(hostname, uname, pwd)
    if pat_id is None or pat is None:
        print("Failure authenticating")
        return sys.exit(1)

    key_id = update_ssh_key(pat, hostname)
    if key_id is None:
        print("Failed to upload key")
        return sys.exit(1)

    print('Success! ')


if __name__ == '__main__':
    main()
