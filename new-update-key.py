#!/usr/bin/python3
import sys
import requests
import subprocess

from os import path
from time import sleep
from socket import gethostname
from getpass import getpass, getuser


if len(sys.argv) != 2:
    raise ValueError('Script should be run with the following parameters:\n \
                        \t./update-key.sh [user]')

user = sys.argv[1]
# Two-Factor Auth code
auth = ''
pat_name = 'Update SSH key'
# Corresponding method names and method functions.
methods = {
    'GET': requests.get,
    'POST': requests.post,
    'DELETE': requests.delete,
    'PUT': requests.put
}
invalid_credential_messages = [
    'Bad credentials',
    'Must specify two-factor authentication OTP code.'
]

client_id = '8c27cf83d50c2d40022e'


def get_auth_code():
    global auth
    if auth != '':
        new_auth = input('Two-Factor Authorization (%s): ' % auth)
    else:
        new_auth = input('Two-Factor Authorization: ')

    if new_auth != '':
        auth = new_auth
    return auth


def url_function(f):
    def out_f(*args, **kwargs):
        if kwargs.get('headers', None) is None:
            kwargs.update({
                'headers': {}
            })
        if kwargs.get('data', None) is not None:
            kwargs['json'] = kwargs.pop('data')
        return f(*args, **kwargs)
    return out_f


def request_url(**kwargs):  # url, method_name, headers=None, data=None, request_auth=None):
    method = methods[kwargs.pop('method_name')]
    response = method(**kwargs)

    return response


@url_function
def request_url_by_token(access_token, **kwargs):
    """
    Requests URL by Personal Access Token provided by initial API request.
    :return:
    """
    # Always add the credentials to the request.
    kwargs.update({
        'auth': (user, access_token)
    })

    response = request_url(**kwargs)

    return response


def update_ssh_key(access_token, ssh_key_name):
    print('\nFinding existing SSH keys on GitHub. ')
    user_ssh_keys = request_url_by_token(access_token, url='https://api.github.com/user/keys', method_name='GET').json()
    print('USER SSH', user_ssh_keys)
    old_ssh = list(filter(lambda item: item.get('title') == ssh_key_name, user_ssh_keys))
    # If the key already exists, delete it.
    if len(old_ssh):
        old_ssh_id = old_ssh[0].get('id')

        print('\nDeleting old SSH key, ID: (%s)\n' % old_ssh_id)
        request_url_by_token(
            access_token,
            url='https://api.github.com/user/keys/%s' % old_ssh_id,
            method_name='DELETE'
        )
    ssh_path = path.expanduser('~/.ssh/id_rsa')

    subprocess.run(['ssh-keygen', '-t', 'rsa', '-b', '4096', '-f', ssh_path, '-N', ''])
    subprocess.run(['ssh-add', ssh_path])
    with open(ssh_path + '.pub', 'r') as ssh_file:
        ssh_value = ssh_file.readline()

    print('\nAdding the created token to your GitHub account. ')
    response = request_url_by_token(
        access_token,
        url='https://api.github.com/user/keys',
        method_name='POST',
        headers={
            'Content-Type': 'application/json'
        },
        data={
            'title': ssh_key_name,
            'key': ssh_value
        }
    )

    if response.json().get('verified'):
        print('Success!\n')
    else:
        print('Something unexpected happened. ')
        print(response)


def main():
    full_host = '%s@%s' % (getuser(), gethostname())
    response = requests.put(
        url='https://api.github.com/authorizations/clients/%s/%s' % (client_id, full_host),
        json={
            'client_secret': client_secret,
            'scopes': ['admin:public_key'],
            'note': 'SSH for %s' % full_host,
        },
        headers={
            'X-GitHub-OTP': get_auth_code()
        },
        # Always add the credentials to the request.
        auth=(user, getpass('Password for [%s]: ' % user))
    )

    print(response.json())
    print('token: [%s]' % response.json()['token'])
    pat_token = response.json()['token']
    # pat_token = '7a76c4ddddaf78cd2c7f6cff535d5d52465fad5f'
    # token_id = '79961765'

    sleep(3)

    update_ssh_key(pat_token, '%s@%s' % (getuser(), gethostname()))

    # response = requests.get(
    #     url='https://api.github.com/user/keys',
    #     auth=(user, pat_token)
    # )

    print('resp2', response.json())

    sleep(3)

    print('SEDING DELETE')
    response = requests.delete(
        url='https://api.github.com/applications/%s/tokens/%s' % (client_id, pat_token),
        auth=(client_id, client_secret)
    )

    print(response.status_code)


if __name__ == '__main__':
    main()
