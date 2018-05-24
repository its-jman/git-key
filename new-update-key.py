#!/usr/bin/python3
import sys
import time
import json
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
    user_ssh_keys = request_url_by_token(
        access_token,
        url='https://api.github.com/user/keys',
        method_name='GET'
    ).json()
    #print('USER SSH', user_ssh_keys)

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
    """
    SECRET -> Create a PAT token for future requests.
    PAT -> Update SSH key
    SECRET -> Delete PAT token
    :return:
    """
    full_host = '%s@%s' % (getuser(), gethostname())

    # Create PAT for given user.
    response = requests.put(
        url='https://api.jman.me/gh/ssh/create-pat',
        json={
            'full_host': full_host,
            'auth_code': get_auth_code(),
            'user': user,
            'pass': getpass('Password for [%s]: ' % user)
        },
        headers={
            'Content-Type': 'application/json'
        }
    )
    pat = json.loads(response.json()).get('pat', None)

    if pat is None:
        print('Failure in PAT creation.')
        return

    sleep(3)

    update_ssh_key(pat, '%s@%s' % (getuser(), gethostname()))

    sleep(3)

    # Delete PAT owned by app.
    print('SEDING DELETE')
    response = requests.delete(
        url='https://api.jman.me/gh/ssh/delete-pat?pat=%s' % pat,
    )
    print(response.text)
    if response.text != '"204"':
        print('Failure in delete PAT.')


if __name__ == '__main__':
    main()


# Delete PAT owned by app.
"""
import requests
import boto3
import os

from base64 import b64decode

client_id = decrypt(os.environ['client_id'])
client_secret = decrypt(os.environ['client_secret'])


def decrypt(value):
    return boto3.client('kms').decrypt(CiphertextBlob=b64decode(value))['Plaintext']


def lambda_handler(event, context):
    pat_token = ''

    response = requests.delete(
        url='https://api.github.com/applications/%s/tokens/%s' % (client_id, pat_token),
        auth=(client_id, client_secret)
    )

    return response
"""
