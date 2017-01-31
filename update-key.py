#!/usr/bin/python3
import sys
import requests
import subprocess

from os import path
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
    'DELETE': requests.delete
}
invalid_credential_messages = [
    'Bad credentials',
    'Must specify two-factor authentication OTP code.'
]


def update_ssh_key(access_token, ssh_key_name):
    print('\nFinding existing SSH keys on GitHub. ')
    user_ssh_keys = request_url_by_token(access_token, url='https://api.github.com/user/keys', method_name='GET').json()
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


def remove_pat(pat_id):
    if pat_id is None:
        print('Invalid PAT id in remove_pat.')
        sys.exit(1)
    print('Removing Personal Access token, ID: (%s)' % pat_id)
    return request_url_by_credentials(
        url='https://api.github.com/authorizations/%s' % pat_id,
        method_name='DELETE'
    )


def remove_existing_pat():
    """
    Get existing tokens
    Find the one with 'Update SSH key' as the name
    Remove that PAT
    :return:
    """
    print('\nThe \'%s\' PAT already exists, attempting to remove. ' % pat_name)
    existing_tokens = request_url_by_credentials(url='https://api.github.com/authorizations', method_name='GET').json()
    old_token = list(filter(lambda item: item.get('note') == pat_name, existing_tokens))[0]

    remove_pat(old_token.get('id', None))


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


def get_auth_code():
    global auth
    if auth != '':
        new_auth = input('Two-Factor Authorization (%s): ' % auth)
    else:
        new_auth = input('Two-Factor Authorization: ')

    if new_auth != '':
        auth = new_auth
    return auth


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


@url_function
def request_url_by_credentials(**kwargs):
    response = None
    while response is None:
        # Always add the Two-Factor header.
        kwargs['headers'].update({
            'X-GitHub-OTP': get_auth_code()
        })
        # Always add the credentials to the request.
        kwargs.update({
            'auth': (user, getpass('Password for [%s]: ' % user))
        })

        response = request_url(**kwargs)

        # DELETE responses do not contain a body, and crash upon calling .json()
        if response.text:
            response_json = response.json()

            # Continue loop if entered bad credentials
            if type(response_json) == dict:
                if response_json.get('message') in invalid_credential_messages:
                    response = None
    return response


def main():
    print('Creating a Personal Access Token for further requests.')
    create_token_response = request_url_by_credentials(
        url='https://api.github.com/authorizations',
        method_name='POST',
        data={
            'scopes': ['admin:public_key'],
            'note': pat_name
        },
        headers={
            'Content-Type': 'application/json'
        }
    )

    ctr_json = create_token_response.json()

    pat_token = ctr_json.get('token', None)
    if pat_token:
        # Personal Access Token ID, used for removal at the end.
        pat_token_id = ctr_json.get('id')
        update_ssh_key(pat_token, '%s@%s' % (getuser(), gethostname()))
        remove_pat(pat_token_id)
    else:
        errors = ctr_json.get('errors', None)
        if errors:
            code = errors[0].get('code')
            if code == 'already_exists':
                remove_existing_pat()
                print('Removed existing PAT, please try running the program again. ')
        else:
            print('Creation of Personal Access Token failed. ')
            sys.exit(1)


if __name__ == '__main__':
    main()
