#!/usr/bin/python3
import sys
import requests

from getpass import getpass

if len(sys.argv) != 2:
    raise ValueError('Script should be run with the following parameters:\n \
                        \t./update-key.sh [user]')
user = sys.argv[1]
auth = ''
methods = {
    'GET': requests.get,
    'POST': requests.post,
    'DELETE': requests.delete
}


def get_auth_code():
    global auth
    if auth != '':
        new_auth = input('Two-Factor Authorization ($auth): ')
    else:
        new_auth = input('Two-Factor Authorization: ')

    if new_auth != '':
        auth = new_auth
    return auth


def request_url(url, method_name, headers=None, data=None, request_auth=None):
    method = methods[method_name]
    result = method(url, headers=headers, json=data, auth=request_auth)

    return result


def request_url_by_token():
    pass


def request_url_by_credentials(*args, **kwargs):
    if False:  # BAD CREDENTIALS
        pass

print('Creating an auth token for further requests.')
create_token_response = request_url(
    url='https://api.github.com/authorizations',
    method_name='POST',
    data={
        'scopes': ['admin:public_key'],
        'note': 'Update ssh key'
    },
    headers={
        'X-GitHub-OTP': get_auth_code(),
        'Content-Type': 'application/json'
    },
    request_auth=(user, getpass('Password for [%s]: ' % user))
)

ctr_json = create_token_response.json()

print(ctr_json)
auth_token = ctr_json.get('token', None)

if not auth_token:



# token_response=`curl -sS \
#  -u '$1' \
#  -H 'X-GitHub-OTP:'$auth'' \
#  -X POST \
#  -H 'Content-Type: application/json' \
#  -d '{'scopes': ['admin:public_key'], 'note': 'Update ssh key'}' \
#  'https://api.github.com/authorizations'`
