import requests
import boto3
import json
import os

from base64 import b64decode


def my_decrypt(value):
    return boto3.client('kms').decrypt(CiphertextBlob=b64decode(value))['Plaintext'].decode('utf-8')


client_id = my_decrypt(os.environ['client_id'])
client_secret = my_decrypt(os.environ['client_secret'])


def lambda_handler(event, context):
    full_host = event.get('full_host', None)
    user = event.get('user', None)
    pwd = event.get('pass', None)
    auth_code = event.get('auth_code', None)

    status = 505
    pat = None

    if full_host and user and pwd and auth_code:
        print('Sending request')
        response = requests.put(
            url='https://api.github.com/authorizations/clients/%s/%s' % (client_id, full_host),
            json={
                'client_secret': client_secret,
                'scopes': ['admin:public_key'],
                'note': 'SSH for %s' % full_host,
            },
            headers={
                'X-GitHub-OTP': auth_code
            },
            # Always add the credentials to the request.
            auth=(user, pwd)
        )
        print(response)
        print(response.json())
        pat = response.json().get('token', None)
        status = response.status_code

    out = json.dumps({
        "pat": pat
    })

    return out
