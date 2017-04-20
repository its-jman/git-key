import requests
import boto3
import os

from base64 import b64decode


def my_decrypt(value):
    return boto3.client('kms').decrypt(CiphertextBlob=b64decode(value))['Plaintext'].decode('utf-8')


client_id = my_decrypt(os.environ['client_id'])
client_secret = my_decrypt(os.environ['client_secret'])


def lambda_handler(event, context):
    pat_token = event.get('pat', None)
    status = 404
    if pat_token:
        response = requests.delete(
            url='https://api.github.com/applications/%s/tokens/%s' % (client_id, pat_token),
            auth=(client_id, client_secret)
        )
        status = response.status_code
        print(response)
        print(response.json())

    return str(status)
