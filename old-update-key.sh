#!/bin/bash

getAuthCode() {
  if [ "$auth" != "" ]
  then
    echo -n "Two-Factor Authorization ($auth): "
  else
    echo -n "Two-Factor Authorization: "
  fi
  read newAuth

  if [ "$newAuth" != "" ]
    then
      auth="$newAuth"
  fi
}

# Verify the correct parameters were passed
if [ $# -ne 1 ]
  then
    echo "Script should be run with the following parameters:"
    echo "./update-key.sh [user]"
    exit
fi

getAuthCode

echo "Creating an auth token for further requests."
# Creating the access token
token_response=`curl -sS \
 -u "$1" \
 -H "X-GitHub-OTP:"$auth"" \
 -X POST \
 -H "Content-Type: application/json" \
 -d '{"scopes": ["admin:public_key"], "note": "Update ssh key"}' \
 "https://api.github.com/authorizations"`

# Checking if there were errors when creating the token
errors=`echo "$token_response" | python -c "import sys,json; print(int('errors' in json.load(sys.stdin)))"`
if [ "$errors" -eq 0 ]
then
  echo "TOKEN CREATION: "$errors""
  access_token=`echo "$token_response" | python -c "import sys,json; print(json.load(sys.stdin)['token'])"`
  token_id=`echo "$token_response" | python -c "import sys,json; print(json.load(sys.stdin)['id'])"`

  echo "Finding the pre-existing ssh key's ID. "
  key_title="$USER"@"$HOSTNAME"
  key_id_res=`curl -sS \
    -u "$1":"$access_token" \
    "https://api.github.com/user/keys"`
  echo "KEY ID RES: "$key_id_res""
  key_id = `echo "$key_id_res" | \
    python find_key_id.py "$key_title"`
  echo "KEY ID: "$key_id""

  if [ "$key_id" != "" ]
  then
    echo "Removing the pre-existing ssh key."
    remove_result=`curl \
      -u "$1":"$access_token" \
      -X DELETE \
      "https://api.github.com/user/keys/"$key_id""`
    echo "REMOVE RESULT: "$remove_result""
  fi

  echo "Creating an SSH key to upload."
  ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
  ssh-add ~/.ssh/id_rsa
  ssh_pub_value=`cat ~/.ssh/id_rsa.pub`

  echo "Uploading SSH key."
  ssh_result=`curl -sS \
    -u "$1":"$access_token" \
    -H "Content-Type: application/json" \
    -X POST \
    -d '{"title": "'"$key_title"'", "key": "'"$ssh_pub_value"'"}' \
    "https://api.github.com/user/keys"`
  echo "SSH RESULT: "$ssh_result""

  # Create an ssh key, and send it to GH.
else
  echo "The auth token already exists, to find the id of the auth token to replace, re-enter your credentials."
  getAuthCode
  list_response=`curl -sS \
    -u "$1" \
    -H "X-GitHub-OTP:"$auth"" \
    -X GET \
    "https://api.github.com/authorizations"`
  token_id=`echo "$list_response" | python find_token_id.py "Update ssh key"`
  # echo "LIST RESPONSE: "$list_response""
fi

echo "To remove the auth token ("$token_id"), you must re-enter your credentials."
getAuthCode

# Remove the access token that was just created
tokenRemoval=`curl -sS \
  -u "$1" \
  -H "X-GitHub-OTP:"$auth"" \
  -X DELETE \
  "https://api.github.com/authorizations/"$token_id""`

echo "TOKEN REMOVAL: "$tokenRemoval""
