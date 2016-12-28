#!/bin/bash
key_id=`curl \
  "https://api.github.com/users/jbmmhk/keys" | \
python -c "import sys, json; print(json.load(sys.stdin)[0]['id'])"`

curl \
  -H 'X-GitHub-OTP:'"$2" \
  -H "Content-Type: application/json" \
  -X DELETE \
  -u $1 \
  "https://api.github.com/user/keys/"$key_id""
