#!/bin/bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
ssh-add ~/.ssh/id_rsa

value=`cat ~/.ssh/id_rsa.pub`

curl -v \
  -H 'X-GitHub-OTP:'"$2" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"title": "'"$1"'-desk.key", "key": "'"$value"'"}' \
  -u $1 \
  "https://api.github.com/user/keys"
