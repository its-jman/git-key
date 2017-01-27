import sys
import json

val = json.load(sys.stdin)
type(val)
keys = filter(lambda key: key['app']['name'] == sys.argv[1], val)

if len(keys):
    print(keys[0]['id'])
