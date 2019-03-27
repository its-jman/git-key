# git-key
Script to create and attach a local SSH key to your GitHub account (Python, GitHub API)

## Pre-requisites

- You must have [Python 3](https://www.python.org/downloads/) installed.
- Once you have Python installed, use the respective `pip` script (often `pip3`) to install the requests library. 
```bash
pip3 install requests
```

## Running

Clone a copy of the repo:
```bash
git clone https://github.com/jbmanning/git-key
```

Change to the git-key directory
```bash
cd git-key/
```

All-in-one: Create new ssh id, add to ssh-agent, and upload to your GitHub account. 
```bash
python3 update-key.py [github username]
```

It will ask for your password and two-factor auth if you have it enabled.
