import sys
from hashlib import sha1
import requests

url = 'https://api.pwnedpasswords.com/range/{password}'


def check_passwords(passwords):
    for password in passwords:
        hashed_password = hash_password(password)
        response = get_pwned_passwords(hashed_password)
        result = handle_response(hashed_password, response)
        if result == 0:
            print(f"No matches found for {password}")
        else:
            print(f"{password} found in {result} breaches.")


def get_pwned_passwords(password):
    request_url = url.replace('{password}', password[:5])

    try:
        with requests.get(request_url) as r:
            if r.status_code != 200:
                raise RuntimeError(f'Error fetching: {r.status_code}')
            return r
    except requests.exceptions.Timeout as e:
        print(e)
    except requests.exceptions.TooManyRedirects as e:
        print(e)
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(1)


def handle_response(password, response):
    password = password[5:]
    hashes = dict(line.split(':') for line in response.text.splitlines())

    if password in hashes.keys():
        return hashes[password]
    return 0


def hash_password(password) -> str:
    return sha1(password.encode('utf-8')).hexdigest().upper()


if __name__ == '__main__':
    try:
        check_passwords(sys.argv[1:])
    except RuntimeError as err:
        print(err)
