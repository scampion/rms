"""rms agent

this agent fetch job from the rms server
"""
import json
import os

import docker
import requests

client = docker.from_env()


def fetch(server_url, auth_token, storage):
    client.images.list()
    config = {"images": [str(i.id) for i in client.images.list()]}
    hed = {'Authorization': 'Bearer ' + auth_token}
    r = requests.post(server_url + '/fetch', headers=hed, json=config)
    if r.status_code == 404:
        print("No job found for the moment")
    elif r.status_code == 200:
        print(r.headers)
        sha1 = r.headers["X-rms-sha1"]
        image = r.headers["X-rms-image"]
        open(os.path.join(storage, sha1), 'wb').write(r.content)
        print(f"Process file {sha1} with docker image {image}")
    else:
        print("Error", r.status_code, r.content)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('auth_token', type=str, help="authentication token")
    parser.add_argument('--server_url', nargs='?', type=str, default="http://localhost:8000", help="rms server url")
    parser.add_argument('--storage', type=str, default="/tmp", help="storage directory")
    parser.add_argument('--refresh_period', nargs='?', type=int, default=15, help="refresh period in sec")
    args = parser.parse_args()
    fetch(args.server_url, args.auth_token, args.storage)
