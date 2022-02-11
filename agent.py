import json
import docker

client = docker.from_env()

client.images.list()
print( {"images": [str(i.id) for i in client.images.list()]})

with open("agent.json", "w") as f:
    json.dump(f, {"images": [str(i.id) for i in client.images.list()]})