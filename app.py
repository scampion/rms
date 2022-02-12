"""rms
a simple job scheduler used to share job on GPU workstation ... initially

Sebastien Campion
"""
import base64
import hashlib
import json
import os.path
import time
import uuid
import logging

import jwt
import redis
from starlette.responses import JSONResponse, HTMLResponse, Response
from starlette.applications import Starlette
from starlette.routing import Route


async def homepage(request):
    return HTMLResponse(content=open("index.html").read())

async def uploadfiles(request):
    try:
        form = await request.form()
        assert form['email'].split('@')[1] in email_domains, f"{form['email']} email domain is not allowed"
        oid = uuid.uuid1()
        r.hmset(f"orders:{oid}", {"image": form["image"],
                                  "time": time.time(),
                                  "email": form['email'],
                                  "status": "tobeconfirmed"})
        r.expire(f"orders:{oid}", ttl)
        r.publish('order', str(oid))
        files = form.getlist("files")
        await register_files(files, form["image"], oid)
        return JSONResponse({'status': 'registered', 'oid': str(oid)})
    except Exception as e:
        return await error_handler(e)


async def register_files(files, image, oid):
    for f in files:
        contents = await f.read()
        sha1 = hashlib.sha1(contents).hexdigest()
        filepath = os.path.join(storage, sha1)
        with open(filepath, 'wb') as outfile:
            outfile.write(contents)
        r.hset(f"files:{sha1}", "filename", f.filename)
        r.hset(f"files:{sha1}", "content_type", f.content_type)
        r.lpush(f"orders:files:{oid}", sha1)
        r.lpush(f"jobs:{image}", sha1)


async def status(request):
    oid = request.path_params.get('oid', '').encode('utf8')
    if r.exists(f"orders:{oid}"):
        r.hmset(f"orders:{oid}", "status", "todo")
        return JSONResponse({'status': 'inqueue'})
    else:
        return JSONResponse({'status': 'notfound'})


async def fetch(request):
    try:
        ip = request.client.host.encode('utf8')
        assert ip in r.smembers("ips_allowed"), f"ip {ip} not authorized"
        runner = request.path_params.get('runner', '')
        assert runner.encode('utf8') in r.smembers("runners"), f"runner {runner} unknown"
        assert 'Authorization' in request.headers, "Authorization needed"
        auth_token = request.headers['Authorization'].replace('Bearer ','').encode('utf8')
        key = r.hget(f"runners:{runner}", "key").decode('utf8')
        data = jwt.decode(auth_token, key, algorithms="HS256")
        assert data.get("name") == runner, "Name not decoded"
        data = await request.json()
        for i in data.get("images", []):
            sha1 = r.lpop("jobs:"+i)
            if sha1:
                sha1 = sha1.decode('utf8')
                r.hmset(f"inprogress:{i}:{sha1}", {"time": time.time(), "runner": auth_token})
                media_type = str(r.hget(f"file:{sha1}", "content_type"))
                filepath = os.path.join(storage, sha1)
                response = Response(content=open(filepath, 'rb').read(), media_type=media_type)
                response.headers['X-rms-sha1'] = sha1
                response.headers['X-rms-image'] = i
                return response
        return Response('', status_code=404)
    except Exception as e:
        return await error_handler(e)


async def error_handler(e):
    eid = uuid.uuid1()
    logging.error(f"{eid} - {e}")
    return JSONResponse({'error': str(eid)}, status_code=500)


########################################################################################################################

print("Start server ...")
r = redis.Redis()
storage = "/tmp"
ttl = 60 * 60 * 24
email_domains = []

# Overwrite config params if needed
config_file = os.environ.get("RMS_CONFIG_FILE", None)
if config_file:
    logging.info("rms config file configured")
    config = json.load(open(config_file))
    r = redis.Redis.from_url(config['redis_url']) if 'redis_url' in config.keys() else r
    ttl = config.get('ttl', ttl)
    email_domains = config.get('email_domains', email_domains)
    print(email_domains)
    storage = config.get('storage', storage)
    for runner, params in config.get('runners', {}).items():
        r.sadd("runners", runner)
        r.hmset("runners:" + runner, params)
        for k, v in params.items():
            if k == 'ip':
                r.sadd('ips_allowed', v)
            if k == 'host':
                r.sadd('hosts_allowed', v)

app = Starlette(debug=True, routes=[
    Route('/', endpoint=homepage),
    Route('/uploadfiles', endpoint=uploadfiles, methods=['POST']),
    Route("/status/{oid}", endpoint=status),
    Route('/fetch/{runner}', endpoint=fetch, methods=['GET', 'POST']),
])
