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

import redis
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from starlette.responses import JSONResponse, HTMLResponse, Response
from starlette.applications import Starlette
from starlette.routing import Route


async def homepage(request):
    content = """
    <body>
    <form action="/uploadfiles/" enctype="multipart/form-data" method="post">
    Select files : <input name="files" type="file" multiple><br>
    Select the task : 
    <select name="task" id="task">
      <option value="476423317124.dkr.ecr.eu-central-1.amazonaws.com/app/keywords">keywords</option>
      <option value="476423317124.dkr.ecr.eu-central-1.amazonaws.com/app/summarization">summarization</option>
    </select><br>
    Email : <input type="text" id="email" name="email" required><br>
    <input type="submit">    
    </form>
    </body>
    """
    return HTMLResponse(content=content)


async def uploadfiles(request):
    try:
        session_key = get_random_bytes(16)
        form = await request.form()
        assert form['email'].split('@')[1] in email_domains, f"{form['email']} email domain is not allowed"
        oid = uuid.uuid1()
        r.hmset(f"orders:{oid}", {"task": form["task"],
                                  "aeskey": base64.b64encode(session_key),
                                  "time": time.time(),
                                  "email": form['email']})
        r.expire(f"orders:{oid}", ttl)
        r.lpush("tobeconfirmed", str(oid))
        r.publish('tobeconfirmed', str(oid))
        files = form.getlist("files")
        await register_files(files, oid, session_key)
        return JSONResponse({'status': 'registered', 'oid': str(oid)})
    except Exception as e:
        return await error_handler(e)


async def register_files(files, oid, session_key):
    for f in files:
        contents = await f.read()
        sha1 = hashlib.sha1(contents).hexdigest()
        filepath = os.path.join(storage, sha1)
        await write_enc_file(contents, filepath, session_key)
        r.hset(f"files:{sha1}", "filename", f.filename)
        r.hset(f"files:{sha1}", "content_type", f.content_type)
        r.lpush(f"orders:files:{oid}", sha1)


async def write_enc_file(contents, filepath, session_key):
    with open(filepath, 'wb') as outfile:
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(contents)
        outfile.write(cipher_aes.nonce)
        outfile.write(tag)
        outfile.write(ciphertext)


async def status(request):
    oid = request.path_params.get('oid', '')
    oid = oid.encode('utf8')
    if oid in r.lrange('tobeconfirmed', 0, -1):
        r.lpush("todo", oid)
        r.lrem("tobeconfirmed", -1, oid)
    position = r.lrange("todo", 0, -1).index(oid) + 1
    queue_size = r.llen("todo")
    return JSONResponse({'status': 'inqueue', 'position': position, 'queue_size': queue_size})


async def file(request):
    sha1 = request.path_params['sha1']
    assert sha1.isalnum(), "Your hash is suspicious"
    filepath = os.path.join(storage, sha1)
    with open(filepath, 'rb') as f:
        return Response(content=open(filepath, 'rb').read(), media_type=str(r.hget(f"file:{sha1}", "content_type")))


# To be deteled / used for decryption test
async def get(request):
    oid = request.path_params['oid']
    sha1 = request.path_params['sha1']
    session_key = base64.b64decode(r.hmget(f"params:{oid}", "aeskey")[0])
    filepath = os.path.join(storage, sha1)
    with open(filepath, 'rb') as f:
        nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return Response(content=data, media_type=str(r.hget(f"file:{sha1}", "content_type")))


async def fetch(request):
    try:
        ip = request.client.host.encode('utf8')
        assert ip in r.smembers("ips_allowed"), f"ip {ip} not authorized"
        assert 'Authorization' in request.headers, "Authorization needed"
        auth_token = request.headers['Authorization'].replace('Bearer ','').encode('utf8')
        assert auth_token in r.smembers("runners"), f"runner {auth_token} not authorized"
        data = await request.json()
        print(data['images'])
        return JSONResponse({'status': 'todo'})
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
    print("%" * 80)
    config = json.load(open(config_file))
    print(config)
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
    Route("/get/{oid}/{sha1}", endpoint=get),  # to delete
    Route("/file/{sha1}", endpoint=file),  # to delete
    Route('/fetch', endpoint=fetch, methods=['GET', 'POST']),
])
