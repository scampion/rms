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
    form = await request.form()
    assert form['email'].split('@')[1] in email_domains, "You email domain is not allowed"
    oid = uuid.uuid1()
    session_key = get_random_bytes(16)
    for f in form.getlist("files"):
        contents = await f.read()
        sha1 = hashlib.sha1(contents).hexdigest()
        filepath = os.path.join(storage, sha1)
        await write_enc_file(contents, filepath, session_key)
        r.hset(f"file:{sha1}", "filename", f.filename)
        r.hset(f"file:{sha1}", "content_type", f.content_type)
        r.lpush(f"files:{oid}", sha1)
        r.expire(f"files:{oid}", ttl)
    r.hmset(f"params:{oid}", {"task": form["task"]})
    r.hmset(f"params:{oid}", {"aeskey": base64.b64encode(session_key)})
    r.hmset(f"params:{oid}", {"time": time.time()})
    r.lpush("tobeconfirmed", str(oid))
    r.publish('todo', str(oid))
    return JSONResponse({'status': 'registered',
                         'oid': str(oid),
                         "files": list(ls_sha1),
                         "getlinks": [f"http://localhost:8000/get/{oid}/" + s for s in ls_sha1]
                         })


async def write_enc_file(contents, filepath, session_key):
    with open(filepath, 'wb') as outfile:
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(contents)
        outfile.write(cipher_aes.nonce)
        outfile.write(tag)
        outfile.write(ciphertext)


async def status(request):
    oid = request.path_params.get('oid','')
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
        return Response(content=open(filepath,'rb').read(), media_type=str(r.hget(f"file:{sha1}", "content_type")))

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


async def job(request):
    if request.client.host.encode('utf8') not in r.smembers("allowed_ips"):
        return JSONResponse({"error": "ip not authorized"}, status_code=403)
    else:
        return JSONResponse({'IP': request.client.host})
    runner = request.path_params['runner_name']
    images = request.path_params['images']
    gpus = request.path_params['gpus_in_gb']


########################################################################################################################

print("Start server ...")
r = redis.Redis()
storage = "/tmp"
ttl = 60 * 60 * 24
email_domains = []

# Overwrite config params if needed
config_file = os.environ.get("RMS_CONFIG_FILE", None)
if config_file:
    config = json.load(open(config_file))
    r = redis.Redis.from_url(config['redis_url']) if 'redis_url' in config.keys() else r
    ttl = config.get('ttl', ttl)
    email_domains = config.get('email_domains', email_domains)
    storage = config.get('storage', storage)

app = Starlette(debug=True, routes=[
    Route('/', endpoint=homepage),
    Route('/uploadfiles', endpoint=uploadfiles, methods=['POST']),
    Route("/status/{oid}", endpoint=status),
    Route("/get/{oid}/{sha1}", endpoint=get), #to delete
    Route("/file/{sha1}", endpoint=file),  # to delete
    Route('/job', endpoint=job, methods=['GET', 'POST']),
])
