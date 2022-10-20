import json
import sys
import requests
import asyncio
import websockets

async def main():
    #############
    # INIT CODE #
    #############
    
    # same hash for everyone for succintness
    HASH = "6c6e2b0cfda80007e693d52b5956083ea68770e1310d0ed02d195cb14113b284"
    
    # login as quantum for init step
    r = requests.post(f'http://localhost:3000/api/user?name=quantum&email=test@example.com', data=HASH, headers={"Content-Type": "text/plain"})
    quantum = r.json()["id"]
    r = requests.post(f'http://localhost:3000/api/login?id={quantum}', data=HASH, headers={"Content-Type": "text/plain"})
    tok = r.text

    # init other users
    r = requests.post(f'http://localhost:3000/api/user?name=jemoka&email=test@example.com', data=HASH, headers={"Content-Type": "text/plain"})
    jemoka = r.json()["id"]
    r = requests.post(f'http://localhost:3000/api/user?name=exr0n&email=test@example.com',data=HASH, headers={"Content-Type": "text/plain"})
    exr0n = r.json()["id"]
    r = requests.post(f'http://localhost:3000/api/user?name=enquirer&email=test@example.com', data=HASH, headers={"Content-Type": "text/plain"})
    enquirer = r.json()["id"]
    r = requests.post(f'http://localhost:3000/api/user?name=zbuster&email=test@example.com', data=HASH, headers={"Content-Type": "text/plain"})
    zbuster = r.json()["id"]
    
    # create group with multiple members
    r = requests.post(f'http://localhost:3000/api/group?name=testing', headers={"Authorization": tok})
    testing = r.json()["id"]
    r = requests.put(f'http://localhost:3000/api/group/members?gid={testing}&uid={zbuster}', headers={"Authorization": tok})
    r = requests.put(f'http://localhost:3000/api/group/members?gid={testing}&uid={exr0n}', headers={"Authorization": tok})
    r = requests.put(f'http://localhost:3000/api/group/members?gid={testing}&uid={jemoka}', headers={"Authorization": tok})
    
    # create another two groups
    r = requests.post(f'http://localhost:3000/api/group?name=whoo', headers={"Authorization": tok})
    whoo = r.json()["id"]
    r = requests.put(f'http://localhost:3000/api/group/members?gid={whoo}&uid={zbuster}', headers={"Authorization": tok})
    r = requests.put(f'http://localhost:3000/api/group/members?gid={whoo}&uid={enquirer}', headers={"Authorization": tok})

    r = requests.post(f'http://localhost:3000/api/group?name=whee', headers={"Authorization": tok})
    whee = r.json()["id"]
    r = requests.put(f'http://localhost:3000/api/group/members?gid={whee}&uid={enquirer}', headers={"Authorization": tok})
    r = requests.put(f'http://localhost:3000/api/group/members?gid={whee}&uid={jemoka}', headers={"Authorization": tok})
    
    ##############################
    # INTEGRATION TEST 1: GROUPS #
    ##############################

    # log two users in
    r = requests.post(f'http://localhost:3000/api/login?id={zbuster}', data=HASH, headers={"Content-Type": "text/plain"})
    z_tok = r.text
    r = requests.post(f'http://localhost:3000/api/login?id={jemoka}', data=HASH, headers={"Content-Type": "text/plain"})
    j_tok = r.text
    
    # init websockets for both
    z_sock = await websockets.connect("ws://localhost:3001/")
    await z_sock.send(f'{{"hash": "{HASH}", "id": {zbuster}}}')
    j_sock = await websockets.connect("ws://localhost:3001/")
    await j_sock.send(f'{{"hash": "{HASH}", "id": {jemoka}}}')    
    
    # check zbuster's groups
    r = requests.get(f'http://localhost:3000/api/user/groups', headers={"Authorization": z_tok})
    assert(len(r.json()) == 2)
    group_ids = list(map(lambda x: x["id"], r.json()))
    assert(testing in group_ids)
    assert(whoo in group_ids)

    # check jemoka's groups
    r = requests.get(f'http://localhost:3000/api/user/groups', headers={"Authorization": j_tok})
    assert(len(r.json()) == 2)
    group_ids = list(map(lambda x: x["id"], r.json()))
    assert(testing in group_ids)
    assert(whee in group_ids)
    
    # get + check main channel of testing
    r = requests.get(f'http://localhost:3000/api/group?id={testing}', headers={"Authorization": z_tok})
    testing_main = r.json()["channels"][0]    
    assert(r.json()["name"] == "testing")
    assert(r.json()["is_dm"] == False)
    assert(jemoka in r.json()["members"])
    assert(quantum in r.json()["members"])
    assert(exr0n in r.json()["members"])
    assert(zbuster in r.json()["members"])

    # test basic messaging
    await j_sock.send(f'{{"content": "chickens", "channel": {testing_main}}}')
    z_msg = json.loads(await z_sock.recv())
    assert(z_msg["author"] == jemoka)
    assert(z_msg["content"] == "chickens")
    assert(z_msg["channel"] == testing_main)

    await z_sock.send(f'{{"content": "what?", "channel": {testing_main}}}')
    j_msg = json.loads(await z_sock.recv())
    assert(j_msg["author"] == zbuster)
    assert(j_msg["content"] == "what?")
    assert(j_msg["channel"] == testing_main)

    # log another user in 
    r = requests.post(f'http://localhost:3000/api/login?id={enquirer}', data=HASH, headers={"Content-Type": "text/plain"})
    h_tok = r.text
    
    # attempt invalid action
    r = requests.delete(f'http://localhost:3000/api/group?id={testing}', headers={"Authorization": h_tok})
    assert(r.status_code == 401)
    print("Test 1 done!")
    
    ##########################
    # INTEGRATION TEST 2: DM #
    ##########################

    # log yet another user in
    r = requests.post(f'http://localhost:3000/api/login?id={exr0n}', data=HASH, headers={"Content-Type": "text/plain"})
    e_tok = r.text
    
    # init websockets for both exr0n and enquirer
    e_sock = await websockets.connect("ws://localhost:3001/")
    await e_sock.send(f'{{"hash": "{HASH}", "id": {exr0n}}}')
    h_sock = await websockets.connect("ws://localhost:3001/")
    await h_sock.send(f'{{"hash": "{HASH}", "id": {enquirer}}}')    
    
    # create dm
    r = requests.post(f'http://localhost:3000/api/dm?uid={exr0n}', headers={"Authorization": h_tok})
    dm = r.json()["id"]
    assert(r.json()["name"] == "")
    assert(r.json()["is_dm"] == True)
    assert(exr0n in r.json()["members"])
    assert(enquirer in r.json()["members"])
    assert(len(r.json()["admin"]) == 0)
    assert(r.json()["owner"] == enquirer)
    assert(len(r.json()["channels"]) == 1)
    dm_main = r.json()["channels"][0]
    
    # check that exr0n can see it
    r = requests.get(f'http://localhost:3000/api/user/dms', headers={"Authorization": e_tok})
    assert(len(r.json()) == 1)
    assert(dm == r.json()[0]["id"])

    # and enquirer for that matter
    r = requests.get(f'http://localhost:3000/api/user/dms', headers={"Authorization": h_tok})
    assert(len(r.json()) == 1)
    assert(dm == r.json()[0]["id"])
    # test basic messaging
    await h_sock.send(f'{{"content": "videogames?", "channel": {dm_main}}}')
    e_msg = json.loads(await e_sock.recv())
    assert(e_msg["author"] == enquirer)
    assert(e_msg["content"] == "videogames?")
    assert(e_msg["channel"] == dm_main)
    print("Test 2 done!")



loop = asyncio.get_event_loop()
loop.run_until_complete(asyncio.wait_for(main(), 5))    
# asyncio.run(main(), timeout=5)

