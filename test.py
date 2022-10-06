import sys
import requests
import asyncio
import websockets

HASH = "6c6e2b0cfda80007e693d52b5956083ea68770e1310d0ed02d195cb14113b284"
if sys.argv[1] == "setup":
    r = requests.post(f'http://localhost:3000/api/user?name=quantum&email=test@example.com&hash={HASH}')
    quantum = r.json()["id"]
    r = requests.post(f'http://localhost:3000/api/login?id={quantum}', data=HASH, headers={"Content-Type": "text/plain"})
    tok = r.text
    
    r = requests.post(f'http://localhost:3000/api/user?name=jemoka&email=test@example.com&hash={HASH}')
    jemoka = r.json()["id"]
    r = requests.post(f'http://localhost:3000/api/user?name=exr0n&email=test@example.com&hash={HASH}')
    exr0n = r.json()["id"]
    r = requests.post(f'http://localhost:3000/api/user?name=enquirer&email=test@example.com&hash={HASH}')
    enquirer = r.json()["id"]
    r = requests.post(f'http://localhost:3000/api/user?name=zbuster&email=test@example.com&hash={HASH}')
    zbuster = r.json()["id"]

    print({"quantum": quantum, "exr0n": exr0n, "jemoka": jemoka, "enquirer": enquirer, "zbuster": zbuster})            
    
    r = requests.post(f'http://localhost:3000/api/group?name=testing', headers={"ScuttleKey": tok})
    print(r.text)
    testing = r.json()["id"]

    r = requests.put(f'http://localhost:3000/api/group/members?gid={testing}&uid={zbuster}', headers={"ScuttleKey": tok})
    r = requests.put(f'http://localhost:3000/api/group/members?gid={testing}&uid={exr0n}', headers={"ScuttleKey": tok})
    r = requests.put(f'http://localhost:3000/api/group/members?gid={testing}&uid={jemoka}', headers={"ScuttleKey": tok})
    r = requests.get(f'http://localhost:3000/api/group?id={testing}', headers={"ScuttleKey": tok})
    
    r = requests.post(f'http://localhost:3000/api/group?name=whoo', headers={"ScuttleKey": tok})
    whoo = r.json()["id"]
    r = requests.put(f'http://localhost:3000/api/group/members?gid={whoo}&uid={zbuster}', headers={"ScuttleKey": tok})
    r = requests.put(f'http://localhost:3000/api/group/members?gid={whoo}&uid={enquirer}', headers={"ScuttleKey": tok})

    r = requests.post(f'http://localhost:3000/api/group?name=whee', headers={"ScuttleKey": tok})
    whee = r.json()["id"]
    r = requests.put(f'http://localhost:3000/api/group/members?gid={whee}&uid={enquirer}', headers={"ScuttleKey": tok})
    r = requests.put(f'http://localhost:3000/api/group/members?gid={whee}&uid={jemoka}', headers={"ScuttleKey": tok})

    exit(0)


async def main():
    ids = {'quantum': 420625705584431104, 'exr0n': 420625705622179840, 'jemoka': 420625705609596928, 'enquirer': 420625705634762752, 'zbuster': 420625705643151360}
    name = sys.argv[1]
    my_id = ids[name]
    r = requests.post(f'http://localhost:3000/api/login?id={my_id}', data=HASH, headers={"Content-Type": "text/plain"})
    tok = r.text
    
    while True:
        cmd = input("$ ").split(" ")
        if cmd[0] == "groups":        
            r = requests.get(f'http://localhost:3000/api/user/groups', headers={"ScuttleKey": tok})
            print(r.text, my_id)
            for g in r.json():
                print(f"{g['name']} ({g['id']})")
        elif cmd[0] == "group":
            r = requests.get(f'http://localhost:3000/api/group/channels?gid={cmd[1]}', headers={"ScuttleKey": tok})
            for c in r.json():
                print(f"{c['name']} ({c['id']})")
        elif cmd[0] == "channel":
            async with websockets.connect("ws://localhost:3001/ws/whee") as websocket:
                await websocket.send(f'{{"hash": "{HASH}", "id": {my_id}}}')
                await websocket.send(f'{{"content": "{name} says whee", "channel": {cmd[1]}}}')
                while True:
                    print(await websocket.recv())

loop = asyncio.get_event_loop()
loop.run_until_complete(main())




    

    
