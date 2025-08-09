'''
"The program establishes a websocket connection with the Fronius Wattpilot wallbox over the local network, 
performs authentication, and starts communication (receiving websocket events).
Developed thanks to joscha82 / wattpilot"
'''
import asyncio
import websockets
import json
import hashlib
import base64
import random

WATTBOX_IP = "192.168.1.100"       # Replace with your Wattpilot IP address
WATTPILOT_PASSWORD = "yourpassword"  # Replace with your password
WATTPILOT_SERIAL = None             # Will be set from hello message


def generate_token3():
    ran = random.randrange(10**80)
    return f"{ran:064x}"[:32]


async def authenticate(ws):
    global WATTPILOT_SERIAL
    hashedpassword = None

    while True:
        raw_msg = await ws.recv()
        msg = json.loads(raw_msg)
        msg_type = msg.get("type")

        if msg_type == "hello":
            # Extract serial number and derive hashed password
            WATTPILOT_SERIAL = msg.get("serial")
            print(f"Received hello. Serial: {WATTPILOT_SERIAL}")

            derived = hashlib.pbkdf2_hmac(
                'sha512',
                WATTPILOT_PASSWORD.encode('utf-8'),
                WATTPILOT_SERIAL.encode('utf-8'),
                100_000,
                256
            )
            hashedpassword = base64.b64encode(derived)[:32]  # bytes
            print(f"Derived hashedpassword (len {len(hashedpassword)} bytes)")

        elif msg_type == "authRequired":
            token1 = msg["token1"]
            token2 = msg["token2"]
            print(f"Auth required with token1={token1} and token2={token2}")

            if hashedpassword is None:
                print("Hashed password not derived yet!")
                return False

            # Compute hash1 = SHA256(token1 + hashedpassword_bytes)
            hash1 = hashlib.sha256(token1.encode('utf-8') + hashedpassword).hexdigest()

            token3 = generate_token3()
            print(f"Generated token3: {token3}")

            # Compute final hash = SHA256(token3 + token2 + hash1) as string concat UTF-8
            final_hash = hashlib.sha256((token3 + token2 + hash1).encode('utf-8')).hexdigest()
            print(f"Computed final hash: {final_hash}")

            auth_msg = {
                "type": "auth",
                "token3": token3,
                "hash": final_hash
            }

            # Send auth message as plain JSON (no securedMsg wrapper!)
            auth_json = json.dumps(auth_msg)
            print(f"Sending auth message: {auth_json}")
            await ws.send(auth_json)

        elif msg_type == "authSuccess":
            print("Authentication succeeded!")
            return True

        elif msg_type == "authError":
            print(f"Authentication failed: {msg.get('message', 'unknown error')}")
            return False

        else:
            print(f"Message during auth: {msg}")


async def main():
    uri = f"ws://{WATTBOX_IP}/ws"
    print(f"Connecting to {uri} ...")

    async with websockets.connect(uri) as ws:
        if not await authenticate(ws):
            print("Authentication failed, exiting")
            return

        print("Authenticated, you can now send secured messages")


        try:
            while True:
                msg = await ws.recv()
                print('> MESSAGE RECEIVED >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>')
                print(msg)
                # Here you can add messages parsing.

        except websockets.ConnectionClosed:
            print("Connection closed")


if __name__ == "__main__":
    asyncio.run(main())
