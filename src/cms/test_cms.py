import asyncio
import random
import websockets

HOST = "0.0.0.0"
PORT = 56284

# Map transactionId -> websocket that started it
active_sessions = {}

async def handler(websocket):
    print("New CP connected:", websocket.remote_address)

    try:
        async for raw in websocket:
            parts = raw.strip().lower().split()
            action = parts[0]
            print(f"Received command: {raw}")

            # START: assign tx_id, send back START_ACCEPTED, KEEP the connection open
            if action == "start":
                tx_id = random.randint(1000, 9999)
                active_sessions[tx_id] = websocket
                print(f"Starting session, transactionId = {tx_id}")
                await websocket.send(f"START_ACCEPTED {tx_id}")

            # STOP: find the owner socket and close it
            elif action == "stop":
                if len(parts) == 2 and parts[1].isdigit():
                    tx = int(parts[1])
                    owner_ws = active_sessions.get(tx)
                    if owner_ws:
                        print(f"Stop for tx_id={tx}. Closing that session.")
                        await owner_ws.send("STOP_ACK")
                        await owner_ws.close()
                        del active_sessions[tx]

                        # If this stop came from another (rogue) ws, ack & close it too
                        if websocket is not owner_ws:
                            await websocket.send("STOP_ACK")
                            await websocket.close()
                        break

                invalid = parts[1] if len(parts) > 1 else None
                print(f"Stop with invalid ID {invalid}. Ignoring.")
                await websocket.send("INVALID_TX_ID")

            else:
                await websocket.send("UNKNOWN_COMMAND")

    except websockets.exceptions.ConnectionClosed:
        print("Connection closed.")

async def main():
    print(f"CMS listening on ws://{HOST}")
    async with websockets.serve(handler, HOST, PORT, ping_interval=None):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
