import asyncio
import websockets

# Port and host
HOST = "localhost"
PORT = 9000

# Handler for incoming client (CP) messages
async def handler(websocket, path):
    print("Charging Point connected.")

    async for message in websocket:
        print(f"Received from CP: {message}")

        # Optional: process message logic here
        response = "Acknowledged. CMS received your status."
        await websocket.send(response)

# Start the WebSocket server
async def main():
    print(f"CMS listening on ws://{HOST}:{PORT}")
    async with websockets.serve(handler, HOST, PORT):
        await asyncio.Future()  # run forever

# Run the server
if __name__ == "__main__":
    asyncio.run(main())
