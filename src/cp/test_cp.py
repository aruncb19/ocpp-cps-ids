import asyncio
import websockets
import matlab.engine
import sys
import io

HOST = "0.0.0.0"
PORT = 56284
URI  = "ws://192.168.0.219:56284"

async def cleanup_simulation(eng, sim_future):
    """Stop Simulink, cancel background job, close model, quit MATLAB."""
    print("Stopping simulation…")
    try: eng.set_param("G2V", "SimulationCommand", "stop", nargout=0)
    except: pass
    if sim_future:
        try: sim_future.cancel()
        except: pass
    try:
        eng.close_system("G2V", nargout=0)
        eng.quit()
    except: pass

async def run_cp():
    # 1) Start MATLAB engine
    print("Starting MATLAB engine (desktop)…")
    eng = matlab.engine.start_matlab("-desktop")
    print("MATLAB engine ready.")

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    sim_future = None
    tx_id = None

    # 2) Connect (disable ping)
    async with websockets.connect(URI, ping_interval=None) as ws:
        print("Connected to CMS.")

        loop = asyncio.get_running_loop()

        while True:
            # Kick off two futures: one for ws.recv(), one for input()
            recv_task  = asyncio.create_task(ws.recv())
            input_future = loop.run_in_executor(None, input, "Enter 'start' or 'stop': ")

            done, pending = await asyncio.wait(
                [recv_task, input_future],
                return_when=asyncio.FIRST_COMPLETED
            )

            # If CMS sent something first:
            if recv_task in done:
                input_future.cancel()
                try:
                    msg = recv_task.result().strip()
                except websockets.exceptions.ConnectionClosed:
                    print("CMS closed the connection unexpectedly.")
                    break

                if msg == "STOP_ACK":
                    print("Received STOP_ACK from CMS!")
                    break
                else:
                    print(f"[from CMS] {msg}")
                    continue

            # Otherwise user typed first:
            else:
                # 1) cancel & await the recv task so the socket is free
                recv_task.cancel()
                try:
                    await recv_task
                except:
                    pass

                # 2) grab the user command
                cmd = input_future.result().strip().lower()

                if cmd == "start":
                    # send start and then single recv
                    await ws.send("start")
                    try:
                        resp = await ws.recv()
                        print("CMS responded:", resp)
                    except websockets.exceptions.ConnectionClosed:
                        print("CMS closed before START reply.")
                        break

                    if resp.startswith("START_ACCEPTED"):
                        _, tx_id = resp.split()
                        print(f"Session started (tx_id={tx_id}). Launching simulation…")

                        eng.eval("run('init_G2V.m')", nargout=0)
                        sim_future = eng.set_param(
                            "G2V", "SimulationCommand", "start",
                            nargout=0, background=True,
                            stdout=stdout_buf, stderr=stderr_buf
                        )
                    else:
                        print("Start rejected:", resp)

                elif cmd == "stop":
                    if not tx_id:
                        print("No active session; type 'start' first.")
                        continue

                    await ws.send(f"stop {tx_id}")
                    print("Sent STOP; waiting for CMS ack…")
                    # next loop pass will catch the STOP_ACK

                else:
                    print("Invalid command; use 'start' or 'stop'.")

        # loop exit → cleanup
    await cleanup_simulation(eng, sim_future)
    print("Session terminated. Exiting CP.")
    sys.exit(0)

if __name__ == "__main__":
    asyncio.run(run_cp())
