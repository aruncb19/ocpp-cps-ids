import asyncio
import websockets
import matlab.engine

async def run_client():
    uri = "ws://localhost:9000"  # Replace with your CMS server URI if needed
    async with websockets.connect(uri) as websocket:
        print("Connected to CMS via WebSocket.")

        # Start MATLAB engine
        print("Starting MATLAB...")
        eng = matlab.engine.start_matlab('-desktop')  # or '-nojvm -nodisplay' for headless
        print("MATLAB started.")

        # Run the simulation using your actual script
        print("Running Simulink model: G2V.slx via main_v2gg2v.m")
        eng.eval("main_v2gg2v", nargout=0)

        # Optionally: Stop and close the Simulink model
        eng.set_param('G2V', 'SimulationCommand', 'stop', nargout=0)
        eng.close_system('G2V', nargout=0)
        eng.quit()
        print("MATLAB engine shut down.")

        # Simulate sending OCPP messages to CMS (optional)
        await websocket.send("Simulation complete from CP.")
        response = await websocket.recv()
        print("CMS says:", response)

asyncio.run(run_client())