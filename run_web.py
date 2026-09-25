"""Start the web interface:  python run_web.py

Run as a script, sys.path[0] is the project root, so `app.api` resolves to the package in
this repository rather than to anything else of that name. The port is 8090 rather than
8000 because 8000 is the first port anything else on the machine takes.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn

PORT = int(os.environ.get("PORT", "8090"))
# 0.0.0.0 for a hosted deployment, and it works locally too; reach it on localhost.
HOST = os.environ.get("HOST", "0.0.0.0")

if __name__ == "__main__":
    print(f"web interface:  http://localhost:{PORT}")
    uvicorn.run("app.api:app", host=HOST, port=PORT)
