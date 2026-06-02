"""Web arayuzunu baslatir:  python run_web.py

Script olarak calistiginda sys.path[0]=proje koku -> 'app.api' DOGRU pakete cozulur.
Port 8090 (8000 AlimGPT, 8077 ml-books-rag'da olabilir).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn

PORT = int(os.environ.get("PORT", "8090"))
# Render/hosted: 0.0.0.0; yerelde de calisir. Yerel erisim icin localhost kullan.
HOST = os.environ.get("HOST", "0.0.0.0")

if __name__ == "__main__":
    print(f"Web arayuzu:  http://localhost:{PORT}")
    uvicorn.run("app.api:app", host=HOST, port=PORT)
