"""Local-only entry point. No proxy-header trust or debug/reload server."""

import os
from dotenv import load_dotenv
import uvicorn
from app import create_app

if __name__ == "__main__":
    load_dotenv()
    app = create_app(
        os.getenv("APP_DB", "local-data/auth.sqlite3"),
        os.getenv("APP_ORIGIN", "http://127.0.0.1:8000"),
        os.getenv("COOKIE_SECURE", "false").lower() == "true",
    )
    uvicorn.run(app, host="127.0.0.1", port=8000, proxy_headers=False)
