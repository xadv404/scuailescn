"""
SQL Audit Scanner – Application entry point
Run with:  python3 run.py
"""
import uvicorn
from config import HOST, PORT

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host=HOST,
        port=PORT,
        reload=False,
        log_level="info",
    )
