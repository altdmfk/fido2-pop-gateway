from fastapi import FastAPI, Header, Request
from typing import Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Mock Upstream Service")

@app.get("/api/v1/resource")
async def get_resource(
    request: Request,
    x_authenticated_user: Optional[str] = Header(None),
    x_authenticated_role: Optional[str] = Header(None)
):
    logger.info(f"Incoming Request - User: {x_authenticated_user}, Role: {x_authenticated_role}")
    return {
        "status": "success", 
        "data": "Protected internal business data",
        "user": x_authenticated_user,
        "role": x_authenticated_role
    }

@app.get("/api/v1/baseline-jwt")
async def get_baseline(request: Request):
    return {"status": "success", "data": "Baseline JWT passed"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
