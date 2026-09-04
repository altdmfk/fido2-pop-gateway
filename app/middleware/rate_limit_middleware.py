from fastapi import Request
from fastapi.responses import JSONResponse
from app.core.rate_limiter import nonce_rate_limiter

async def rate_limit_middleware(request: Request, call_next):
    if request.url.path == "/auth/nonce":
        client_ip = request.headers.get("X-Forwarded-For")
        if not client_ip:
            client_ip = request.client.host if request.client else "unknown"
            
        if client_ip and "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()
            
        if not nonce_rate_limiter.is_allowed(client_ip):
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limit_exceeded", "message": "Too many nonce requests. Please retry later."},
                headers={"Retry-After": "1"}
            )
            
    return await call_next(request)
