from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.rate_limiter import nonce_rate_limiter


async def rate_limit_middleware(request: Request, call_next):
    if request.url.path == "/auth/nonce":
        # Extract client IP, prioritizing leftmost X-Forwarded-For when behind proxy
        client_ip = request.headers.get("X-Forwarded-For")
        if not client_ip:
            client_ip = request.client.host if request.client else "unknown"
        elif "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()

        if not nonce_rate_limiter.is_allowed(client_ip):
            retry_after = str(max(1, int(settings.rate_limit_window_seconds)))
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limit_exceeded", "message": "Too many nonce requests. Please retry later."},
                headers={"Retry-After": retry_after},
            )

    return await call_next(request)
