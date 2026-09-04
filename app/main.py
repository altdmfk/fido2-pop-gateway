from fastapi import FastAPI
from app.routes import auth, proxy
from app.middleware.pop_middleware import pop_middleware
from app.middleware.rate_limit_middleware import rate_limit_middleware
from starlette.middleware.base import BaseHTTPMiddleware

app = FastAPI(title="PoP Token Gateway")

# Register middlewares (executed bottom to top in Starlette)
app.add_middleware(BaseHTTPMiddleware, dispatch=pop_middleware)
app.add_middleware(BaseHTTPMiddleware, dispatch=rate_limit_middleware)

app.include_router(auth.router)
app.include_router(proxy.router)
