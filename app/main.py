from fastapi import FastAPI
from app.routes import auth, proxy
from app.middleware.pop_middleware import pop_middleware
from app.middleware.rate_limit_middleware import rate_limit_middleware
from starlette.middleware.base import BaseHTTPMiddleware
from contextlib import asynccontextmanager
import asyncio
import httpx
from app.core.nonce_store import nonce_store
from app.core.config import settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    # GC task for nonce store and rate limiter
    async def gc_task():
        import logging
        logger = logging.getLogger("gc_task")
        from app.core.rate_limiter import nonce_rate_limiter
        while True:
            await asyncio.sleep(30)
            try:
                nonce_store.cleanup()
                nonce_rate_limiter.cleanup()
            except Exception as e:
                logger.error(f"Error during GC cleanup: {e}")
    
    task = asyncio.create_task(gc_task())
    
    # Global HTTP client
    app.state.http_client = httpx.AsyncClient(
        base_url=settings.upstream_url,
        timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0),
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50)
    )
    
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    await app.state.http_client.aclose()

app = FastAPI(title="PoP Token Gateway", lifespan=lifespan)

# Register middlewares (executed bottom to top in Starlette)
app.add_middleware(BaseHTTPMiddleware, dispatch=pop_middleware)
app.add_middleware(BaseHTTPMiddleware, dispatch=rate_limit_middleware)

app.include_router(auth.router)
app.include_router(proxy.router)
