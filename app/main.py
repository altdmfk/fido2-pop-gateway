import asyncio
from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
import httpx
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.nonce_store import nonce_store
from app.core.rate_limiter import nonce_rate_limiter
from app.middleware.pop_middleware import pop_middleware
from app.middleware.rate_limit_middleware import rate_limit_middleware
from app.routes import auth, proxy

logger = logging.getLogger("gateway.lifecycle")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Background GC task for in-memory nonce store and sliding window rate limiter
    async def gc_task():
        while True:
            await asyncio.sleep(settings.nonce_cleanup_interval_seconds)
            try:
                purged_nonces = nonce_store.cleanup()
                purged_ips = nonce_rate_limiter.cleanup()
                if purged_nonces or purged_ips:
                    logger.debug(f"GC cycle completed: {purged_nonces} nonces, {purged_ips} IPs pruned")
            except Exception as exc:
                logger.error(f"Error during in-memory state GC cleanup: {exc}")

    gc_worker = asyncio.create_task(gc_task())

    # Shared connection-pooled HTTP client for upstream reverse proxy
    app.state.http_client = httpx.AsyncClient(
        base_url=settings.upstream_url,
        timeout=httpx.Timeout(
            connect=settings.upstream_connect_timeout,
            read=settings.upstream_read_timeout,
            write=settings.upstream_write_timeout,
            pool=settings.upstream_pool_timeout,
        ),
        limits=httpx.Limits(
            max_connections=settings.upstream_max_connections,
            max_keepalive_connections=settings.upstream_max_keepalive_connections,
        ),
    )

    yield

    # Graceful shutdown: cancel GC worker and drain HTTP client pool
    gc_worker.cancel()
    try:
        await gc_worker
    except asyncio.CancelledError:
        pass

    await app.state.http_client.aclose()


app = FastAPI(title="PoP Token Gateway", lifespan=lifespan)

# Register middlewares (Starlette executes in reverse registration order: RateLimit -> PoP)
app.add_middleware(BaseHTTPMiddleware, dispatch=pop_middleware)
app.add_middleware(BaseHTTPMiddleware, dispatch=rate_limit_middleware)

app.include_router(auth.router)
app.include_router(proxy.router)
