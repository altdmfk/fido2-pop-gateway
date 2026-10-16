from anyio import to_thread
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
import httpx
from starlette.background import BackgroundTask

from app.core.config import settings

router = APIRouter()


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str):
    url = httpx.URL(path=request.url.path, query=request.url.query.encode("utf-8"))

    # Zero-Trust Header Sanitization:
    # Explicitly drop client-supplied identity assertion headers to prevent header injection attacks
    headers = {
        k: v for k, v in request.headers.items()
        if not k.lower().startswith("x-authenticated-") and k.lower() not in ("x-forwarded-user", "host")
    }

    # Inject verified claims from PoP/JWT verification stage
    if hasattr(request.state, "user") and request.state.user:
        headers["X-Authenticated-User"] = request.state.user
        headers["X-Forwarded-User"] = request.state.user
    if hasattr(request.state, "role") and request.state.role:
        headers["X-Authenticated-Role"] = request.state.role

    spooled_body = getattr(request.state, "spooled_body", None)
    if spooled_body:
        async def file_stream():
            try:
                while True:
                    chunk = await to_thread.run_sync(spooled_body.read, 65536)
                    if not chunk:
                        break
                    yield chunk
            finally:
                if not spooled_body.closed:
                    await to_thread.run_sync(spooled_body.close)

        content = file_stream()
    else:
        content = request.stream()

    client: httpx.AsyncClient = getattr(request.app.state, "http_client", None)
    if client is None or client.is_closed:
        client = httpx.AsyncClient(
            base_url=settings.upstream_url,
            timeout=httpx.Timeout(
                connect=settings.upstream_connect_timeout,
                read=settings.upstream_read_timeout,
                write=settings.upstream_write_timeout,
                pool=settings.upstream_pool_timeout,
            ),
        )

    req = client.build_request(
        method=request.method,
        url=url,
        headers=headers,
        content=content,
    )

    try:
        response = await client.send(req, stream=True)
        return StreamingResponse(
            response.aiter_raw(),
            status_code=response.status_code,
            headers={
                k: v for k, v in response.headers.items()
                if k.lower() not in ("content-encoding", "content-length", "transfer-encoding", "connection")
            },
            background=BackgroundTask(response.aclose),
        )
    except httpx.TimeoutException as exc:
        if spooled_body and not spooled_body.closed:
            await to_thread.run_sync(spooled_body.close)
        raise HTTPException(status_code=504, detail=f"Upstream timeout: {exc}")
    except httpx.RequestError as exc:
        if spooled_body and not spooled_body.closed:
            await to_thread.run_sync(spooled_body.close)
        raise HTTPException(status_code=502, detail=f"Error forwarding request: {exc}")
