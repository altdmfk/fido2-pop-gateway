from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse
import httpx
from app.core.config import settings

router = APIRouter()
client = httpx.AsyncClient(base_url=settings.upstream_url)

@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str):
    url = httpx.URL(path=request.url.path, query=request.url.query.encode("utf-8"))
    
    headers = dict(request.headers)
    headers.pop("host", None)
    
    if hasattr(request.state, "user") and request.state.user:
        headers["X-Authenticated-User"] = request.state.user
    if hasattr(request.state, "role") and request.state.role:
        headers["X-Authenticated-Role"] = request.state.role

    req = client.build_request(
        method=request.method,
        url=url,
        headers=headers,
        content=request.stream()
    )

    try:
        response = await client.send(req, stream=True)
        return StreamingResponse(
            response.aiter_raw(),
            status_code=response.status_code,
            headers={k: v for k, v in response.headers.items() if k.lower() not in ("content-encoding", "content-length", "transfer-encoding", "connection")}
        )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Error forwarding request: {str(exc)}")
