from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
import httpx
import json

from app.deps import get_templates

router = APIRouter(tags=["Targets (viewer)"])

class ProxyRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None

@router.get("/{scope}/viewer", response_class=HTMLResponse)
async def viewer_page(request: Request, scope: str, url: str = ""):
    templates = get_templates(request)
    ctx = {
        "request": request,
        "scope": scope,
        "initial_url": url,
    }
    return templates.TemplateResponse("targets/viewer_combo.html", ctx)

@router.post("/{scope}/viewer/proxy")
async def viewer_proxy(scope: str, proxy_req: ProxyRequest):
    method = proxy_req.method.upper()
    headers = proxy_req.headers or {}
    
    # Optional: we can strip some restricted headers if needed, but for pentesting it's better to send exactly what they ask for.
    
    try:
        # We disable following redirects so the user can inspect the 301/302 response directly.
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=15.0) as client:
            kwargs: Dict[str, Any] = {
                "method": method,
                "url": proxy_req.url,
                "headers": headers,
            }
            if proxy_req.body and method in ("POST", "PUT", "PATCH", "DELETE"):
                kwargs["content"] = proxy_req.body.encode("utf-8")
                
            response = await client.request(**kwargs)
            
            # Prepare response data
            res_headers = dict(response.headers)
            try:
                body_text = response.text
            except Exception:
                # Fallback for binary data
                body_text = repr(response.content)
                
            return JSONResponse({
                "status_code": response.status_code,
                "headers": res_headers,
                "body": body_text,
                "elapsed": response.elapsed.total_seconds()
            })
    except httpx.RequestError as exc:
        return JSONResponse(
            status_code=502,
            content={"error": f"Request failed: {str(exc)}"}
        )
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"error": f"Internal error: {str(exc)}"}
        )

@router.get("/{scope}/viewer/proxy_render")
async def proxy_render(scope: str, url: str):
    if not url.startswith("http"):
        return HTMLResponse("Invalid URL", status_code=400)
    
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:
            response = await client.get(url)
            
            # Get the body text
            try:
                body_text = response.text
            except Exception:
                body_text = response.content.decode('utf-8', errors='replace')
                
            # Inject base tag to fix relative links
            from urllib.parse import urlparse
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}/"
            
            # Simple insertion of base tag right after <head> if it exists, else just prepend
            if "<head" in body_text.lower():
                import re
                body_text = re.sub(r'(<head[^>]*>)', fr'\1\n<base href="{base_url}">', body_text, flags=re.IGNORECASE, count=1)
            else:
                body_text = f'<base href="{base_url}">\n' + body_text
                
            # Return as HTML, but DO NOT include X-Frame-Options or CSP headers
            headers = dict(response.headers)
            # Remove restrictive headers
            for h in ["x-frame-options", "content-security-policy", "content-security-policy-report-only", "strict-transport-security"]:
                if h in headers:
                    del headers[h]
            # Remove transfer-encoding to avoid chunked errors
            if "transfer-encoding" in headers:
                del headers["transfer-encoding"]
            if "content-encoding" in headers:
                del headers["content-encoding"] # Let FastAPI handle encoding
            if "content-length" in headers:
                del headers["content-length"]
                
            # Copy content type
            content_type = headers.get("content-type", "text/html")
            
            return HTMLResponse(content=body_text, status_code=response.status_code, headers=headers)
            
    except Exception as exc:
        return HTMLResponse(f"Proxy Render Error: {str(exc)}", status_code=502)
