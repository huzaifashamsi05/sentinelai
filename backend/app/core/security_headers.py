"""
Security-headers middleware for the backend's own HTTP responses.

This exists specifically to give the Vulnerability Scanner module a real,
live "before vs after" demonstration using SentinelAI's own backend as
the (safe, localhost, always-authorized) scan target — exactly the
structure the handbook's assessment checklist asks for: show normal
operation, a controlled failure/finding, the applied control, then a
retest showing the improved result.

`HEADERS_ENABLED` starts True (secure by default). An Admin can flip it
off via POST /vuln-scanner/security-headers to reproduce the "before"
state live, then flip it back on and rescan to show the fix taking
effect — all against our own server, never a third-party site.
"""
from starlette.middleware.base import BaseHTTPMiddleware

HEADERS_ENABLED = True


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if HEADERS_ENABLED:
            response.headers["Content-Security-Policy"] = "default-src 'self'"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response
