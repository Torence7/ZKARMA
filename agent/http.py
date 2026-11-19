"""Small JSON transport. Never retry purchases or follow credential redirects."""
from __future__ import annotations

import json
from http.client import HTTPException
import urllib.error
import urllib.request


class TransportError(Exception):
    """No usable response was received; a POST may already have executed."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class JsonHTTP:
    def __init__(self, timeout: float = 15):
        self.timeout = timeout
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, url, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json", **(headers or {})})
        try:
            try:
                response = self.opener.open(req, timeout=self.timeout)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise ValueError("Response too large")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise ValueError("Expected object")
                return response.code, result
        except (OSError, ValueError, HTTPException, urllib.error.URLError) as error:
            # Do not include request headers, response bodies, or secrets in errors.
            raise TransportError("HTTP request failed or returned invalid JSON") from error
