"""Abstract base class for all product APIs."""

from __future__ import annotations

import logging
from abc import ABC
from typing import Any, Dict, Optional

from ..config import SDKConfig
from ..exceptions import NetworkError, RateLimitError

logger = logging.getLogger("veriforge")


class BaseProductAPI(ABC):
    """Every product module inherits from this base.

    Provides common HTTP helpers, retry logic, and telemetry hooks.
    """

    PRODUCT_NAME: str = ""

    def __init__(self, config: SDKConfig) -> None:
        self._config = config
        self._logger = logger.getChild(self.PRODUCT_NAME or "product")

    def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Execute an HTTP request against the VeriForge platform.

        Args:
            method: HTTP verb (GET, POST, etc.).
            path: URL path fragment (appended to ``config.base_url``).
            json_data: Optional JSON payload.
            timeout: Per-call override for ``config.timeout``.

        Raises:
            NetworkError: On transport or 5xx errors.
            RateLimitError: On HTTP 429.

        Returns:
            Parsed JSON response body.
        """
        import time
        import urllib.error
        import urllib.request

        url = f"{self._config.base_url}/{self.PRODUCT_NAME}/{path.lstrip('/')}"
        data = None
        if json_data is not None:
            import json

            data = json.dumps(json_data).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers=self._config.headers(),
        )

        last_exc: Optional[Exception] = None
        retries = self._config.max_retries
        for attempt in range(1, retries + 1):
            try:
                self._logger.debug("%s %s (attempt %d/%d)", method, url, attempt, retries)
                resp = urllib.request.urlopen(req, timeout=timeout or self._config.timeout)
                body = resp.read().decode("utf-8")
                import json

                return json.loads(body) if body else {}
            except urllib.error.HTTPError as exc:
                if exc.code == 429:
                    retry_after = int(exc.headers.get("Retry-After", 2))
                    raise RateLimitError(
                        f"Rate limited on {url}",
                        retry_after=retry_after,
                        limit=None,
                    )
                if 500 <= exc.code < 600:
                    last_exc = exc
                    wait = 2 ** attempt
                    self._logger.warning("Server error %d, retrying in %.1fs", exc.code, wait)
                    time.sleep(wait)
                    continue
                raise NetworkError(
                    f"HTTP {exc.code}: {exc.reason}",
                    url=url,
                    status_code=exc.code,
                ) from exc
            except urllib.error.URLError as exc:
                last_exc = exc
                wait = 2 ** attempt
                self._logger.warning("Network error, retrying in %.1fs: %s", wait, exc.reason)
                time.sleep(wait)
                continue

        raise NetworkError(
            f"Request failed after {retries} attempts",
            url=url,
            status_code=None,
        ) from last_exc

    @property
    def config(self) -> SDKConfig:
        """Read-only access to the current configuration."""
        return self._config
