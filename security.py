"""Security helpers shared by the web app and report exporters."""

from __future__ import annotations

import math
import re
import threading
import time
from collections import defaultdict, deque
from typing import Any, Callable
from urllib.request import Request, urlopen

import jwt


ALB_KID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
ALB_ARN_RE = re.compile(r"^arn:(?:aws|aws-us-gov|aws-cn):elasticloadbalancing:([a-z0-9-]+):\d{12}:loadbalancer/app/.+$")


class AuthenticationError(ValueError):
    """Raised when an upstream authentication assertion is invalid."""


class SlidingWindowLimiter:
    """Small in-process rate limiter used as defense in depth behind AWS WAF."""

    def __init__(self, max_keys: int = 10_000) -> None:
        self.max_keys = max_keys
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._checks = 0

    def check(self, key: str, limit: int, window_seconds: int) -> int:
        """Record an event and return retry-after seconds, or zero when allowed."""
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            self._checks += 1
            if self._checks % 100 == 0:
                self._prune(cutoff)
            if key not in self._events and len(self._events) >= self.max_keys:
                return window_seconds
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                return max(1, math.ceil(window_seconds - (now - events[0])))
            events.append(now)
            return 0

    def clear(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)

    def _prune(self, cutoff: float) -> None:
        expired: list[str] = []
        for key, events in self._events.items():
            while events and events[0] <= cutoff:
                events.popleft()
            if not events:
                expired.append(key)
        for key in expired:
            self._events.pop(key, None)


class AlbOidcVerifier:
    """Verify the ES256 user assertion supplied by an AWS Application Load Balancer."""

    def __init__(
        self,
        alb_arn: str,
        client_id: str,
        issuer: str = "",
        key_ttl_seconds: int = 3600,
        key_loader: Callable[[str, str], bytes] | None = None,
    ) -> None:
        arn_match = ALB_ARN_RE.fullmatch(alb_arn)
        if not arn_match:
            raise ValueError("ALB_ARN must be a valid Application Load Balancer ARN.")
        if not client_id:
            raise ValueError("ALB_CLIENT_ID is required.")
        self.alb_arn = alb_arn
        self.client_id = client_id
        self.issuer = issuer
        self.region = arn_match.group(1)
        self.key_ttl_seconds = key_ttl_seconds
        self.key_loader = key_loader or self._download_key
        self._keys: dict[str, tuple[bytes, float]] = {}
        self._lock = threading.Lock()

    def verify(self, token: str, asserted_identity: str) -> dict[str, Any]:
        if not token or len(token) > 32_768 or not asserted_identity:
            raise AuthenticationError("Missing or oversized ALB authentication assertion.")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthenticationError("Malformed ALB authentication assertion.") from exc

        if header.get("alg") != "ES256":
            raise AuthenticationError("Unexpected ALB assertion algorithm.")
        if header.get("signer") != self.alb_arn:
            raise AuthenticationError("Unexpected ALB assertion signer.")
        if header.get("client") != self.client_id:
            raise AuthenticationError("Unexpected ALB assertion client.")
        if self.issuer and header.get("iss") != self.issuer:
            raise AuthenticationError("Unexpected ALB assertion issuer.")
        try:
            expires_at = int(header["exp"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("ALB assertion has no valid expiry.") from exc
        if expires_at <= int(time.time()):
            raise AuthenticationError("ALB authentication assertion has expired.")

        kid = str(header.get("kid", ""))
        if not ALB_KID_RE.fullmatch(kid):
            raise AuthenticationError("ALB assertion has an invalid key identifier.")
        key = self._get_key(kid)
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["ES256"],
                options={"verify_aud": False, "verify_exp": False},
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError("ALB authentication signature is invalid.") from exc

        subject = str(claims.get("sub", ""))
        if not subject or subject != asserted_identity:
            raise AuthenticationError("ALB identity does not match the signed subject.")
        return claims

    def _get_key(self, kid: str) -> bytes:
        now = time.monotonic()
        with self._lock:
            cached = self._keys.get(kid)
            if cached and cached[1] > now:
                return cached[0]
        key = self.key_loader(self.region, kid)
        if not key or len(key) > 16_384:
            raise AuthenticationError("ALB public key response is invalid.")
        with self._lock:
            self._keys[kid] = (key, now + self.key_ttl_seconds)
        return key

    @staticmethod
    def _download_key(region: str, kid: str) -> bytes:
        request = Request(
            f"https://public-keys.auth.elb.{region}.amazonaws.com/{kid}",
            headers={"User-Agent": "checkmarx-sca-report-studio/1"},
        )
        try:
            # Region and key ID are allowlisted before this fixed HTTPS endpoint is built.
            with urlopen(request, timeout=3) as response:  # nosec B310
                return response.read(16_385)
        except OSError as exc:
            raise AuthenticationError("Could not retrieve the ALB public key.") from exc
