"""Security helpers shared by the web app and report exporters."""

from __future__ import annotations

import math
import re
import threading
import time
from collections import OrderedDict, deque
from typing import Any, Callable
from urllib.request import Request, urlopen

import jwt


ALB_KID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
ALB_ARN_RE = re.compile(r"^arn:(?:aws|aws-us-gov|aws-cn):elasticloadbalancing:([a-z0-9-]+):\d{12}:loadbalancer/app/.+$")
KEY_FETCH_TIMEOUT_SECONDS = 3


class AuthenticationError(ValueError):
    """Raised when an upstream authentication assertion is invalid."""


class SlidingWindowLimiter:
    """Small in-process rate limiter used as defense in depth behind AWS WAF.

    Keys are attacker-controlled -- the login limiter keys on a submitted
    username -- so reaching ``max_keys`` evicts the least recently used entry
    instead of refusing the new key. Refusing would let a flood of unknown keys
    deny service to every legitimate caller, which is a worse failure than
    briefly weakening the limit for the flooded namespace. AWS WAF, not this
    class, is the control that is expected to absorb such a flood.
    """

    def __init__(self, max_keys: int = 10_000) -> None:
        if max_keys < 1:
            raise ValueError("max_keys must be at least 1.")
        self.max_keys = max_keys
        self._events: OrderedDict[str, deque[float]] = OrderedDict()
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
            events = self._events.get(key)
            if events is None:
                while self._events and len(self._events) >= self.max_keys:
                    self._events.popitem(last=False)
                events = self._events[key] = deque()
            self._events.move_to_end(key)
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
        max_cached_keys: int = 32,
        negative_ttl_seconds: int = 60,
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
        self.max_cached_keys = max_cached_keys
        self.negative_ttl_seconds = negative_ttl_seconds
        self.key_loader = key_loader or self._download_key
        self._keys: OrderedDict[str, tuple[bytes, float]] = OrderedDict()
        self._failures: OrderedDict[str, float] = OrderedDict()
        self._inflight: dict[str, threading.Event] = {}
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

    def _expire(self, now: float) -> None:
        """Drop timed-out cache and negative-cache entries. Caller holds the lock."""
        for kid in [k for k, (_, expires_at) in self._keys.items() if expires_at <= now]:
            self._keys.pop(kid, None)
        for kid in [k for k, expires_at in self._failures.items() if expires_at <= now]:
            self._failures.pop(kid, None)

    def _get_key(self, kid: str) -> bytes:
        """Resolve an ALB signing key, fetching it at most once per key ID.

        The kid is attacker-controlled and this runs *before* the signature is
        verified, so three things are bounded here: concurrent requests for the
        same kid share a single fetch, a kid that fails to resolve is negatively
        cached so it cannot be replayed into a fetch storm, and the cache evicts
        its oldest entry rather than refusing new keys -- refusing would let a
        caller pin the cache full and break genuine ALB key rotation.
        """
        while True:
            with self._lock:
                self._expire(time.monotonic())
                cached = self._keys.get(kid)
                if cached:
                    self._keys.move_to_end(kid)
                    return cached[0]
                if kid in self._failures:
                    raise AuthenticationError("ALB public key is not available.")
                waiter = self._inflight.get(kid)
                if waiter is None:
                    waiter = self._inflight[kid] = threading.Event()
                    break
            # Another thread is already fetching this kid. Wait for it to finish
            # and re-read the cache instead of issuing a duplicate request.
            if not waiter.wait(timeout=KEY_FETCH_TIMEOUT_SECONDS + 1):
                raise AuthenticationError("Timed out waiting for the ALB public key.")

        try:
            key = self.key_loader(self.region, kid)
            if not key or len(key) > 16_384:
                raise AuthenticationError("ALB public key response is invalid.")
        except Exception:
            with self._lock:
                self._failures[kid] = time.monotonic() + self.negative_ttl_seconds
                while len(self._failures) > self.max_cached_keys:
                    self._failures.popitem(last=False)
                self._inflight.pop(kid, None)
            waiter.set()
            raise

        with self._lock:
            self._keys[kid] = (key, time.monotonic() + self.key_ttl_seconds)
            self._keys.move_to_end(kid)
            while len(self._keys) > self.max_cached_keys:
                self._keys.popitem(last=False)
            self._inflight.pop(kid, None)
        waiter.set()
        return key

    @staticmethod
    def _download_key(region: str, kid: str) -> bytes:
        request = Request(
            f"https://public-keys.auth.elb.{region}.amazonaws.com/{kid}",
            headers={"User-Agent": "checkmarx-sca-stitcher/1"},
        )
        try:
            # Region and key ID are allowlisted before this fixed HTTPS endpoint is built.
            with urlopen(request, timeout=KEY_FETCH_TIMEOUT_SECONDS) as response:  # nosec B310
                return response.read(16_385)
        except OSError as exc:
            raise AuthenticationError("Could not retrieve the ALB public key.") from exc
