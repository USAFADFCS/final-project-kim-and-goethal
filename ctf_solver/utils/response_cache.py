"""
Response caching and request deduplication for CTF Solver.

Provides:
- ResponseCache: TTL-based caching for HTTP responses
- RequestDeduplicator: Prevents duplicate concurrent requests
"""

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple


@dataclass
class CacheEntry:
    """A single cache entry with value, timestamp, and metadata."""

    value: Any
    timestamp: float
    hits: int = 0
    size_bytes: int = 0


class ResponseCache:
    """
    Thread-safe TTL-based response cache with LRU eviction.

    Features:
    - TTL (time-to-live) expiration for entries
    - Maximum entry count with LRU eviction
    - Maximum total size with size-based eviction
    - Thread-safe operations
    - Cache statistics

    Usage:
        cache = ResponseCache(ttl=300, max_entries=1000)

        # Check cache first
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        # Make request and cache result
        result = make_request(...)
        cache.set(cache_key, result)
    """

    def __init__(
        self,
        ttl: float = 300.0,  # 5 minutes default
        max_entries: int = 1000,
        max_size_bytes: int = 50 * 1024 * 1024,  # 50MB default
        enabled: bool = True,
    ):
        """
        Initialize the response cache.

        Args:
            ttl: Time-to-live in seconds for cache entries
            max_entries: Maximum number of entries to store
            max_size_bytes: Maximum total size of cached data
            enabled: Whether caching is enabled
        """
        self.ttl = ttl
        self.max_entries = max_entries
        self.max_size_bytes = max_size_bytes
        self.enabled = enabled

        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._total_size = 0

        # Statistics
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    @staticmethod
    def make_cache_key(
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Create a deterministic cache key from request parameters.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            params: Query parameters
            data: Request body/form data
            headers: Request headers (only cache-relevant ones)

        Returns:
            SHA256 hash of the request signature
        """
        # Only include cache-relevant headers
        cache_headers = {}
        if headers:
            for key in ["Accept", "Accept-Language", "Authorization"]:
                if key in headers:
                    cache_headers[key] = headers[key]

        signature = {
            "method": method.upper(),
            "url": url,
            "params": params or {},
            "data": data or {},
            "headers": cache_headers,
        }

        # Create deterministic JSON string
        sig_str = json.dumps(signature, sort_keys=True, default=str)
        return hashlib.sha256(sig_str.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        """
        Get a value from the cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        if not self.enabled:
            return None

        with self._lock:
            entry = self._cache.get(key)

            if entry is None:
                self._misses += 1
                return None

            # Check if expired
            if time.time() - entry.timestamp > self.ttl:
                self._remove_entry(key)
                self._misses += 1
                return None

            # Update access order (LRU)
            self._cache.move_to_end(key)
            entry.hits += 1
            self._hits += 1

            return entry.value

    def set(self, key: str, value: Any) -> None:
        """
        Store a value in the cache.

        Args:
            key: Cache key
            value: Value to cache
        """
        if not self.enabled:
            return

        # Estimate size
        try:
            size_bytes = len(str(value).encode())
        except Exception:
            size_bytes = 1000  # Default estimate

        with self._lock:
            # Remove old entry if exists
            if key in self._cache:
                self._remove_entry(key)

            # Evict entries if needed
            self._evict_if_needed(size_bytes)

            # Add new entry
            self._cache[key] = CacheEntry(
                value=value,
                timestamp=time.time(),
                size_bytes=size_bytes,
            )
            self._total_size += size_bytes

    def _remove_entry(self, key: str) -> None:
        """Remove an entry from the cache (must hold lock)."""
        if key in self._cache:
            entry = self._cache.pop(key)
            self._total_size -= entry.size_bytes

    def _evict_if_needed(self, new_size: int) -> None:
        """Evict entries to make room for new entry (must hold lock)."""
        # Evict by count
        while len(self._cache) >= self.max_entries:
            oldest_key = next(iter(self._cache))
            self._remove_entry(oldest_key)
            self._evictions += 1

        # Evict by size
        while self._total_size + new_size > self.max_size_bytes and self._cache:
            oldest_key = next(iter(self._cache))
            self._remove_entry(oldest_key)
            self._evictions += 1

    def invalidate(self, key: str) -> bool:
        """
        Remove a specific entry from the cache.

        Args:
            key: Cache key to invalidate

        Returns:
            True if entry was found and removed
        """
        with self._lock:
            if key in self._cache:
                self._remove_entry(key)
                return True
            return False

    def invalidate_pattern(self, url_pattern: str) -> int:
        """
        Invalidate all entries whose URL contains the pattern.

        Note: This requires storing URL info, which we don't currently do.
        For now, this is a placeholder that clears the entire cache.

        Args:
            url_pattern: URL substring to match

        Returns:
            Number of entries invalidated
        """
        with self._lock:
            count = len(self._cache)
            self.clear()
            return count

    def clear(self) -> None:
        """Clear all entries from the cache."""
        with self._lock:
            self._cache.clear()
            self._total_size = 0

    def cleanup_expired(self) -> int:
        """
        Remove all expired entries from the cache.

        Returns:
            Number of entries removed
        """
        now = time.time()
        removed = 0

        with self._lock:
            expired_keys = [
                key
                for key, entry in self._cache.items()
                if now - entry.timestamp > self.ttl
            ]
            for key in expired_keys:
                self._remove_entry(key)
                removed += 1

        return removed

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = self._hits / total_requests if total_requests > 0 else 0.0

            return {
                "enabled": self.enabled,
                "entries": len(self._cache),
                "max_entries": self.max_entries,
                "total_size_bytes": self._total_size,
                "max_size_bytes": self.max_size_bytes,
                "ttl_seconds": self.ttl,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": hit_rate,
                "evictions": self._evictions,
            }

    def __len__(self) -> int:
        """Return number of entries in cache."""
        with self._lock:
            return len(self._cache)

    def __contains__(self, key: str) -> bool:
        """Check if key is in cache (without affecting LRU order)."""
        with self._lock:
            if key not in self._cache:
                return False
            entry = self._cache[key]
            return time.time() - entry.timestamp <= self.ttl


class RequestDeduplicator:
    """
    Prevents duplicate concurrent requests to the same endpoint.

    When multiple concurrent requests are made to the same URL with the same
    parameters, only one request is actually made and all callers receive
    the same result.

    Usage:
        dedup = RequestDeduplicator()

        def make_request():
            return dedup.dedupe(
                key=cache_key,
                request_fn=lambda: session.get(url),
            )
    """

    def __init__(self, enabled: bool = True):
        """
        Initialize the request deduplicator.

        Args:
            enabled: Whether deduplication is enabled
        """
        self.enabled = enabled
        self._pending: Dict[
            str, Tuple[threading.Event, Optional[Any], Optional[Exception]]
        ] = {}
        self._lock = threading.Lock()

        # Statistics
        self._deduplicated = 0
        self._total_requests = 0

    def dedupe(
        self,
        key: str,
        request_fn: Callable[[], Any],
    ) -> Any:
        """
        Execute a request with deduplication.

        If another request with the same key is in progress, wait for it
        to complete and return its result instead of making a duplicate request.

        Args:
            key: Unique key for this request (use ResponseCache.make_cache_key)
            request_fn: Function that makes the actual request

        Returns:
            Result of the request

        Raises:
            Any exception raised by request_fn
        """
        if not self.enabled:
            return request_fn()

        with self._lock:
            self._total_requests += 1

            # Check if request is already in progress
            if key in self._pending:
                event, _, _ = self._pending[key]
                self._deduplicated += 1
                # Wait outside the lock
                wait_event = event
            else:
                # We're the first, create an event for others to wait on
                event = threading.Event()
                self._pending[key] = (event, None, None)
                wait_event = None

        if wait_event is not None:
            # Wait for the other request to complete
            wait_event.wait()

            with self._lock:
                if key in self._pending:
                    _, result, error = self._pending[key]
                    if error is not None:
                        raise error
                    return result
                else:
                    # Entry was removed, shouldn't happen but handle gracefully
                    return request_fn()

        # We're the primary request, execute it
        result = None
        error = None

        try:
            result = request_fn()
            return result
        except Exception as e:
            error = e
            raise
        finally:
            with self._lock:
                # Store result for waiters
                event, _, _ = self._pending[key]
                self._pending[key] = (event, result, error)
                # Signal waiters
                event.set()
                # Clean up after a short delay to let waiters get the result
                # In practice, we could use a timer but for simplicity,
                # we'll clean up immediately since waiters check before we delete

            # Remove from pending (waiters have the event reference)
            # Use a small delay to ensure waiters can read the result
            def cleanup():
                time.sleep(0.1)
                with self._lock:
                    if key in self._pending:
                        del self._pending[key]

            cleanup_thread = threading.Thread(target=cleanup, daemon=True)
            cleanup_thread.start()

    def get_stats(self) -> Dict[str, Any]:
        """
        Get deduplication statistics.

        Returns:
            Dictionary with stats
        """
        with self._lock:
            dedup_rate = (
                self._deduplicated / self._total_requests
                if self._total_requests > 0
                else 0.0
            )

            return {
                "enabled": self.enabled,
                "total_requests": self._total_requests,
                "deduplicated": self._deduplicated,
                "deduplication_rate": dedup_rate,
                "pending_requests": len(self._pending),
            }

    def clear_pending(self) -> None:
        """Clear all pending requests (use with caution)."""
        with self._lock:
            for key, (event, _, _) in self._pending.items():
                event.set()
            self._pending.clear()


class CachedSession:
    """
    A wrapper around requests.Session that adds caching and deduplication.

    This can be used as a drop-in replacement for requests.Session in tools
    that want to benefit from caching.

    Usage:
        session = requests.Session()
        cached_session = CachedSession(session, cache, deduplicator)

        # Use like a normal session
        response = cached_session.get(url)
    """

    def __init__(
        self,
        session,  # requests.Session
        cache: Optional[ResponseCache] = None,
        deduplicator: Optional[RequestDeduplicator] = None,
    ):
        """
        Initialize the cached session.

        Args:
            session: The underlying requests.Session
            cache: Optional ResponseCache instance
            deduplicator: Optional RequestDeduplicator instance
        """
        self.session = session
        # Use explicit None check since ResponseCache.__len__ can make empty cache falsy
        self.cache = cache if cache is not None else ResponseCache(enabled=False)
        self.deduplicator = (
            deduplicator
            if deduplicator is not None
            else RequestDeduplicator(enabled=False)
        )

    def _make_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs,
    ):
        """Make a request with caching and deduplication."""
        # Create cache key
        cache_key = ResponseCache.make_cache_key(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=headers,
        )

        # Check cache first (only for GET and HEAD)
        if method.upper() in ("GET", "HEAD") and self.cache.enabled:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached

        # Define the actual request function
        def do_request():
            if method.upper() == "GET":
                return self.session.get(url, params=params, headers=headers, **kwargs)
            elif method.upper() == "HEAD":
                return self.session.head(url, params=params, headers=headers, **kwargs)
            elif method.upper() == "POST":
                return self.session.post(url, data=data, headers=headers, **kwargs)
            else:
                return self.session.request(
                    method, url, params=params, data=data, headers=headers, **kwargs
                )

        # Execute with deduplication
        if self.deduplicator.enabled:
            response = self.deduplicator.dedupe(cache_key, do_request)
        else:
            response = do_request()

        # Cache the result (only for GET and HEAD)
        if method.upper() in ("GET", "HEAD") and self.cache.enabled:
            self.cache.set(cache_key, response)

        return response

    def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs,
    ):
        """Cached GET request."""
        return self._make_request("GET", url, params=params, headers=headers, **kwargs)

    def head(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs,
    ):
        """Cached HEAD request."""
        return self._make_request("HEAD", url, params=params, headers=headers, **kwargs)

    def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs,
    ):
        """POST request (not cached by default, but deduplicated)."""
        return self._make_request("POST", url, data=data, headers=headers, **kwargs)

    def request(self, method: str, url: str, **kwargs):
        """Generic request method."""
        return self._make_request(method, url, **kwargs)

    @property
    def cookies(self):
        """Access the underlying session's cookies."""
        return self.session.cookies

    def get_stats(self) -> Dict[str, Any]:
        """Get combined cache and deduplication stats."""
        return {
            "cache": self.cache.get_stats(),
            "deduplicator": self.deduplicator.get_stats(),
        }
