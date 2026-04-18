"""
Tests for CTF Solver utility modules.

Tests cover:
- ResponseCache: TTL-based caching, LRU eviction, thread safety
- RequestDeduplicator: Concurrent request deduplication
- CachedSession: drop-in ``requests.Session`` wrapper with cache + dedup

AsyncToolExecutor tests were removed in Batch C alongside the executor
itself (the LLM's native parallel tool use replaces that abstraction).
"""

import threading
import time
from unittest.mock import Mock

from ctf_solver.utils.response_cache import (
    CachedSession,
    RequestDeduplicator,
    ResponseCache,
)

# =============================================================================
# ResponseCache Tests
# =============================================================================


class TestResponseCacheBasics:
    """Basic ResponseCache functionality tests."""

    def test_create_cache_with_defaults(self):
        """Test cache creation with default parameters."""
        cache = ResponseCache()
        assert cache.ttl == 300.0
        assert cache.max_entries == 1000
        assert cache.max_size_bytes == 50 * 1024 * 1024
        assert cache.enabled is True
        assert len(cache) == 0

    def test_create_cache_with_custom_params(self):
        """Test cache creation with custom parameters."""
        cache = ResponseCache(
            ttl=60.0,
            max_entries=100,
            max_size_bytes=1024,
            enabled=False,
        )
        assert cache.ttl == 60.0
        assert cache.max_entries == 100
        assert cache.max_size_bytes == 1024
        assert cache.enabled is False

    def test_set_and_get(self):
        """Test basic set and get operations."""
        cache = ResponseCache()
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_get_nonexistent_key(self):
        """Test getting a key that doesn't exist."""
        cache = ResponseCache()
        assert cache.get("nonexistent") is None

    def test_get_updates_lru_order(self):
        """Test that get updates LRU order."""
        cache = ResponseCache(max_entries=2)
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        # Access key1 to make it most recently used
        cache.get("key1")

        # Add key3, should evict key2 (least recently used)
        cache.set("key3", "value3")

        assert cache.get("key1") == "value1"
        assert cache.get("key2") is None
        assert cache.get("key3") == "value3"

    def test_disabled_cache(self):
        """Test that disabled cache doesn't store or retrieve."""
        cache = ResponseCache(enabled=False)
        cache.set("key1", "value1")
        assert cache.get("key1") is None
        assert len(cache) == 0


class TestResponseCacheTTL:
    """TTL-related tests for ResponseCache."""

    def test_expired_entry_returns_none(self):
        """Test that expired entries return None."""
        cache = ResponseCache(ttl=0.1)  # 100ms TTL
        cache.set("key1", "value1")

        # Should be available immediately
        assert cache.get("key1") == "value1"

        # Wait for expiration
        time.sleep(0.15)
        assert cache.get("key1") is None

    def test_cleanup_expired(self):
        """Test cleanup of expired entries."""
        cache = ResponseCache(ttl=0.1)
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        time.sleep(0.15)

        removed = cache.cleanup_expired()
        assert removed == 2
        assert len(cache) == 0

    def test_contains_respects_ttl(self):
        """Test that __contains__ respects TTL."""
        cache = ResponseCache(ttl=0.1)
        cache.set("key1", "value1")

        assert "key1" in cache
        time.sleep(0.15)
        assert "key1" not in cache


class TestResponseCacheEviction:
    """Eviction-related tests for ResponseCache."""

    def test_max_entries_eviction(self):
        """Test eviction when max entries is reached."""
        cache = ResponseCache(max_entries=3)

        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        cache.set("key4", "value4")

        assert len(cache) == 3
        assert cache.get("key1") is None  # Oldest, should be evicted
        assert cache.get("key4") == "value4"

    def test_max_size_eviction(self):
        """Test eviction when max size is reached."""
        cache = ResponseCache(max_size_bytes=100)

        # Add entries that exceed size limit
        cache.set("key1", "a" * 40)
        cache.set("key2", "b" * 40)
        cache.set("key3", "c" * 40)

        # Should have evicted oldest entries
        stats = cache.get_stats()
        assert stats["total_size_bytes"] <= 100


class TestResponseCacheInvalidation:
    """Invalidation-related tests for ResponseCache."""

    def test_invalidate_specific_key(self):
        """Test invalidating a specific key."""
        cache = ResponseCache()
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        result = cache.invalidate("key1")
        assert result is True
        assert cache.get("key1") is None
        assert cache.get("key2") == "value2"

    def test_invalidate_nonexistent_key(self):
        """Test invalidating a key that doesn't exist."""
        cache = ResponseCache()
        result = cache.invalidate("nonexistent")
        assert result is False

    def test_clear_cache(self):
        """Test clearing the entire cache."""
        cache = ResponseCache()
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        cache.clear()
        assert len(cache) == 0


class TestResponseCacheStats:
    """Statistics-related tests for ResponseCache."""

    def test_hit_miss_tracking(self):
        """Test hit and miss tracking."""
        cache = ResponseCache()
        cache.set("key1", "value1")

        # Hit
        cache.get("key1")
        # Miss
        cache.get("nonexistent")

        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 0.5

    def test_eviction_tracking(self):
        """Test eviction tracking."""
        cache = ResponseCache(max_entries=2)
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")

        stats = cache.get_stats()
        assert stats["evictions"] >= 1


class TestResponseCacheKey:
    """Cache key generation tests."""

    def test_make_cache_key_basic(self):
        """Test basic cache key generation."""
        key = ResponseCache.make_cache_key(
            method="GET",
            url="http://example.com/test",
        )
        assert isinstance(key, str)
        assert len(key) == 64  # SHA256 hex

    def test_make_cache_key_deterministic(self):
        """Test that cache key generation is deterministic."""
        key1 = ResponseCache.make_cache_key(
            method="GET",
            url="http://example.com/test",
            params={"a": "1", "b": "2"},
        )
        key2 = ResponseCache.make_cache_key(
            method="GET",
            url="http://example.com/test",
            params={"b": "2", "a": "1"},
        )
        assert key1 == key2

    def test_make_cache_key_different_methods(self):
        """Test that different methods produce different keys."""
        key_get = ResponseCache.make_cache_key(method="GET", url="http://example.com")
        key_post = ResponseCache.make_cache_key(method="POST", url="http://example.com")
        assert key_get != key_post


class TestResponseCacheThreadSafety:
    """Thread safety tests for ResponseCache."""

    def test_concurrent_access(self):
        """Test concurrent access to cache."""
        cache = ResponseCache()
        errors = []

        def worker(thread_id):
            try:
                for i in range(100):
                    key = f"key_{thread_id}_{i}"
                    cache.set(key, f"value_{thread_id}_{i}")
                    cache.get(key)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


# =============================================================================
# RequestDeduplicator Tests
# =============================================================================


class TestRequestDeduplicatorBasics:
    """Basic RequestDeduplicator functionality tests."""

    def test_create_deduplicator(self):
        """Test deduplicator creation."""
        dedup = RequestDeduplicator()
        assert dedup.enabled is True

    def test_disabled_deduplicator(self):
        """Test that disabled deduplicator just executes."""
        dedup = RequestDeduplicator(enabled=False)
        call_count = 0

        def request_fn():
            nonlocal call_count
            call_count += 1
            return "result"

        result = dedup.dedupe("key1", request_fn)
        assert result == "result"
        assert call_count == 1

    def test_single_request(self):
        """Test single request execution."""
        dedup = RequestDeduplicator()
        result = dedup.dedupe("key1", lambda: "result")
        assert result == "result"


class TestRequestDeduplicatorConcurrency:
    """Concurrency tests for RequestDeduplicator."""

    def test_deduplicates_concurrent_requests(self):
        """Test that concurrent requests are deduplicated."""
        dedup = RequestDeduplicator()
        call_count = 0
        results = []
        lock = threading.Lock()

        def slow_request():
            nonlocal call_count
            with lock:
                call_count += 1
            time.sleep(0.2)
            return "result"

        def worker():
            result = dedup.dedupe("same_key", slow_request)
            with lock:
                results.append(result)

        # Start multiple threads with the same key
        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Only one actual request should have been made
        assert call_count == 1
        assert all(r == "result" for r in results)

    def test_different_keys_not_deduplicated(self):
        """Test that different keys are not deduplicated."""
        dedup = RequestDeduplicator()
        call_count = 0
        lock = threading.Lock()

        def request():
            nonlocal call_count
            with lock:
                call_count += 1
            return "result"

        def worker(key):
            dedup.dedupe(key, request)

        threads = [threading.Thread(target=worker, args=(f"key{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert call_count == 5


class TestRequestDeduplicatorErrors:
    """Error handling tests for RequestDeduplicator."""

    def test_propagates_errors(self):
        """Test that errors are propagated to all waiters."""
        dedup = RequestDeduplicator()
        errors = []
        lock = threading.Lock()

        def failing_request():
            time.sleep(0.1)
            raise ValueError("Test error")

        def worker():
            try:
                dedup.dedupe("key1", failing_request)
            except ValueError as e:
                with lock:
                    errors.append(str(e))

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All threads should receive the error
        assert len(errors) == 3
        assert all(e == "Test error" for e in errors)


class TestRequestDeduplicatorStats:
    """Statistics tests for RequestDeduplicator."""

    def test_stats_tracking(self):
        """Test that stats are tracked correctly."""
        dedup = RequestDeduplicator()

        dedup.dedupe("key1", lambda: "result1")
        dedup.dedupe("key2", lambda: "result2")

        stats = dedup.get_stats()
        assert stats["total_requests"] == 2
        assert stats["enabled"] is True


# =============================================================================
# CachedSession Tests
# =============================================================================


class TestCachedSession:
    """Tests for CachedSession wrapper."""

    def test_cached_get_request(self):
        """Test that GET requests flow through cached session correctly."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "test response"
        mock_session.get.return_value = mock_response

        # Create with explicit enabled=True
        cache = ResponseCache(enabled=True)
        cached_session = CachedSession(mock_session, cache=cache)

        # Make a request
        result = cached_session.get("http://example.com/test")

        # Verify the request returned the mock response
        assert result == mock_response

        # Verify session.get was called
        assert mock_session.get.call_count == 1

        # Verify cache is enabled in the cached session
        assert cached_session.cache.enabled is True

    def test_post_not_cached(self):
        """Test that POST requests are not cached."""
        mock_session = Mock()
        mock_response = Mock()
        mock_session.post.return_value = mock_response

        cache = ResponseCache()
        cached_session = CachedSession(mock_session, cache=cache)

        cached_session.post("http://example.com/test", data={"key": "value"})
        cached_session.post("http://example.com/test", data={"key": "value"})

        # POST should not be cached
        assert mock_session.post.call_count == 2

    def test_combined_stats(self):
        """Test combined statistics."""
        mock_session = Mock()
        cache = ResponseCache()
        dedup = RequestDeduplicator()
        cached_session = CachedSession(mock_session, cache=cache, deduplicator=dedup)

        stats = cached_session.get_stats()
        assert "cache" in stats
        assert "deduplicator" in stats


# =============================================================================
# SolverConfig wiring — enable_response_cache flag
# =============================================================================


class TestEnableResponseCacheFlag:
    """Config flag + ``build_agent`` wiring for the response cache."""

    def test_default_off(self):
        from ctf_solver.config import SolverConfig

        cfg = SolverConfig()
        assert cfg.enable_response_cache is False
        assert cfg.response_cache_ttl_seconds == 120.0
        assert cfg.response_cache_max_entries == 500

    def test_opt_in_sets_all_fields(self):
        from ctf_solver.config import SolverConfig

        cfg = SolverConfig(
            enable_response_cache=True,
            response_cache_ttl_seconds=60.0,
            response_cache_max_entries=200,
        )
        assert cfg.enable_response_cache is True
        assert cfg.response_cache_ttl_seconds == 60.0
        assert cfg.response_cache_max_entries == 200
