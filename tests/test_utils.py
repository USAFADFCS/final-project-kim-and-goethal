"""
Tests for CTF Solver utility modules.

Tests cover:
- ResponseCache: TTL-based caching, LRU eviction, thread safety
- RequestDeduplicator: Concurrent request deduplication
- AsyncToolExecutor: Parallel tool execution
"""

import json
import threading
import time
from unittest.mock import Mock, MagicMock
import pytest

from ctf_solver.utils.response_cache import (
    ResponseCache,
    RequestDeduplicator,
    CachedSession,
    CacheEntry,
)
from ctf_solver.utils.async_executor import (
    AsyncToolExecutor,
    RateLimitedExecutor,
    BatchResult,
    ExecutionResult,
    ProgressTracker,
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
# AsyncToolExecutor Tests
# =============================================================================

class TestAsyncToolExecutorBasics:
    """Basic AsyncToolExecutor functionality tests."""

    def test_create_executor(self):
        """Test executor creation."""
        executor = AsyncToolExecutor()
        assert executor.max_workers == 10
        assert executor.timeout == 30.0
        assert executor.enabled is True

    def test_create_executor_custom_params(self):
        """Test executor creation with custom params."""
        executor = AsyncToolExecutor(max_workers=5, timeout=10.0, enabled=False)
        assert executor.max_workers == 5
        assert executor.timeout == 10.0
        assert executor.enabled is False


class TestAsyncToolExecutorExecution:
    """Execution tests for AsyncToolExecutor."""

    def test_submit_and_wait(self):
        """Test submitting and waiting for a task."""
        executor = AsyncToolExecutor()

        mock_tool = Mock()
        mock_tool.use.return_value = "result"
        mock_tool.name = "test_tool"

        executor.submit("test_tool", mock_tool, '{"key": "value"}')
        results = executor.wait_all()

        assert len(results) == 1
        assert results[0].success is True
        assert results[0].output == "result"
        executor.shutdown()

    def test_execute_batch(self):
        """Test batch execution."""
        executor = AsyncToolExecutor()

        mock_tool = Mock()
        mock_tool.use.return_value = "result"
        mock_tool.name = "test_tool"

        tasks = [
            ("test_tool", mock_tool, '{"url": "http://example.com/1"}'),
            ("test_tool", mock_tool, '{"url": "http://example.com/2"}'),
            ("test_tool", mock_tool, '{"url": "http://example.com/3"}'),
        ]

        batch_result = executor.execute_batch(tasks)

        assert batch_result.successful == 3
        assert batch_result.failed == 0
        assert len(batch_result.results) == 3
        executor.shutdown()

    def test_disabled_executor_runs_sequentially(self):
        """Test that disabled executor runs tasks sequentially."""
        executor = AsyncToolExecutor(enabled=False)

        mock_tool = Mock()
        mock_tool.use.return_value = "result"
        mock_tool.name = "test_tool"

        executor.submit("test_tool", mock_tool, '{"key": "value"}')
        results = executor.wait_all()

        assert len(results) == 1
        assert results[0].success is True

    def test_handles_tool_errors(self):
        """Test handling of tool errors."""
        executor = AsyncToolExecutor()

        mock_tool = Mock()
        mock_tool.use.side_effect = ValueError("Test error")
        mock_tool.name = "test_tool"

        executor.submit("test_tool", mock_tool, '{"key": "value"}')
        results = executor.wait_all()

        assert len(results) == 1
        assert results[0].success is False
        assert "Test error" in results[0].error
        executor.shutdown()


class TestAsyncToolExecutorParallel:
    """Parallel execution tests for AsyncToolExecutor."""

    def test_parallel_execution(self):
        """Test that tasks actually run in parallel."""
        executor = AsyncToolExecutor(max_workers=5)
        start_times = []
        lock = threading.Lock()

        def slow_use(tool_input):
            with lock:
                start_times.append(time.time())
            time.sleep(0.2)
            return "result"

        mock_tool = Mock()
        mock_tool.use = slow_use
        mock_tool.name = "test_tool"

        tasks = [
            ("test_tool", mock_tool, f'{{"i": {i}}}')
            for i in range(5)
        ]

        start = time.time()
        batch_result = executor.execute_batch(tasks, timeout=5.0)
        duration = time.time() - start

        # If run in parallel, should take ~0.2s, not ~1.0s
        assert duration < 0.5
        assert batch_result.successful == 5
        executor.shutdown()


class TestAsyncToolExecutorMapUrls:
    """URL mapping tests for AsyncToolExecutor."""

    def test_map_urls(self):
        """Test mapping URLs to tool calls."""
        executor = AsyncToolExecutor()

        mock_tool = Mock()
        mock_tool.use.return_value = "result"
        mock_tool.name = "http_fetch"

        urls = [
            "http://example.com/1",
            "http://example.com/2",
            "http://example.com/3",
        ]

        batch_result = executor.map_urls(mock_tool, urls)

        assert batch_result.successful == 3
        assert mock_tool.use.call_count == 3

        # Verify URLs were passed correctly
        calls = mock_tool.use.call_args_list
        for i, call in enumerate(calls):
            input_data = json.loads(call[0][0])
            assert input_data["url"] in urls

        executor.shutdown()

    def test_map_urls_with_extra_params(self):
        """Test mapping URLs with extra parameters."""
        executor = AsyncToolExecutor()

        mock_tool = Mock()
        mock_tool.use.return_value = "result"
        mock_tool.name = "http_fetch"

        urls = ["http://example.com/test"]
        extra_params = {"headers": {"User-Agent": "TestBot"}}

        executor.map_urls(mock_tool, urls, extra_params=extra_params)

        call_input = json.loads(mock_tool.use.call_args[0][0])
        assert call_input["url"] == "http://example.com/test"
        assert call_input["headers"]["User-Agent"] == "TestBot"
        executor.shutdown()


class TestAsyncToolExecutorStats:
    """Statistics tests for AsyncToolExecutor."""

    def test_stats_tracking(self):
        """Test that statistics are tracked."""
        executor = AsyncToolExecutor()

        mock_tool = Mock()
        mock_tool.use.return_value = "result"
        mock_tool.name = "test_tool"

        executor.submit("test_tool", mock_tool, '{}')
        executor.wait_all()

        stats = executor.get_stats()
        assert stats["total_executions"] == 1
        assert stats["errors"] == 0
        executor.shutdown()


class TestAsyncToolExecutorContextManager:
    """Context manager tests for AsyncToolExecutor."""

    def test_context_manager(self):
        """Test using executor as context manager."""
        mock_tool = Mock()
        mock_tool.use.return_value = "result"
        mock_tool.name = "test_tool"

        with AsyncToolExecutor() as executor:
            executor.submit("test_tool", mock_tool, '{}')
            results = executor.wait_all()
            assert len(results) == 1


# =============================================================================
# RateLimitedExecutor Tests
# =============================================================================

class TestRateLimitedExecutor:
    """Tests for RateLimitedExecutor."""

    def test_create_rate_limited_executor(self):
        """Test rate limited executor creation."""
        executor = RateLimitedExecutor(
            requests_per_second=10.0,
            per_host_limit=5.0,
        )
        assert executor.requests_per_second == 10.0
        assert executor.per_host_limit == 5.0
        executor.shutdown()

    def test_rate_limiting(self):
        """Test that rate limiting works."""
        executor = RateLimitedExecutor(
            max_workers=1,
            requests_per_second=10.0,  # 100ms between requests
        )

        mock_tool = Mock()
        mock_tool.use.return_value = "result"
        mock_tool.name = "test_tool"

        start = time.time()
        for i in range(3):
            executor.submit("test_tool", mock_tool, f'{{"i": {i}}}')
        executor.wait_all()
        duration = time.time() - start

        # Should take at least 200ms for 3 requests at 10/s
        assert duration >= 0.2
        executor.shutdown()


# =============================================================================
# ProgressTracker Tests
# =============================================================================

class TestProgressTracker:
    """Tests for ProgressTracker."""

    def test_create_tracker(self):
        """Test tracker creation."""
        tracker = ProgressTracker(total=100)
        assert tracker.total == 100
        assert tracker.completed == 0
        assert tracker.progress == 0.0

    def test_update_progress(self):
        """Test updating progress."""
        tracker = ProgressTracker(total=10)

        for i in range(5):
            tracker.update()

        assert tracker.completed == 5
        assert tracker.progress == 0.5

    def test_callback(self):
        """Test progress callback."""
        updates = []

        def callback(completed, total, message):
            updates.append((completed, total, message))

        tracker = ProgressTracker(total=3, callback=callback)
        tracker.update("Step 1")
        tracker.update("Step 2")
        tracker.update("Step 3")

        assert len(updates) == 3
        assert updates[0] == (1, 3, "Step 1")
        assert updates[2] == (3, 3, "Step 3")


# =============================================================================
# BatchResult Tests
# =============================================================================

class TestBatchResult:
    """Tests for BatchResult dataclass."""

    def test_create_batch_result(self):
        """Test batch result creation."""
        result = BatchResult(
            results=[],
            total_duration_ms=100.0,
            successful=5,
            failed=2,
        )
        assert result.successful == 5
        assert result.failed == 2
        assert result.total_duration_ms == 100.0

    def test_success_rate(self):
        """Test success rate calculation."""
        result = BatchResult(successful=3, failed=1)
        assert result.success_rate == 0.75

    def test_success_rate_empty(self):
        """Test success rate with no operations."""
        result = BatchResult()
        assert result.success_rate == 0.0


# =============================================================================
# ExecutionResult Tests
# =============================================================================

class TestExecutionResult:
    """Tests for ExecutionResult dataclass."""

    def test_create_execution_result(self):
        """Test execution result creation."""
        result = ExecutionResult(
            tool_name="http_fetch",
            input_data='{"url": "http://example.com"}',
            output="Response data",
            duration_ms=50.0,
            success=True,
        )
        assert result.tool_name == "http_fetch"
        assert result.success is True
        assert result.output == "Response data"

    def test_create_error_result(self):
        """Test error execution result."""
        result = ExecutionResult(
            tool_name="http_fetch",
            input_data='{}',
            error="Connection failed",
            success=False,
        )
        assert result.success is False
        assert result.error == "Connection failed"


# =============================================================================
# Integration Tests
# =============================================================================

class TestCacheExecutorIntegration:
    """Integration tests combining cache and executor."""

    def test_cached_parallel_execution(self):
        """Test parallel execution with caching."""
        cache = ResponseCache()

        mock_tool = Mock()
        call_count = 0

        def use_with_count(tool_input):
            nonlocal call_count
            call_count += 1
            return f"result_{call_count}"

        mock_tool.use = use_with_count
        mock_tool.name = "test_tool"

        with AsyncToolExecutor() as executor:
            # First batch
            tasks = [("test_tool", mock_tool, f'{{"i": {i}}}') for i in range(3)]
            result1 = executor.execute_batch(tasks)

            assert result1.successful == 3

    def test_executor_with_cached_session(self):
        """Test executor using cached session."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "response"
        mock_session.get.return_value = mock_response

        # Create with explicit enabled=True
        cache = ResponseCache(enabled=True)
        cached_session = CachedSession(mock_session, cache=cache)

        # Make a request through the cached session
        result = cached_session.get("http://example.com")

        # Verify the request was made and returned correctly
        assert result == mock_response
        assert mock_session.get.call_count == 1

        # Verify cache object is enabled
        assert cached_session.cache.enabled is True

        # Verify stats structure
        stats = cached_session.get_stats()
        assert "cache" in stats
        assert "deduplicator" in stats
