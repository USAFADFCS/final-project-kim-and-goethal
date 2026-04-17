"""
Async/parallel tool execution for CTF Solver.

Provides:
- AsyncToolExecutor: Execute multiple tools concurrently
- BatchExecutor: Execute batches of similar operations
"""

import concurrent.futures
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of an async tool execution."""

    tool_name: str
    input_data: str
    output: Optional[str] = None
    error: Optional[str] = None
    duration_ms: float = 0.0
    success: bool = True


@dataclass
class BatchResult:
    """Result of a batch execution."""

    results: List[ExecutionResult] = field(default_factory=list)
    total_duration_ms: float = 0.0
    successful: int = 0
    failed: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        total = self.successful + self.failed
        return self.successful / total if total > 0 else 0.0


class AsyncToolExecutor:
    """
    Execute multiple tool calls concurrently with thread pooling.

    This executor allows running multiple independent tool operations
    in parallel, improving performance for tasks like path enumeration
    or multi-target probing.

    Usage:
        executor = AsyncToolExecutor(max_workers=10)

        # Queue multiple tool calls
        executor.submit("http_fetch", tool, '{"url": "http://example.com/path1"}')
        executor.submit("http_fetch", tool, '{"url": "http://example.com/path2"}')

        # Wait for all results
        results = executor.wait_all()

        # Or use the convenience method
        results = executor.execute_batch([
            ("http_fetch", tool, '{"url": "http://example.com/path1"}'),
            ("http_fetch", tool, '{"url": "http://example.com/path2"}'),
        ])
    """

    def __init__(
        self,
        max_workers: int = 10,
        timeout: float = 30.0,
        enabled: bool = True,
    ):
        """
        Initialize the async executor.

        Args:
            max_workers: Maximum number of concurrent threads
            timeout: Default timeout for each operation in seconds
            enabled: Whether async execution is enabled (if False, runs sequentially)
        """
        self.max_workers = max_workers
        self.timeout = timeout
        self.enabled = enabled

        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._futures: List[Tuple[concurrent.futures.Future, str, str]] = []
        self._lock = threading.Lock()

        # Statistics
        self._total_executions = 0
        self._total_time_ms = 0.0
        self._errors = 0

    def _get_executor(self) -> concurrent.futures.ThreadPoolExecutor:
        """Get or create the thread pool executor."""
        if self._executor is None:
            self._executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_workers,
                thread_name_prefix="ctf_async_",
            )
        return self._executor

    def submit(
        self,
        tool_name: str,
        tool: Any,  # Tool with .use() method
        tool_input: str,
    ) -> None:
        """
        Submit a tool call for async execution.

        Args:
            tool_name: Name of the tool (for logging/results)
            tool: Tool instance with .use() method
            tool_input: JSON input string for the tool
        """

        def execute():
            start = time.time()
            try:
                result = tool.use(tool_input)
                return ExecutionResult(
                    tool_name=tool_name,
                    input_data=tool_input,
                    output=result,
                    duration_ms=(time.time() - start) * 1000,
                    success=True,
                )
            except Exception as e:
                return ExecutionResult(
                    tool_name=tool_name,
                    input_data=tool_input,
                    error=str(e),
                    duration_ms=(time.time() - start) * 1000,
                    success=False,
                )

        if not self.enabled:
            # Run synchronously, store result as a "completed" future
            result = execute()
            with self._lock:
                # Create a pre-completed future-like object
                future = concurrent.futures.Future()
                future.set_result(result)
                self._futures.append((future, tool_name, tool_input))
        else:
            executor = self._get_executor()
            future = executor.submit(execute)
            with self._lock:
                self._futures.append((future, tool_name, tool_input))

    def wait_all(self, timeout: Optional[float] = None) -> List[ExecutionResult]:
        """
        Wait for all submitted tasks to complete.

        Args:
            timeout: Maximum time to wait (uses default if None)

        Returns:
            List of ExecutionResult objects
        """
        timeout = timeout or self.timeout
        results = []

        with self._lock:
            futures_copy = self._futures.copy()
            self._futures.clear()

        start = time.time()

        for future, tool_name, tool_input in futures_copy:
            try:
                remaining = timeout - (time.time() - start)
                if remaining <= 0:
                    remaining = 0.1  # Minimum timeout

                result = future.result(timeout=remaining)
                results.append(result)

                # Update stats
                self._total_executions += 1
                self._total_time_ms += result.duration_ms
                if not result.success:
                    self._errors += 1

            except concurrent.futures.TimeoutError:
                results.append(
                    ExecutionResult(
                        tool_name=tool_name,
                        input_data=tool_input,
                        error="Execution timed out",
                        success=False,
                    )
                )
                self._errors += 1
            except Exception as e:
                results.append(
                    ExecutionResult(
                        tool_name=tool_name,
                        input_data=tool_input,
                        error=str(e),
                        success=False,
                    )
                )
                self._errors += 1

        return results

    def execute_batch(
        self,
        tasks: List[Tuple[str, Any, str]],
        timeout: Optional[float] = None,
    ) -> BatchResult:
        """
        Execute a batch of tool calls and wait for all results.

        Args:
            tasks: List of (tool_name, tool_instance, tool_input) tuples
            timeout: Maximum time for entire batch

        Returns:
            BatchResult with all results
        """
        start = time.time()

        # Submit all tasks
        for tool_name, tool, tool_input in tasks:
            self.submit(tool_name, tool, tool_input)

        # Wait for results
        results = self.wait_all(timeout=timeout)

        # Build batch result
        batch_result = BatchResult(
            results=results,
            total_duration_ms=(time.time() - start) * 1000,
            successful=sum(1 for r in results if r.success),
            failed=sum(1 for r in results if not r.success),
        )

        return batch_result

    def execute_parallel_probes(
        self,
        tool: Any,
        base_input: Dict[str, Any],
        variations: List[Dict[str, Any]],
        variation_key: str = "payload",
    ) -> BatchResult:
        """
        Execute a tool with multiple payload variations in parallel.

        Useful for probing multiple payloads against the same endpoint.

        Args:
            tool: Tool instance with .use() method
            base_input: Base input dictionary
            variations: List of variation dictionaries to merge with base
            variation_key: Key name for variation in the base input

        Returns:
            BatchResult with all results
        """
        import json

        tasks = []
        for variation in variations:
            input_data = base_input.copy()
            input_data.update(variation)
            tool_input = json.dumps(input_data)
            tasks.append((tool.name, tool, tool_input))

        return self.execute_batch(tasks)

    def map_urls(
        self,
        tool: Any,
        urls: List[str],
        extra_params: Optional[Dict[str, Any]] = None,
    ) -> BatchResult:
        """
        Execute a tool against multiple URLs in parallel.

        Args:
            tool: Tool instance with .use() method
            urls: List of URLs to process
            extra_params: Additional parameters to include in each call

        Returns:
            BatchResult with all results
        """
        import json

        tasks = []
        for url in urls:
            input_data = {"url": url}
            if extra_params:
                input_data.update(extra_params)
            tool_input = json.dumps(input_data)
            tasks.append((tool.name, tool, tool_input))

        return self.execute_batch(tasks)

    def get_stats(self) -> Dict[str, Any]:
        """Get executor statistics."""
        avg_time = (
            self._total_time_ms / self._total_executions
            if self._total_executions > 0
            else 0.0
        )
        error_rate = (
            self._errors / self._total_executions if self._total_executions > 0 else 0.0
        )

        return {
            "enabled": self.enabled,
            "max_workers": self.max_workers,
            "timeout": self.timeout,
            "total_executions": self._total_executions,
            "total_time_ms": self._total_time_ms,
            "avg_time_ms": avg_time,
            "errors": self._errors,
            "error_rate": error_rate,
        }

    def shutdown(self, wait: bool = True) -> None:
        """
        Shutdown the executor.

        Args:
            wait: Whether to wait for pending tasks to complete
        """
        if self._executor is not None:
            self._executor.shutdown(wait=wait)
            self._executor = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - shutdown executor."""
        self.shutdown(wait=True)
        return False


class RateLimitedExecutor(AsyncToolExecutor):
    """
    Async executor with rate limiting to avoid overwhelming targets.

    Extends AsyncToolExecutor with configurable rate limits and
    per-host tracking to prevent excessive requests.
    """

    def __init__(
        self,
        max_workers: int = 10,
        timeout: float = 30.0,
        enabled: bool = True,
        requests_per_second: float = 10.0,
        per_host_limit: float = 5.0,
    ):
        """
        Initialize the rate-limited executor.

        Args:
            max_workers: Maximum concurrent threads
            timeout: Default timeout per operation
            enabled: Whether async execution is enabled
            requests_per_second: Global rate limit
            per_host_limit: Rate limit per unique host
        """
        super().__init__(max_workers, timeout, enabled)
        self.requests_per_second = requests_per_second
        self.per_host_limit = per_host_limit

        self._last_request_time = 0.0
        self._host_times: Dict[str, float] = {}
        self._rate_lock = threading.Lock()

    def _wait_for_rate_limit(self, host: Optional[str] = None) -> None:
        """Wait if necessary to comply with rate limits."""
        with self._rate_lock:
            now = time.time()

            # Global rate limit
            min_interval = 1.0 / self.requests_per_second
            elapsed = now - self._last_request_time
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
                now = time.time()

            self._last_request_time = now

            # Per-host rate limit
            if host:
                host_min_interval = 1.0 / self.per_host_limit
                last_host_time = self._host_times.get(host, 0.0)
                host_elapsed = now - last_host_time
                if host_elapsed < host_min_interval:
                    time.sleep(host_min_interval - host_elapsed)
                    now = time.time()

                self._host_times[host] = now

    def submit(
        self,
        tool_name: str,
        tool: Any,
        tool_input: str,
        host: Optional[str] = None,
    ) -> None:
        """
        Submit a tool call with rate limiting.

        Args:
            tool_name: Name of the tool
            tool: Tool instance with .use() method
            tool_input: JSON input string
            host: Optional host for per-host rate limiting
        """
        self._wait_for_rate_limit(host)
        super().submit(tool_name, tool, tool_input)


class ProgressTracker:
    """
    Track progress of batch operations.

    Provides callbacks and progress reporting for long-running
    batch operations.
    """

    def __init__(
        self,
        total: int,
        callback: Optional[Callable[[int, int, Optional[str]], None]] = None,
    ):
        """
        Initialize progress tracker.

        Args:
            total: Total number of operations
            callback: Optional callback(completed, total, message)
        """
        self.total = total
        self.callback = callback

        self._completed = 0
        self._lock = threading.Lock()

    def update(self, message: Optional[str] = None) -> None:
        """Update progress by one."""
        with self._lock:
            self._completed += 1
            if self.callback:
                self.callback(self._completed, self.total, message)

    @property
    def completed(self) -> int:
        """Get number of completed operations."""
        with self._lock:
            return self._completed

    @property
    def progress(self) -> float:
        """Get progress as a fraction (0.0 to 1.0)."""
        with self._lock:
            return self._completed / self.total if self.total > 0 else 0.0
