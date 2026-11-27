
"""Rate limiting for authentication requests."""

import time
from collections import defaultdict, deque
from threading import Lock


class RateLimiter:

    def __init__(self, max_requests=10, window_seconds=1):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)
        self.lock = Lock()

    def allow_request(self, request_ip):
        """Check whether an IP address can make another request."""

        with self.lock:
            current_time = time.monotonic()
            timestamps = self.requests[request_ip]

            # Remove requests outside the time window.
            while timestamps and (
                current_time - timestamps[0] >= self.window_seconds
            ):
                timestamps.popleft()

            # Reject requests exceeding the limit.
            if len(timestamps) >= self.max_requests:
                return False

            # Record the accepted request.
            timestamps.append(current_time)

            return True
