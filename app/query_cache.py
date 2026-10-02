"""Small TTL caches for expensive console counts and filter choices."""
import threading
import time
from collections import OrderedDict


class QueryCountCache:
    def __init__(self, ttl=5.0, capacity=128):
        self.ttl = ttl
        self.capacity = capacity
        self.entries = OrderedDict()
        self.lock = threading.Lock()

    def get(self, key, compute):
        with self.lock:
            now = time.monotonic()
            cached = self.entries.get(key)
            if cached and cached[0] > now:
                self.entries.move_to_end(key)
                return cached[1]
            value = compute()
            self.entries[key] = (time.monotonic() + self.ttl, value)
            self.entries.move_to_end(key)
            while len(self.entries) > self.capacity:
                self.entries.popitem(last=False)
            return value


query_counts = QueryCountCache()
query_choices = QueryCountCache(ttl=30.0, capacity=8)


def literal_pattern(value, mode):
    """Treat user text literally, including SQL LIKE wildcard characters."""
    escaped = value.replace("!", "!!").replace("%", "!%").replace("_", "!_")
    return escaped + "%" if mode == "prefix" else "%" + escaped + "%"
