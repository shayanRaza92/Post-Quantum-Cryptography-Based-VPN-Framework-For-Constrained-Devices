"""
Thread-safe console output for the multi-ESP32 gateway.

Every ESP32 session runs in its own thread. Without coordination, the long
handshake tables of two devices connecting at the same moment get mixed line by
line. This module fixes that:

  * safe_print()  - drop-in replacement for print(); one lock for the whole process.
  * log_block()   - context manager: while active, everything the current thread
                    prints is collected and written as ONE uninterrupted block,
                    framed by a header naming the device.
"""
import builtins
import threading
from contextlib import contextmanager

_print_lock = threading.Lock()
_thread_state = threading.local()


def safe_print(*args, sep=" ", end="\n", **kwargs):
    """Same signature as print(). Buffers if the calling thread is inside log_block()."""
    buffer = getattr(_thread_state, "buffer", None)
    if buffer is not None and "file" not in kwargs:
        buffer.append(sep.join(str(a) for a in args) + end)
        return
    with _print_lock:
        builtins.print(*args, sep=sep, end=end, flush=True, **kwargs)


@contextmanager
def log_block(label_fn):
    """
    Collects this thread's output and prints it atomically when the block ends
    (also when it ends with an exception). label_fn() is called at the end so the
    header can include information learned during the block (e.g. the device ID).
    """
    _thread_state.buffer = []
    try:
        yield
    finally:
        lines = "".join(_thread_state.buffer)
        _thread_state.buffer = None
        label = label_fn()
        bar = "#" * 79
        with _print_lock:
            builtins.print(f"\n{bar}\n# BEGIN HANDSHAKE LOG : {label}\n{bar}", flush=False)
            builtins.print(lines, end="", flush=False)
            builtins.print(f"{bar}\n# END HANDSHAKE LOG   : {label}\n{bar}\n", flush=True)
