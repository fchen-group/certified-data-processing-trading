"""Sampling only; no simulated cryptography or estimated phase subtraction."""
import ctypes
import os

_lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "libcommon_svm.so"))
_lib.vddpi_clock_ns.argtypes = []
_lib.vddpi_clock_ns.restype = ctypes.c_uint64


def now_ns():
    value = _lib.vddpi_clock_ns()
    if not value:
        raise RuntimeError("CLOCK_MONOTONIC_RAW failed")
    return value
