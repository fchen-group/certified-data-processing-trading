"""Registered aggregate workload; native core is shared with the other systems."""
import ctypes
import os

_core = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "libcommon_svm.so"))
_core.work2_svm_summary.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_size_t]
_core.work2_svm_summary.restype = ctypes.c_int


# Output:
def run_svm(data):
    # No raw source field is returned. Aggregate output fields are recorded in
    # registration.json; this is not a claim of zero information disclosure.
    raw = data["data"].encode("ascii")
    result = ctypes.create_string_buffer(512)
    length = _core.work2_svm_summary(raw, len(raw), result, len(result))
    if length <= 0 or length >= len(result):
        raise ValueError("common SVM task rejected input: {}".format(length))
    return result.raw[:length].decode("ascii")
