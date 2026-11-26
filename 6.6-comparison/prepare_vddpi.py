#!/usr/bin/env python3
"""Prepare a reviewable adaptation from immutable, verified source inputs."""
import argparse
import ast
import difflib
import hashlib
import json
import shutil
import tarfile
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1]
VENDOR = IMPL / "third_party/vddpi"
ADAPTER = VENDOR / "adapter"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("nonunique source patch: " + old[:70])
    return text.replace(old, new, 1)


def replace_function(text, name, replacement):
    node = next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name)
    lines = text.splitlines(True)
    return "".join(lines[:node.lineno-1]) + replacement.rstrip() + "\n" + "".join(lines[node.end_lineno:])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = json.loads((VENDOR / "source.json").read_text())
    assert sha(VENDOR / "upstream.tar.gz") == source["archive_sha256"]
    upstream = out / "upstream"
    upstream.mkdir()
    with tarfile.open(VENDOR / "upstream.tar.gz") as archive:
        for member in archive:
            parts = Path(member.name).parts[1:]
            if not parts:
                continue
            if member.issym() or member.islnk() or ".." in parts:
                raise ValueError("unexpected archive entry")
            destination = upstream.joinpath(*parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.extractfile(member).read())
                destination.chmod(member.mode)
    for name, meta in source["files"].items():
        assert sha(upstream / name) == meta["sha256"], name
    app = out / "app"
    code = app / "code"
    code.mkdir(parents=True)
    patches = out / "patches"
    patches.mkdir()

    def record_patch(name, before, after, path):
        (patches / name).write_text("".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                    fromfile="a/" + path, tofile="b/" + path)))

    original = (upstream / "docker/gramine_consumer/code_eval_02/main.py").read_text()
    fixed = replace_once(original, "import ast\n", "import ast\nimport base64\n")
    fixed = replace_once(fixed, 'DUMMY_CERT = "./code/dummy.pem"', 'DUMMY_CERT = "./certs/server.pem"')
    fixed = replace_once(fixed, 'DUMMY_KEY = "./code/dummy.key"', 'DUMMY_KEY = "./certs/server.key"')
    fixed = replace_function(fixed, "check_condition_phase", '''def check_condition_phase(usage_condition):
    counter = usage_condition["counter"]
    if counter != "":
        if not isinstance(counter, str) or not counter.isdigit() or int(counter) <= 0:
            return False, 1
    ok, status = check_expiration_date(usage_condition)
    if not ok:
        return False, status
    ok, status = check_location(usage_condition)
    if not ok:
        return False, status
    return True, 0
''')
    fixed = replace_once(fixed, '            print("Failed to load cached data due to invalid client CN.")',
                         '            raise PermissionError("cached data belongs to another client")\n'
                         '        if cached_data["path"] != file_path:\n'
                         '            raise PermissionError("cached path does not match request")')
    fixed = replace_once(fixed, '    data["clientCN"] = client_cn', '    data["clientCN"] = received_cert_cn')
    fixed = replace_once(fixed, '    for ext in cert.extensions:',
                         '    identity_found = False\n    for ext in client_cert.extensions:')
    fixed = replace_once(fixed, 'if (ext.value.oid.dotted_string == "1.2.3.5"):',
                         'if (ext.oid.dotted_string == "1.2.3.5"):')
    fixed = replace_once(fixed, '            MRENCLAVE = base64.b64decode(report["isvEnclaveQuoteBody"])[112:144].hex()',
                         '            quote = base64.b64decode(report["isvEnclaveQuoteBody"], validate=True)\n'
                         '            if len(quote) < 144:\n                raise RuntimeError("truncated identity report")\n'
                         '            MRENCLAVE = quote[112:144].hex()')
    fixed = replace_once(fixed, '                break\n    \n    return payload',
                         '                identity_found = True\n                break\n'
                         '    if not identity_found:\n        raise RuntimeError("missing application identity")\n'
                         '    return payload')
    start = fixed.index('    providers = []\n', fixed.index('def request('))
    end = fixed.index('    provided_data_uc = []', start)
    fixed = fixed[:start] + '''    providers = []
    for line in tokens.splitlines():
        if not line:
            raise ValueError("empty token line")
        token, cert = line.split(",", 1)
        providers.append(verify_token(token, cert))
    if not providers:
        raise ValueError("no authorized inputs")

''' + fixed[end:]
    fixed = replace_once(fixed, '                print("Failed to receive data: " + usage_statement["data_ID"])\n                tls_socket.send("Failed to receive data".encode())\n                continue',
                         '                raise RuntimeError("failed to receive authorized input")')
    start = fixed.index('        if (not is_ok):', fixed.index('def request('))
    end = fixed.index('        else:', start)
    fixed = fixed[:start] + '''        if (not is_ok):
            if is_expired == 0:
                remove_data(provided_data_uc[-1])
            raise PermissionError("usage condition is not met")
''' + fixed[end:]
    fixed = replace_once(fixed, '                print("Invalid argument number.")\n                tls_socket.send("Invalid argument number".encode())\n                continue',
                         '                raise ValueError("invalid argument number")')
    fixed = replace_function(fixed, "remove_data", '''def remove_data(data):
    os.remove(data["path"])
''')
    record_patch("01-correctness.patch", original, fixed, "docker/gramine_consumer/code_eval_02/main.py")

    measured = replace_once(fixed, "import plib\n", "import plib\nfrom measurement import now_ns\nLAST_MEASUREMENT = None\n")
    measured = replace_once(measured, '    start = datetime.now()', '    start = datetime.now()\n    begin_ns = now_ns()')
    measured = replace_once(measured, '    start_process_data = datetime.now()',
                             '    input_done_ns = now_ns()\n    start_process_data = datetime.now()')
    measured = replace_once(measured, '        tls_socket.send(processed_data.encode())',
                             '        payload = processed_data.encode()\n'
                             '        if tls_socket.send(payload) != len(payload):\n'
                             '            raise RuntimeError("incomplete protected result")\n'
                             '        protected_done_ns = now_ns()')
    measured = replace_once(measured, '    end = datetime.now()', '''    end = datetime.now()
    global LAST_MEASUREMENT
    LAST_MEASUREMENT = {
        "begin_ns": begin_ns, "input_done_ns": input_done_ns,
        "protected_done_ns": protected_done_ns, "cleanup_done_ns": now_ns(),
        "processing_ns": protected_done_ns - begin_ns,
        "cached": cached,
    }''')
    record_patch("02-timing.patch", fixed, measured, "docker/gramine_consumer/code_eval_02/main.py")
    ast.parse(measured)
    (code / "main.py").write_text(measured)
    # The upstream format checker expects a two-line placeholder body in its
    # registered template, not the concrete multi-line application body.
    template_source = replace_function(measured, "process_data", 'def process_data(svm_1):\n    return ""\n')
    (out / "registered-template.py").write_text(template_source)
    oldlib = (upstream / "docker/gramine_consumer/code_eval_02/plib.py").read_text()
    newlib = (ADAPTER / "plib.py").read_text()
    record_patch("03-task.patch", oldlib, newlib, "docker/gramine_consumer/code_eval_02/plib.py")
    for name in ("plib.py", "measurement.py", "bio_transport.py", "bench.py"):
        if (ADAPTER / name).exists():
            shutil.copy2(ADAPTER / name, code / name)
    shutil.copy2(upstream / "docker/gramine_base/gramine-python/gen_cert.py", app / "gen_cert.py")

    core = out / "common"
    core.mkdir()
    hashes = json.loads((ADAPTER / "common/source-hashes.json").read_text())
    common_manifest = {}
    for name in ("svm.cpp", "svm.h", "svm_task.cpp", "svm_task.h", "transform.hpp"):
        rel = "work2-source/pkg/svmpilot/" + name
        assert sha(ADAPTER / "common" / name) == hashes[rel], rel
        shutil.copy2(ADAPTER / "common" / name, core / name)
        common_manifest[name] = hashes[rel]
    shutil.copy2(ADAPTER / "common/COPYRIGHT", core / "COPYRIGHT")
    shutil.copy2(ADAPTER / "measurement.cpp", core / "measurement.cpp")
    (out / "common-source.json").write_text(json.dumps(common_manifest, indent=2) + "\n")

    original_c = (upstream / "docker/gramine_base/python.c").read_text()
    prefix = original_c[:original_c.index('#ifdef __FreeBSD__')]
    suffix = original_c[original_c.index('int call_Py_Main(int argc, char **argv) {'):]
    suffix = suffix.replace('int call_Py_Main(', 'static int call_Py_Main(', 1)
    fixed_c = prefix + (ADAPTER / "interpreter_main.c").read_text() + "\n" + suffix
    (out / "python.c.template").write_text(fixed_c)
    record_patch("04-interpreter.patch", original_c, fixed_c, "docker/gramine_base/python.c")
    registry = {
        "upstream_commit": source["commit"], "template_sha256": sha(out / "registered-template.py"),
        "application_sha256": sha(code / "main.py"),
        "registered_function": "run_svm", "library_sha256": sha(code / "plib.py"),
        "input": {"svm_1": {"data": "complete Adult record lines"}},
        "output": ["count", "support_vectors", "training_correct", "rho"],
        "raw_source_fields_returned": [], "aggregate_information_is_disclosed": True,
        "approval_status": "research fixture; no Fabric registration or full Pysa pipeline claimed",
        "common_core": common_manifest,
    }
    (out / "registration.json").write_text(json.dumps(registry, indent=2) + "\n")
    print(json.dumps({"out": str(out), "upstream_files": len(source["files"]), "common_core_identical": True}))


if __name__ == "__main__":
    main()
