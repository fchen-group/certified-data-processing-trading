#!/usr/bin/env python3
"""Check local registration coherence; not a Fabric/Pysa audit certificate."""
import argparse
import ast
import hashlib
import json
import re
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("prepared", type=Path)
    p.add_argument("output", type=Path)
    args = p.parse_args()
    root = args.prepared.resolve()
    template = root / "registered-template.py"
    source = (root / "app/code/main.py").read_text()
    registration = json.loads((root / "registration.json").read_text())
    assert sha(template) == registration["template_sha256"]
    assert sha(root / "app/code/main.py") == registration["application_sha256"]
    assert sha(root / "app/code/plib.py") == registration["library_sha256"]
    upstream = root / "upstream/docker/analyzer/analyzer"
    names = {"read_programfile", "check_format"}
    tree = ast.parse((upstream / "analyzer.py").read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    ns = {"re": re, "TEMPLATE_PROGRAM": str(template)}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "upstream-format-checker", "exec"), ns)
    normalized = ns["read_programfile"](file_path=str(template))
    ns["PROCESS_LINE_NUM"] = next(i for i, line in enumerate(normalized) if line.startswith("def process_data("))
    ns["END_LINE_NUM"] = len(normalized) - 1
    assert ns["check_format"](source) == (0, ["svm_1"])
    assert ns["check_format"](source.replace('cached = False', 'cached = True', 1))[0] == 1
    # Execute the author's metadata parser unchanged against the new library.
    pn = {}
    exec(compile((upstream / "policy.py").read_text(), "upstream-policy", "exec"), pn)
    pn["PLIB_PATH"] = str(root / "app/code/plib.py")
    spec = pn["FunctionSpec"].get_function_spec()
    assert list(spec) == ["run_svm"]
    assert spec["run_svm"].args == ["data"]
    process = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "process_data")
    calls = [n.func for n in ast.walk(process) if isinstance(n, ast.Call)]
    assert len(calls) == 1 and isinstance(calls[0], ast.Attribute)
    assert isinstance(calls[0].value, ast.Name) and calls[0].value.id == "plib" and calls[0].attr in spec
    result = {"upstream_format_check": "passed", "outside_task_tamper": "rejected",
              "format_checker_indices": {"PROCESS_LINE_NUM": ns["PROCESS_LINE_NUM"], "END_LINE_NUM": ns["END_LINE_NUM"]},
              "registered_functions": list(spec), "raw_field_annotation": spec["run_svm"].returns,
              "aggregate_outputs": registration["output"], "full_pysa_executed": False,
              "fabric_registration_completed": False, "application_sha256": registration["application_sha256"]}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
