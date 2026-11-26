#!/usr/bin/env python3
"""Recompute D1/D2 gas statistics from verified transaction receipts, offline."""

import argparse
import hashlib
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean


NORMAL = ["registerTrade", "deposit", "confirmKey/DO", "confirmKey/DB", "settle"]
OSAKA_SCOPE = "formal local Osaka gas measurement; not a Sepolia observation"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hex_bytes(value):
    require(value.startswith("0x"), "expected hex byte string")
    return bytes.fromhex(value[2:])


def stats(values):
    return {"n": len(values), "mean": mean(values), "min": min(values), "max": max(values)}


def summarize(directory):
    files = {name: (directory / name).read_bytes() for name in ("run.json", "verification.json")}
    record, verified = (json.loads(files[name]) for name in ("run.json", "verification.json"))
    failure_path = directory / "failure.json"
    if failure_path.exists():
        files[failure_path.name] = failure_path.read_bytes()
        failure = json.loads(files[failure_path.name])
        require(failure.get("phase") == "verification", "failed transaction run cannot be summarized as complete")
        # A later successful read-only verification resolves a confirmation/RPC
        # interruption; retain the earlier failure as source evidence.
        verified_at = datetime.fromisoformat(verified["verified_utc"].replace("Z", "+00:00"))
        failed_at = datetime.fromisoformat(failure["at"].replace("Z", "+00:00"))
        require(verified_at > failed_at, "verification does not resolve the recorded failure")
    run, plan = record["run"], record["run"]["plan"]
    require(record["chain"]["development"] == verified["development"], "verification mode mismatch")
    sizes = {"D1/" + f["name"]: len(hex_bytes(f["plaintext"])) for f in plan["fixtures"]}
    sizes.update({f"D2/{size}": size for size in plan["plaintext_sizes"]})
    expected = [("preparation", 0)] if run["initial_counter"] == 0 else []
    expected += [(group, i) for group in sizes for i in range(1, plan["repeats"] + 1)]
    expected += [("refund", i) for i in range(1, plan["refunds"] + 1)]
    require([(t["group"], t["repeat"]) for t in run["trials"]] == expected, "incomplete or reordered matrix")
    require(len(verified["trials"]) == len(expected), "verification matrix mismatch")
    groups = defaultdict(list)
    seen_tx, seen_ciphertext = set(), set()
    preparation = []
    for trial, check in zip(run["trials"], verified["trials"]):
        group = trial["group"]
        for key in ("group", "repeat", "tid"):
            require(trial[key] == check[key], f"verification {key} mismatch")
        methods = (["registerTrade"] if group == "preparation" else
                   NORMAL[:4] + ["timeoutRefund"] if group == "refund" else NORMAL + ["withdraw"])
        require([s["transaction"]["method"] for s in trial["steps"]] == methods, "wrong operation sequence")
        operations = {}
        for step in trial["steps"]:
            tx, state = step["transaction"], step["state_after"]
            receipt = tx["receipt"]
            require(int(receipt["status"], 16) == 1, "unsuccessful transaction")
            require(receipt["transactionHash"] not in seen_tx, "duplicate transaction")
            seen_tx.add(receipt["transactionHash"])
            require(state["block"] == int(receipt["blockNumber"], 16), "state block mismatch")
            require(state["block_hash"] == receipt["blockHash"], "state block hash mismatch")
            require(state["block"] <= verified["anchor_number"], "transaction newer than verification anchor")
            operations[tx["method"]] = int(receipt["gasUsed"], 16)
        require(operations == check["operation_gas"], "receipt gas differs from chain verification")
        total = sum(operations[m] for m in NORMAL) if group in sizes else 0
        require(total == check["normal_five_call_gas"], "five-call total mismatch")
        if group == "preparation":
            preparation.append({"tid": trial["tid"], "register_gas": operations["registerTrade"]})
            continue
        if group in sizes:
            cipher = hex_bytes(trial["ciphertext"])
            require(cipher not in seen_ciphertext, "reused result ciphertext")
            seen_ciphertext.add(cipher)
            require(len(cipher) == sizes[group] + 48 == check["ciphertext_bytes"], "ciphertext length mismatch")
            require(sizes[group] == check["plaintext_bytes"], "plaintext length mismatch")
            # Four ABI heads; dynamic ciphertext and signature each have a length word.
            calldata = 4 + 4 * 32 + 32 + ((len(cipher) + 31) // 32) * 32 + 32 + 96
            require(calldata == check["settlement_calldata_bytes"] <= 120 * 1024, "calldata length mismatch")
            require(trial["steps"][4]["state_after"]["owner_credit_wei"] == plan["price_wei"], "wrong settlement credit")
            require(trial["steps"][5]["state_after"]["owner_credit_wei"] == "0", "withdrawal did not restore zero credit")
        groups[group].append(check)
    require(len(seen_tx) == verified["transactions"], "transaction count mismatch")
    result = {
        "scope": "local Anvil precheck" if verified["development"] else "finalized Sepolia measurement",
        "verification": "offline arithmetic audit of receipts; chain checks and decryption are performed by tradegasbench",
        "source_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
        "transactions": len(seen_tx), "unique_ciphertexts": len(seen_ciphertext),
        "counter_preparation": preparation, "groups": {},
    }
    for group, trials in groups.items():
        item = {"samples": len(trials), "operations_gas": {
            operation: stats([t["operation_gas"][operation] for t in trials])
            for operation in trials[0]["operation_gas"]}}
        if group in sizes:
            item.update({"plaintext_bytes": sizes[group], "ciphertext_bytes": sizes[group] + 48,
                         "settlement_calldata_bytes": trials[0]["settlement_calldata_bytes"],
                         "normal_five_call_gas": stats([t["normal_five_call_gas"] for t in trials])})
        result["groups"][group] = item
    # Deployment is optional evidence, outside the measured five-call paths.
    setup = directory / "setup-receipts.json"
    if setup.exists():
        data = setup.read_bytes()
        result["source_sha256"][setup.name] = hashlib.sha256(data).hexdigest()
        deployments = [r for r in json.loads(data) if r.get("contractAddress", "").lower() == record["chain"]["contract"].lower()]
        require(len(deployments) == 1 and int(deployments[0]["status"], 16) == 1, "invalid deployment evidence")
        result["deployment_gas"] = int(deployments[0]["gasUsed"], 16)
    return result


def summarize_measurement(directory, *, require_formal=False):
    """Classify formal local measurements only after checking frozen evidence.

    Keep summarize() as the receipt-only arithmetic entry used by the original
    measurement scripts. Both the CLI and plotting use this evidence-aware entry.
    """
    directory = directory.resolve()
    checked = summarize(directory)
    evidence = {}
    if checked["scope"] == "local Anvil precheck":
        root = directory.parent
        formal_path, saved_path = root / "summary.json", directory / "summary.json"
        formal = json.loads(formal_path.read_text()) if formal_path.exists() else {}
        saved = json.loads(saved_path.read_text()) if saved_path.exists() else {}
        claimed_formal = (formal.get("status") == "formal_measurement_verified" or
                          saved.get("scope") == OSAKA_SCOPE)
        if require_formal or claimed_formal:
            manifest_path = root / "SHA256SUMS.json"
            manifest = json.loads(manifest_path.read_text())
            required = {"summary.json", "environment.json", "independent-replay.json"}
            required.update(str((directory / name).relative_to(root))
                            for name in {*checked["source_sha256"], "summary.json"})
            require(required <= manifest.keys(), "formal evidence manifest is incomplete")
            for name, digest in manifest.items():
                require(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest,
                        f"formal evidence checksum mismatch: {name}")
            environment = json.loads((root / "environment.json").read_text())
            replay = json.loads((root / "independent-replay.json").read_text())
            require(formal.get("status") == "formal_measurement_verified", "completed formal run required")
            require(environment["node_info"]["hardFork"] == "Osaka", "fixed Osaka rules required")
            rules = [r for r in replay["rules"] if r["rule"] == "Osaka"]
            require(len(rules) == 1, "one independent Osaka replay required")
            osaka = rules[0]
            require(osaka["receipts_matched"] == osaka["transactions"] == formal["checks"]["transactions_verified"],
                    "independent replay does not cover all transactions")
            checked.update(scope=OSAKA_SCOPE, execution_rule="Osaka")
            require(formal["trade"] == checked, "formal aggregate differs from receipt recomputation")
            require(saved == checked, "saved summary differs from independent recomputation")
            evidence = {"formal_run": str(root), "execution_rule": "Osaka",
                        "evidence_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                        "independent_replay_sha256": hashlib.sha256((root / "independent-replay.json").read_bytes()).hexdigest()}
    else:
        require(checked["scope"] == "finalized Sepolia measurement", "verified measurement required")
    return checked, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, help="completed run directory")
    args = parser.parse_args()
    result, _ = summarize_measurement(args.run)
    output = args.run / "summary.json"
    encoded = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if output.exists():
        require(json.loads(output.read_text()) == result, "existing summary differs; refusing to overwrite")
    else:
        with output.open("x") as stream:
            stream.write(encoded)
    print(f"Validated {result['transactions']} transactions, {result['unique_ciphertexts']} fresh ciphertexts: {output}")


if __name__ == "__main__":
    main()
