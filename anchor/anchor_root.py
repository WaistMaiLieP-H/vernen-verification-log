#!/usr/bin/env python3
"""
Vernen Verification — Base L2 Anchor

Posts a daily Merkle root from the verification log to the Base blockchain
as a self-send transaction. The 32-byte root rides in the tx `data` field,
permanently anchored in Base's block history.

Once landed, the root is verifiable by anyone via basescan.org without any
trust in Vernen, GitHub, or any centralized service.

Usage:
    export ANCHOR_PRIVATE_KEY="0x..."          # required, never commit
    python anchor_root.py                       # anchors latest root
    python anchor_root.py 2026/04/07.json       # anchors a specific root file
    python anchor_root.py --dry-run             # builds + prints, does not send

The private key is read from env only. It is never written to disk, logged,
or echoed. Suggested workflow: `read -s ANCHOR_PRIVATE_KEY; export ANCHOR_PRIVATE_KEY`
so the key never appears in shell history.
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

from eth_account import Account
from eth_account._utils.legacy_transactions import Transaction
from eth_utils import to_hex, to_bytes

REPO_ROOT = Path(__file__).resolve().parent.parent
BASE_RPC = os.environ.get("BASE_RPC", "https://base.publicnode.com")
BASE_CHAIN_ID = 8453
EXPECTED_FROM = "0x8c514af69ffdd2221946cD5E0e712d82cBf17E11"


def rpc(method: str, params: list):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        BASE_RPC,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "vernen-anchor/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
    if "error" in result:
        raise RuntimeError(f"RPC error: {result['error']}")
    return result["result"]


def find_latest_root() -> Path:
    candidates = sorted(REPO_ROOT.glob("[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9].json"))
    if not candidates:
        raise FileNotFoundError("No daily root files found in repo")
    return candidates[-1]


def main():
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]

    if args:
        root_path = REPO_ROOT / args[0]
    else:
        root_path = find_latest_root()

    if not root_path.exists():
        print(f"error: root file not found: {root_path}", file=sys.stderr)
        sys.exit(1)

    root_doc = json.loads(root_path.read_text())
    merkle_root = root_doc["merkle_root"]
    if not (len(merkle_root) == 64 and all(c in "0123456789abcdefABCDEF" for c in merkle_root)):
        print(f"error: merkle_root in {root_path} is not 32-byte hex", file=sys.stderr)
        sys.exit(1)

    print(f"Anchoring root from: {root_path.relative_to(REPO_ROOT)}")
    print(f"  date:         {root_doc['date']}")
    print(f"  record_count: {root_doc['record_count']}")
    print(f"  merkle_root:  0x{merkle_root}")
    print()

    pk = os.environ.get("ANCHOR_PRIVATE_KEY")
    if not pk and not dry_run:
        print("error: ANCHOR_PRIVATE_KEY env var not set", file=sys.stderr)
        print("  set with: read -s ANCHOR_PRIVATE_KEY; export ANCHOR_PRIVATE_KEY", file=sys.stderr)
        sys.exit(1)

    if pk:
        acct = Account.from_key(pk)
        if acct.address.lower() != EXPECTED_FROM.lower():
            print(f"error: key derives {acct.address}, expected {EXPECTED_FROM}", file=sys.stderr)
            sys.exit(1)
        from_addr = acct.address
    else:
        from_addr = EXPECTED_FROM

    nonce = int(rpc("eth_getTransactionCount", [from_addr, "pending"]), 16)
    base_fee_hex = rpc("eth_gasPrice", [])
    gas_price = int(base_fee_hex, 16)
    max_fee = gas_price * 2
    max_priority = min(gas_price, 1_000_000)
    data = "0x" + merkle_root

    tx = {
        "type": 2,
        "chainId": BASE_CHAIN_ID,
        "nonce": nonce,
        "to": from_addr,
        "value": 0,
        "data": data,
        "gas": 30_000,
        "maxFeePerGas": max_fee,
        "maxPriorityFeePerGas": max_priority,
    }

    cost_wei = tx["gas"] * max_fee
    cost_eth = cost_wei / 10**18
    print(f"Built tx:")
    print(f"  from:                {from_addr}")
    print(f"  to (self):           {tx['to']}")
    print(f"  nonce:               {nonce}")
    print(f"  gas:                 {tx['gas']}")
    print(f"  maxFeePerGas:        {max_fee} wei ({max_fee / 1e9:.4f} gwei)")
    print(f"  maxPriorityFeePerGas:{max_priority} wei")
    print(f"  data:                {data}")
    print(f"  est. max cost:       {cost_eth:.8f} ETH")
    print()

    if dry_run:
        print("[dry-run] not sending. Re-run without --dry-run to broadcast.")
        return

    bal_hex = rpc("eth_getBalance", [from_addr, "latest"])
    bal_wei = int(bal_hex, 16)
    if bal_wei < cost_wei:
        print(f"error: balance {bal_wei} wei < est. cost {cost_wei} wei", file=sys.stderr)
        sys.exit(1)

    signed = acct.sign_transaction(tx)
    raw = to_hex(signed.raw_transaction)
    print("Broadcasting...")
    tx_hash = rpc("eth_sendRawTransaction", [raw])
    print()
    print(f"  tx hash:  {tx_hash}")
    print(f"  basescan: https://basescan.org/tx/{tx_hash}")
    print()
    print("Anchor submitted. Wait ~2s for confirmation, then verify on basescan.")
    print(f"The root 0x{merkle_root} is now permanently in Base block history.")

    receipt_hint = {
        "anchored_at_root": root_doc["date"],
        "merkle_root": merkle_root,
        "tx_hash": tx_hash,
        "chain": "base-mainnet",
        "chain_id": BASE_CHAIN_ID,
        "from": from_addr,
        "basescan_url": f"https://basescan.org/tx/{tx_hash}",
    }
    receipt_path = root_path.with_suffix(".anchor.json")
    receipt_path.write_text(json.dumps(receipt_hint, indent=2) + "\n")
    print(f"  receipt:  {receipt_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
