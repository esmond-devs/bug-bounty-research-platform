"""CLI for authorized scope-first research."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from bbplatform.core import Policy, PolicyError, run

parser = argparse.ArgumentParser()
parser.add_argument("--policy", required=True)
parser.add_argument("--targets", required=True)
parser.add_argument("--output", default="results.json")
parser.add_argument("--active", action="store_true")
parser.add_argument("--approval-db", default="state/approvals.sqlite3")
parser.add_argument("--approval-id", type=int)
args = parser.parse_args()
try:
    policy = Policy.from_file(args.policy)
    from bbplatform.approvals import connect
    db = connect(args.approval_db) if args.active else None
    if args.active and args.approval_id is None:
        raise PolicyError("--approval-id required for active checks")
    results = run(policy, Path(args.targets).read_text().splitlines(), args.active, db, args.approval_id)
    report = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "mode": "approved_http" if args.active else "scope_only", "results": results}
    Path(args.output).write_text(json.dumps(report, indent=2))
    print("Saved", len(results), "records to", args.output)
except (PolicyError, ValueError, KeyError) as exc:
    parser.error(str(exc))
