"""Ad-hoc: count event IDs in the Security channel archives on the device."""
import collections
import json
import sys
from pathlib import Path

archive_root = Path("/media/ubuntu/GRTMPVOL_EN/NIELSOLN_RESCUE_USB/event_archive")
counts: collections.Counter = collections.Counter()
total = 0

for jsonl in archive_root.rglob("*.jsonl"):
    for line in jsonl.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get("channel") == "Security":
            counts[ev.get("event_id", "?")] += 1
            total += 1

print(f"Total Security events in archive: {total}")
print(f"{'Event ID':>12}  {'Count':>8}  Description")
print("-" * 50)
names = {
    4624: "Successful logon",
    4625: "Failed logon",
    4634: "Logoff",
    4647: "User initiated logoff",
    4648: "Explicit credentials logon",
    4672: "Special privileges assigned",
    4688: "Process created",
    4720: "Account created",
    4723: "Password change attempt",
    4724: "Password reset",
    4740: "Account locked out",
}
for eid, cnt in counts.most_common(25):
    print(f"{eid:>12}  {cnt:>8}  {names.get(eid, '')}")
