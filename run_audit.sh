#!/bin/bash

# ── Color codes for terminal output ──────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color (reset)

# ── Config ────────────────────────────────────────────────────────────────────
TIMESTAMP=$(date -u +"%Y%m%d_%H%M%S")
REPORTS_DIR="reports"
FINAL_REPORT="$REPORTS_DIR/final_report_$TIMESTAMP.json"
PYTHON=python3

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}       AWS Security Auditor — Full Scan         ${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "Started at: $(date -u)"
echo ""

# ── Helper: check if last command failed ─────────────────────────────────────
check_exit() {
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR] $1 failed. Exiting.${NC}"
        exit 1
    fi
}

# ── Run S3 Auditor ────────────────────────────────────────────────────────────
echo -e "${BLUE}[1/3] Running S3 Auditor...${NC}"
$PYTHON auditors/s3_auditor.py
check_exit "S3 Auditor"

# Grab the most recently created S3 report
S3_REPORT=$(ls -t $REPORTS_DIR/s3_audit_*.json 2>/dev/null | head -1)
if [ -z "$S3_REPORT" ]; then
    echo -e "${RED}[ERROR] No S3 report found.${NC}"
    exit 1
fi
echo -e "${GREEN}[S3] Report: $S3_REPORT${NC}"
echo ""

# ── Run IAM Auditor ───────────────────────────────────────────────────────────
echo -e "${BLUE}[2/3] Running IAM Auditor...${NC}"
$PYTHON auditors/iam_auditor.py
check_exit "IAM Auditor"

IAM_REPORT=$(ls -t $REPORTS_DIR/iam_audit_*.json 2>/dev/null | head -1)
if [ -z "$IAM_REPORT" ]; then
    echo -e "${RED}[ERROR] No IAM report found.${NC}"
    exit 1
fi
echo -e "${GREEN}[IAM] Report: $IAM_REPORT${NC}"
echo ""

# ── Run Security Group Auditor ────────────────────────────────────────────────
echo -e "${BLUE}[3/3] Running Security Group Auditor...${NC}"
$PYTHON auditors/sg_auditor.py
check_exit "Security Group Auditor"

SG_REPORT=$(ls -t $REPORTS_DIR/sg_audit_*.json 2>/dev/null | head -1)
if [ -z "$SG_REPORT" ]; then
    echo -e "${RED}[ERROR] No SG report found.${NC}"
    exit 1
fi
echo -e "${GREEN}[SG] Report: $SG_REPORT${NC}"
echo ""

# ── Combine all reports into one final report ─────────────────────────────────
echo -e "${BLUE}Combining reports into final report...${NC}"

$PYTHON << EOF
import json
from datetime import datetime, timezone

# Load individual reports
with open("$S3_REPORT")  as f: s3  = json.load(f)
with open("$IAM_REPORT") as f: iam = json.load(f)
with open("$SG_REPORT")  as f: sg  = json.load(f)

# Count total criticals across all auditors
total_critical = (
    s3["summary"]["critical"] +
    iam["summary"]["critical"] +
    sg["summary"]["critical"]
)

final = {
    "audit_type":    "FULL_AUDIT",
    "timestamp":     datetime.now(timezone.utc).isoformat(),
    "total_critical": total_critical,
    "audits": {
        "s3":              s3,
        "iam":             iam,
        "security_groups": sg,
    }
}

with open("$FINAL_REPORT", "w") as f:
    json.dump(final, f, indent=2)

print(f"Final report written → $FINAL_REPORT")
EOF

check_exit "Report combination"
echo ""

# ── Print color-coded summary ─────────────────────────────────────────────────
echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}                 AUDIT SUMMARY                 ${NC}"
echo -e "${BLUE}================================================${NC}"

# Parse and print each section using python3
python3 << EOF
import json

with open("$FINAL_REPORT") as f:
    report = json.load(f)

RED    = '\033[0;31m'
YELLOW = '\033[1;33m'
GREEN  = '\033[0;32m'
BLUE   = '\033[0;34m'
NC     = '\033[0m'

def severity_color(count):
    if count > 0:
        return RED
    return GREEN

def print_section(name, summary, keys):
    print(f"\n{BLUE}[ {name} ]{NC}")
    for k in keys:
        val = summary.get(k, 0)
        color = severity_color(val) if k in ("critical", "high") else NC
        print(f"  {k:<30} {color}{val}{NC}")

s3  = report["audits"]["s3"]["summary"]
iam = report["audits"]["iam"]["summary"]
sg  = report["audits"]["security_groups"]["summary"]

print_section("S3 Buckets", s3, [
    "total_buckets", "critical", "high", "medium", "ok"
])

print_section("IAM Users", iam, [
    "total_users", "critical", "high", "medium", "ok",
    "no_mfa", "admins", "inactive"
])

print_section("Security Groups", sg, [
    "total_security_groups", "critical", "high", "ok",
    "ssh_open", "rdp_open", "all_traffic_open"
])

total_critical = report["total_critical"]
print(f"\n{BLUE}================================================{NC}")
if total_critical > 0:
    print(f"  {RED}TOTAL CRITICAL FINDINGS: {total_critical}{NC}")
    print(f"  {RED}ACTION REQUIRED — review final report immediately{NC}")
else:
    print(f"  {GREEN}TOTAL CRITICAL FINDINGS: 0 — All clear{NC}")
print(f"{BLUE}================================================{NC}\n")
EOF

echo -e "Completed at: $(date -u)"
echo -e "${GREEN}Final report → $FINAL_REPORT${NC}"
