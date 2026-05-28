import boto3
import json
import logging
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s"
)
logger = logging.getLogger(__name__)

# Ports that are critical if exposed to the internet
CRITICAL_PORTS = {
    22:   "SSH",
    3389: "RDP",
}

# CIDRs that mean "entire internet"
PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}  # IPv4 and IPv6


def get_ec2_client():
    return boto3.client("ec2")


def is_public_cidr(cidr):
    """Return True if the CIDR represents the entire internet."""
    return cidr in PUBLIC_CIDRS


def analyze_rule(rule):
    """
    Analyze a single inbound rule and return a list of findings.

    Each rule can have multiple IP ranges, so we check each one.
    A rule with IpProtocol = -1 means ALL traffic is allowed.

    Returns a list of dicts describing each risky range found.
    """
    findings = []

    from_port  = rule.get("FromPort", 0)
    to_port    = rule.get("ToPort", 65535)
    protocol   = rule.get("IpProtocol", "")

    # Collect all CIDRs from this rule (IPv4 + IPv6)
    ip_ranges  = [r["CidrIp"]   for r in rule.get("IpRanges", [])]
    ip_ranges += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]

    for cidr in ip_ranges:
        if not is_public_cidr(cidr):
            continue    # restricted to specific IP — not a risk

        # All traffic open to internet
        if protocol == "-1":
            findings.append({
                "type":      "ALL_TRAFFIC_OPEN",
                "protocol":  "all",
                "port_range": "all",
                "cidr":      cidr,
                "severity":  "CRITICAL",
            })
            continue

        # Check if any critical port falls within this rule's port range
        for port, service in CRITICAL_PORTS.items():
            if from_port <= port <= to_port:
                findings.append({
                    "type":       f"{service}_OPEN",
                    "protocol":   protocol,
                    "port_range": f"{from_port}-{to_port}",
                    "cidr":       cidr,
                    "severity":   "CRITICAL",
                })

        # Any other port open to internet — HIGH, not CRITICAL
        # but only if we haven't already flagged it above
        already_flagged_ports = [f["port_range"] for f in findings]
        port_range_str = f"{from_port}-{to_port}"
        if port_range_str not in already_flagged_ports:
            findings.append({
                "type":       "PORT_OPEN_TO_INTERNET",
                "protocol":   protocol,
                "port_range": port_range_str,
                "cidr":       cidr,
                "severity":   "HIGH",
            })

    return findings


def audit_security_group(sg):
    """
    Audit a single security group — check all its inbound rules.
    Outbound rules are not checked (outbound is usually unrestricted by design).
    """
    sg_id   = sg["GroupId"]
    sg_name = sg["GroupName"]
    vpc_id  = sg.get("VpcId", "no-vpc")

    logger.info(f"Auditing security group: {sg_id} ({sg_name})")

    all_rule_findings = []
    for rule in sg.get("IpPermissions", []):     # IpPermissions = inbound rules
        rule_findings = analyze_rule(rule)
        all_rule_findings.extend(rule_findings)

    issues = list({f["type"] for f in all_rule_findings})   # deduplicated

    # Severity: CRITICAL if any rule finding is critical, HIGH otherwise
    if any(f["severity"] == "CRITICAL" for f in all_rule_findings):
        severity = "CRITICAL"
    elif all_rule_findings:
        severity = "HIGH"
    else:
        severity = "OK"

    return {
        "sg_id":         sg_id,
        "sg_name":       sg_name,
        "vpc_id":        vpc_id,
        "severity":      severity,
        "issues":        issues,
        "risky_rules":   all_rule_findings,
        "total_inbound_rules": len(sg.get("IpPermissions", [])),
    }


def run_sg_audit():
    """
    Entry point. Fetches all security groups and audits each one.
    Returns the full report dict for M4 aggregation.
    """
    ec2 = get_ec2_client()

    try:
        resp = ec2.describe_security_groups()
        security_groups = resp["SecurityGroups"]
    except ClientError as e:
        logger.error(f"Failed to fetch security groups: {e}")
        raise

    logger.info(f"Found {len(security_groups)} security group(s)")

    findings = [audit_security_group(sg) for sg in security_groups]

    summary = {
        "total_security_groups": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high":     sum(1 for f in findings if f["severity"] == "HIGH"),
        "ok":       sum(1 for f in findings if f["severity"] == "OK"),
        "ssh_open": sum(1 for f in findings if "SSH_OPEN" in f["issues"]),
        "rdp_open": sum(1 for f in findings if "RDP_OPEN" in f["issues"]),
        "all_traffic_open": sum(
            1 for f in findings if "ALL_TRAFFIC_OPEN" in f["issues"]
        ),
    }

    report = {
        "audit_type": "SECURITY_GROUPS",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "summary":    summary,
        "findings":   findings,
    }

    ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/sg_audit_{ts}.json"

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info(f"Report written → {report_path}")
    logger.info(f"Summary: {summary}")

    return report


if __name__ == "__main__":
    run_sg_audit()
