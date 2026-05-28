import boto3
import json
import logging
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s"
)
logger = logging.getLogger(__name__)


def get_s3_client():
    """Return a boto3 S3 client. Credentials come from the environment
    (AWS CLI profile, IAM role on EC2, or env vars) — never hardcoded."""
    return boto3.client("s3")


def list_buckets(s3):
    """Return a list of all bucket names in the account."""
    response = s3.list_buckets()
    return [b["Name"] for b in response.get("Buckets", [])]


def check_public_access_block(s3, bucket_name):
    """
    Check whether the S3 Block Public Access settings are fully enabled.

    AWS gives you four individual toggles. A bucket is only truly locked
    down when ALL FOUR are True. If even one is False (or the config is
    missing entirely), a policy or ACL could expose data publicly.

    Returns a dict: {setting_name: bool}
    """
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        config = resp["PublicAccessBlockConfiguration"]
        return {
            "BlockPublicAcls":       config.get("BlockPublicAcls", False),
            "IgnorePublicAcls":      config.get("IgnorePublicAcls", False),
            "BlockPublicPolicy":     config.get("BlockPublicPolicy", False),
            "RestrictPublicBuckets": config.get("RestrictPublicBuckets", False),
        }
    except ClientError as e:
        # NoSuchPublicAccessBlockConfiguration → no block config set at all
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return {
                "BlockPublicAcls":       False,
                "IgnorePublicAcls":      False,
                "BlockPublicPolicy":     False,
                "RestrictPublicBuckets": False,
            }
        raise   # re-raise anything unexpected


def check_bucket_acl(s3, bucket_name):
    """
    Check whether the bucket ACL grants access to AllUsers or
    AuthenticatedUsers (both are effectively public in different ways).

    ACLs are the older, grant-based access model. Even with Block Public
    Access enabled, understanding ACLs is part of a thorough audit.
    """
    risky_grantees = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
    try:
        resp = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in resp.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("URI") in risky_grantees:
                return True     # public ACL found
        return False
    except ClientError:
        return False            # access denied → not our bucket to judge here


def check_bucket_policy_public(s3, bucket_name):
    """
    Fetch the bucket policy and look for statements that allow any
    principal ('*') with no conditions — the classic 'oops, anyone can
    read this' misconfiguration.
    """
    try:
        resp = s3.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(resp["Policy"])
        for statement in policy.get("Statement", []):
            if (
                statement.get("Effect") == "Allow"
                and statement.get("Principal") == "*"
                and not statement.get("Condition")   # no condition = truly open
            ):
                return True
        return False
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchBucketPolicy", "AccessDenied"):
            return False
        raise


def check_encryption(s3, bucket_name):
    """
    Check whether Server-Side Encryption (SSE) is configured.
    Without SSE, data at rest is unencrypted — a common compliance gap.
    """
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return True     # config exists → encryption is on
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return False
        raise


def check_versioning(s3, bucket_name):
    """Versioning protects against accidental deletes and ransomware."""
    try:
        resp = s3.get_bucket_versioning(Bucket=bucket_name)
        return resp.get("Status") == "Enabled"
    except ClientError:
        return False


def audit_bucket(s3, bucket_name):
    """
    Run all checks for a single bucket and return a structured finding dict.
    severity is set here so the report consumer can filter/alert on it.
    """
    logger.info(f"Auditing bucket: {bucket_name}")

    public_access_block = check_public_access_block(s3, bucket_name)
    all_blocked         = all(public_access_block.values())
    acl_public          = check_bucket_acl(s3, bucket_name)
    policy_public       = check_bucket_policy_public(s3, bucket_name)
    encrypted           = check_encryption(s3, bucket_name)
    versioned           = check_versioning(s3, bucket_name)

    # Severity logic:
    #   CRITICAL  → public ACL or open policy (data is actually exposed now)
    #   HIGH      → Block Public Access not fully enabled (one misconfiguration away)
    #   MEDIUM    → encryption or versioning missing
    #   OK        → everything clean
    issues = []
    if acl_public:
        issues.append("PUBLIC_ACL")
    if policy_public:
        issues.append("PUBLIC_POLICY")
    if not all_blocked:
        issues.append("BLOCK_PUBLIC_ACCESS_INCOMPLETE")
    if not encrypted:
        issues.append("NO_ENCRYPTION")
    if not versioned:
        issues.append("VERSIONING_DISABLED")

    if "PUBLIC_ACL" in issues or "PUBLIC_POLICY" in issues:
        severity = "CRITICAL"
    elif "BLOCK_PUBLIC_ACCESS_INCOMPLETE" in issues:
        severity = "HIGH"
    elif issues:
        severity = "MEDIUM"
    else:
        severity = "OK"

    return {
        "bucket_name":          bucket_name,
        "severity":             severity,
        "issues":               issues,
        "public_access_block":  public_access_block,
        "acl_public":           acl_public,
        "policy_public":        policy_public,
        "encrypted":            encrypted,
        "versioning_enabled":   versioned,
    }


def run_s3_audit():
    """
    Entry point. Audits every bucket and writes a JSON report to reports/.
    Returns the full findings list so the M4 wrapper can aggregate it.
    """
    s3      = get_s3_client()
    buckets = list_buckets(s3)
    logger.info(f"Found {len(buckets)} bucket(s)")

    findings = [audit_bucket(s3, name) for name in buckets]

    # ── Summary counters ──────────────────────────────────────────────────────
    summary = {
        "total_buckets": len(findings),
        "critical":      sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high":          sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium":        sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "ok":            sum(1 for f in findings if f["severity"] == "OK"),
    }

    report = {
        "audit_type":  "S3",
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "summary":     summary,
        "findings":    findings,
    }

    # ── Write report ──────────────────────────────────────────────────────────
    ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/s3_audit_{ts}.json"

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Report written → {report_path}")
    logger.info(f"Summary: {summary}")

    return report      # M4 will use this return value


if __name__ == "__main__":
    run_s3_audit()

