import boto3
import json
import logging
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s"
)
logger = logging.getLogger(__name__)

INACTIVE_DAYS_THRESHOLD = 90   # flag users with no login beyond this


def get_iam_client():
    return boto3.client("iam")


# ── Per-user checks ───────────────────────────────────────────────────────────

def check_mfa(iam, username):
    """
    MFA is required for any human IAM user.
    Without it, a stolen password = full account access.
    Returns True if at least one MFA device is registered.
    """
    try:
        resp = iam.list_mfa_devices(UserName=username)
        return len(resp["MFADevices"]) > 0
    except ClientError:
        return False


def check_admin_privileges(iam, username):
    """
    Check for admin access via two paths:
      1. Directly attached policies (e.g. AdministratorAccess attached to the user)
      2. Group memberships → policies attached to those groups

    We flag AdministratorAccess by ARN AND any inline/managed policy
    whose name contains 'admin' (case-insensitive) as a belt-and-suspenders check.
    """
    admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"

    # Path 1 — directly attached managed policies
    try:
        attached = iam.list_attached_user_policies(UserName=username)
        for policy in attached["AttachedPolicies"]:
            if (policy["PolicyArn"] == admin_policy_arn or
                    "admin" in policy["PolicyName"].lower()):
                return True
    except ClientError:
        pass

    # Path 2 — policies inherited through groups
    try:
        groups = iam.list_groups_for_user(UserName=username)
        for group in groups["Groups"]:
            group_policies = iam.list_attached_group_policies(
                GroupName=group["GroupName"]
            )
            for policy in group_policies["AttachedPolicies"]:
                if (policy["PolicyArn"] == admin_policy_arn or
                        "admin" in policy["PolicyName"].lower()):
                    return True
    except ClientError:
        pass

    return False


def check_last_login(iam, username):
    """
    PasswordLastUsed tells us when the user last signed into the console.
    If it's None, the user has never logged in OR never had a console password.
    Both are worth flagging — either unused account or a service account
    that shouldn't have console access at all.

    Returns (days_since_login: int | None, is_inactive: bool)
    """
    try:
        resp = iam.get_user(UserName=username)
        last_used = resp["User"].get("PasswordLastUsed")

        if last_used is None:
            return None, True   # never logged in → treat as inactive

        now = datetime.now(timezone.utc)
        days = (now - last_used).days
        return days, days > INACTIVE_DAYS_THRESHOLD

    except ClientError:
        return None, False


def check_access_keys(iam, username):
    """
    List access keys for the user and flag:
      - keys that are Active but haven't been used in 90+ days (stale)
      - users with more than one active key (key rotation hygiene)

    Returns a list of dicts, one per key.
    """
    key_findings = []
    try:
        resp = iam.list_access_keys(UserName=username)
        for key in resp["AccessKeyMetadata"]:
            key_id     = key["AccessKeyId"]
            status     = key["Status"]          # "Active" or "Inactive"
            created    = key["CreateDate"]

            # When was this key last used?
            try:
                usage = iam.get_access_key_last_used(AccessKeyId=key_id)
                last_used_date = usage["AccessKeyLastUsed"].get("LastUsedDate")
            except ClientError:
                last_used_date = None

            now        = datetime.now(timezone.utc)
            days_since = (now - last_used_date).days if last_used_date else None
            stale      = (
                status == "Active" and
                (last_used_date is None or days_since > INACTIVE_DAYS_THRESHOLD)
            )

            key_findings.append({
                "key_id":           key_id,
                "status":           status,
                "created":          created.isoformat(),
                "last_used":        last_used_date.isoformat() if last_used_date else None,
                "days_since_use":   days_since,
                "stale":            stale,
            })

    except ClientError:
        pass

    return key_findings


# ── Per-user orchestrator ─────────────────────────────────────────────────────

def audit_user(iam, user):
    """Run all checks for a single IAM user and return a finding dict."""
    username = user["UserId"]
    username = user["UserName"]
    logger.info(f"Auditing IAM user: {username}")

    mfa_enabled    = check_mfa(iam, username)
    is_admin       = check_admin_privileges(iam, username)
    days_since, is_inactive = check_last_login(iam, username)
    access_keys    = check_access_keys(iam, username)

    stale_keys     = [k for k in access_keys if k["stale"]]
    active_keys    = [k for k in access_keys if k["status"] == "Active"]

    issues = []
    if not mfa_enabled:
        issues.append("NO_MFA")
    if is_admin:
        issues.append("ADMIN_PRIVILEGES")
    if is_inactive:
        issues.append("INACTIVE_USER")
    if stale_keys:
        issues.append("STALE_ACCESS_KEY")
    if len(active_keys) > 1:
        issues.append("MULTIPLE_ACTIVE_KEYS")

    # Severity:
    #   CRITICAL → admin + no MFA (fully compromisable with one stolen password)
    #   HIGH     → no MFA alone, OR stale admin key
    #   MEDIUM   → inactive user, stale key, multiple keys
    #   OK       → no issues
    if is_admin and not mfa_enabled:
        severity = "CRITICAL"
    elif not mfa_enabled or (is_admin and stale_keys):
        severity = "HIGH"
    elif issues:
        severity = "MEDIUM"
    else:
        severity = "OK"

    return {
        "username":           username,
        "user_arn":           user["Arn"],
        "created":            user["CreateDate"].isoformat(),
        "severity":           severity,
        "issues":             issues,
        "mfa_enabled":        mfa_enabled,
        "is_admin":           is_admin,
        "days_since_login":   days_since,
        "is_inactive":        is_inactive,
        "access_keys":        access_keys,
    }


# ── Entry point ───────────────────────────────────────────────────────────────

def run_iam_audit():
    iam   = get_iam_client()
    users = iam.list_users()["Users"]
    logger.info(f"Found {len(users)} IAM user(s)")

    findings = [audit_user(iam, u) for u in users]

    summary = {
        "total_users": len(findings),
        "critical":    sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high":        sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium":      sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "ok":          sum(1 for f in findings if f["severity"] == "OK"),
        "no_mfa":      sum(1 for f in findings if not f["mfa_enabled"]),
        "admins":      sum(1 for f in findings if f["is_admin"]),
        "inactive":    sum(1 for f in findings if f["is_inactive"]),
    }

    report = {
        "audit_type": "IAM",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "summary":    summary,
        "findings":   findings,
    }

    ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/iam_audit_{ts}.json"

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info(f"Report written → {report_path}")
    logger.info(f"Summary: {summary}")

    return report


if __name__ == "__main__":
    run_iam_audit()
