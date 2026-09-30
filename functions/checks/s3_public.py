from botocore.exceptions import ClientError

from functions.common import make_finding

CHECK_TYPE = "s3_public"

PUBLIC_GROUPS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)
BPA_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _bpa_fully_enabled(s3, bucket):
    try:
        config = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as error:
        if error.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise
    return all(config.get(key, False) for key in BPA_KEYS)


def _policy_is_public(s3, bucket):
    try:
        return s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"].get("IsPublic", False)
    except ClientError as error:
        if error.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return False
        raise


def _acl_is_public(s3, bucket):
    grants = s3.get_bucket_acl(Bucket=bucket)["Grants"]
    return any(grant["Grantee"].get("URI") in PUBLIC_GROUPS for grant in grants)


def scan(session):
    s3 = session.client("s3")
    findings = []

    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        blocked = _bpa_fully_enabled(s3, name)
        public = _policy_is_public(s3, name) or _acl_is_public(s3, name)

        if blocked:
            severity, issue = "ok", "Block Public Access activado por completo"
        elif public:
            severity, issue = "critical", "Bucket público: política o ACL abierta a internet"
        else:
            severity, issue = "warning", "Sin Block Public Access completo (no es público, pero le falta la red de seguridad)"

        findings.append(make_finding(CHECK_TYPE, name, issue, severity))

    return findings