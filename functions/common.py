from datetime import datetime, timezone


def make_finding(check_type, resource, issue, severity):
    return {
        "id": f"{check_type}#{resource}",  
        "check_type": check_type,
        "resource": resource,
        "issue": issue,
        "severity": severity,
        "detected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def save_findings(table, findings, checked_types):
    current_ids = {f["id"] for f in findings}

    for finding in findings:
        table.put_item(Item=finding)

    scan_kwargs = {}
    while True:
        response = table.scan(**scan_kwargs)
        for item in response["Items"]:
            stale = item.get("check_type") in checked_types and item["id"] not in current_ids
            if stale:
                table.delete_item(Key={"id": item["id"]})
        if "LastEvaluatedKey" not in response:
            break
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]