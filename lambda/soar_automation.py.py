import json
import boto3
from datetime import datetime

dynamodb = boto3.resource("dynamodb")
incidents_table = dynamodb.Table("incidents")
ti_table = dynamodb.Table("threat_intel")
s3 = boto3.client("s3")
sns = boto3.client("sns")
wafv2 = boto3.client("wafv2")

# -------- CONFIG ----------
SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:YOUR_ACCOUNT_ID:cloud-soc-alerts"
S3_BUCKET = "cloud-soc-evidence-2025-11-21"
WAF_WEBACL_ARN = "arn:aws:wafv2:ap-south-1:YOUR_ACCOUNT_ID:regional/webacl/cloud-soc-waf/12345"
# --------------------------

def block_ip_in_waf(ip):
    try:
        # Fetch existing rules
        response = wafv2.get_web_acl(
            Name="cloud-soc-waf",
            Scope="REGIONAL",
            Id=WAF_WEBACL_ARN.split("/")[-1]
        )
        lock_token = response["LockToken"]
        web_acl = response["WebACL"]

        # Add a new block rule
        new_rule = {
            "Name": f"BlockIP_{ip}",
            "Priority": 1,
            "Action": {"Block": {}},
            "Statement": {
                "IPSetReferenceStatement": {
                    "ARN": create_ip_set(ip)
                }
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": f"BlockIP_{ip}"
            }
        }

        web_acl["Rules"].append(new_rule)

        # Update WAF
        wafv2.update_web_acl(
            Name="cloud-soc-waf",
            Scope="REGIONAL",
            Id=WAF_WEBACL_ARN.split("/")[-1],
            DefaultAction=web_acl["DefaultAction"],
            Rules=web_acl["Rules"],
            VisibilityConfig=web_acl["VisibilityConfig"],
            LockToken=lock_token
        )
        print(f"[WAF] IP blocked: {ip}")

    except Exception as e:
        print("WAF block error:", e)


def create_ip_set(ip):
    """Create an IP Set inside WAF"""
    response = wafv2.create_ip_set(
        Name=f"IPSet_{ip}",
        Scope="REGIONAL",
        IPAddressVersion="IPV4",
        Addresses=[f"{ip}/32"],
        Description="Auto-blocked malicious IP"
    )
    return response["Summary"]["ARN"]


def save_evidence_to_s3(alert, incident_id):
    filename = f"incidents/{incident_id}/event.json"
    s3.put_object(
        Bucket=S3_BUCKET,
        Key=filename,
        Body=json.dumps(alert, indent=4)
    )
    print("[S3] Evidence stored:", filename)


def create_incident(alert):
    incident_id = str(datetime.utcnow().timestamp()).replace(".", "")
    item = {
        "incident_id": incident_id,
        "timestamp": str(datetime.utcnow()),
        "source_ip": alert["source_ip"],
        "attack_type": alert["attack_type"],
        "severity": alert["severity"],
        "status": "open",
        "mitre_tag": alert["mitre_tag"]
    }
    incidents_table.put_item(Item=item)
    print("[INCIDENT] Created:", item)
    return incident_id


def add_to_threat_intel(ip):
    ti_table.put_item(Item={
        "ip": ip,
        "listed_at": str(datetime.utcnow()),
        "reason": "Auto-added due to malicious behavior"
    })
    print("[Threat Intel] Blacklisted:", ip)


def send_sns_notification(alert):
    message = f"""
🚨 Cloud SOC Alert Generated!

Attack Type: {alert['attack_type']}
Source IP: {alert['source_ip']}
Severity: {alert['severity']}
MITRE Technique: {alert['mitre_tag']}
Timestamp: {alert['timestamp']}
"""
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject="Cloud SOC Alert"
    )
    print("[SNS] Notification sent!")


def lambda_handler(event, context):
    print("SOAR Triggered:", json.dumps(event))

    # DynamoDB Streams format
    for record in event["Records"]:
        if record["eventName"] != "INSERT":
            continue

        alert = record["dynamodb"]["NewImage"]
        
        # Extract values from DynamoDB streams format
        parsed_alert = {
            "alert_id": alert["alert_id"]["S"],
            "timestamp": alert["timestamp"]["S"],
            "source_ip": alert["source_ip"]["S"],
            "attack_type": alert["attack_type"]["S"],
            "severity": alert["severity"]["S"],
            "mitre_tag": alert["mitre_tag"]["S"],
            "raw_event": alert["raw_event"]["S"]
        }

        # 1️⃣ Create incident ticket
        incident_id = create_incident(parsed_alert)

        # 2️⃣ Save evidence to S3
        save_evidence_to_s3(parsed_alert, incident_id)

        # 3️⃣ Block IP in WAF for CRITICAL attacks
        if parsed_alert["severity"] == "CRITICAL":
            block_ip_in_waf(parsed_alert["source_ip"])

        # 4️⃣ Add to Threat Intel DB
        add_to_threat_intel(parsed_alert["source_ip"])

        # 5️⃣ Send SNS alert
        send_sns_notification(parsed_alert)

    return {"message": "SOAR automation complete"}
