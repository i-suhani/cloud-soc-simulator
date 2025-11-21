import json
import boto3
from datetime import datetime

# DynamoDB Resources
dynamodb = boto3.resource("dynamodb")
incidents_table = dynamodb.Table("incidents")
ti_table = dynamodb.Table("threat_intel")

# S3 Client
s3 = boto3.client("s3")

# SNS Client
sns = boto3.client("sns")

# -------- CONFIG ----------
SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:627031163413:cloud-soc-alerts"
S3_BUCKET = "cloud-soc-evidence-mumbai"

# --------------------------


# Save incident evidence
def save_evidence_to_s3(alert, incident_id):
    filename = f"incidents/{incident_id}/event.json"
    s3.put_object(
        Bucket=S3_BUCKET,
        Key=filename,
        Body=json.dumps(alert, indent=4)
    )
    print("[S3] Evidence stored:", filename)


# Create Incident in DynamoDB
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


# Add malicious IP to Threat Intel DB
def add_to_threat_intel(ip):
    ti_table.put_item(Item={
        "ip": ip,
        "listed_at": str(datetime.utcnow()),
        "reason": "Automatically added by SOAR during alert handling"
    })
    print("[Threat Intelligence] Blacklisted IP:", ip)


# Notify admin using SNS
def send_sns_notification(alert):
    message = f"""
🚨 Cloud SOC Alert Generated!

Attack Type: {alert['attack_type']}
Source IP: {alert['source_ip']}
Severity: {alert['severity']}
MITRE: {alert['mitre_tag']}
Timestamp: {alert['timestamp']}
"""

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=message,
        Subject="Cloud SOC Security Alert"
    )
    print("[SNS] Notification sent.")


# MAIN HANDLER
def lambda_handler(event, context):
    print("SOAR Trigger Event:", json.dumps(event))

    # DynamoDB Streams format
    for record in event["Records"]:
        if record["eventName"] != "INSERT":
            continue

        alert = record["dynamodb"]["NewImage"]

        # Extract fields from DynamoDB JSON
        parsed_alert = {
            "alert_id": alert["alert_id"]["S"],
            "timestamp": alert["timestamp"]["S"],
            "source_ip": alert["source_ip"]["S"],
            "attack_type": alert["attack_type"]["S"],
            "severity": alert["severity"]["S"],
            "mitre_tag": alert["mitre_tag"]["S"],
            "raw_event": alert["raw_event"]["S"]
        }

        # 1️⃣ Create incident record
        incident_id = create_incident(parsed_alert)

        # 2️⃣ Save evidence in S3
        save_evidence_to_s3(parsed_alert, incident_id)

        # 3️⃣ Add IP to threat intel
        add_to_threat_intel(parsed_alert["source_ip"])

        # 4️⃣ Notify via SNS
        send_sns_notification(parsed_alert)

    return {"message": "SOAR automation completed (no-WAF version)"}
