import json
import boto3
import base64
from datetime import datetime

dynamodb = boto3.resource("dynamodb")
alerts_table = dynamodb.Table("alerts")
s3 = boto3.client("s3")

# MITRE mapping stays same
MITRE_MAP = {
    "port_scan": "T1046 - Network Service Scanning",
    "bruteforce": "T1110 - Brute Force",
    "sql_injection": "T1505 - Server-Side Injection",
    "directory_traversal": "T1083 - File and Directory Discovery",
    "dos_attack": "T1499 - Endpoint Denial of Service",
    "normal": "None"
}

# ================================
# DETECTION LOGIC (no changes)
# ================================
def detect_port_scan(event):
    return len(event.get("ports_scanned", [])) > 10

def detect_bruteforce(event):
    return event.get("attempts", 0) >= 5

def detect_sql_injection(event):
    payload = event.get("payload", "")
    patterns = ["' OR '1'='1", "DROP TABLE", "UNION SELECT"]
    return any(p in payload for p in patterns)

def detect_directory_traversal(event):
    path = event.get("path", "")
    return "../" in path or "..\\" in path

def detect_dos(event):
    return event.get("packet_rate", 0) > 1000

# Store alert in DynamoDB
def save_alert(event, severity):
    item = {
        "alert_id": str(datetime.utcnow().timestamp()).replace(".", ""),
        "timestamp": str(datetime.utcnow()),
        "source_ip": event.get("source_ip", "unknown"),
        "attack_type": event["attack_type"],
        "severity": severity,
        "mitre_tag": MITRE_MAP[event["attack_type"]],
        "raw_event": json.dumps(event)
    }
    alerts_table.put_item(Item=item)
    return item

# ================================
# MAIN HANDLER FOR S3 TRIGGER
# ================================
def lambda_handler(event, context):

    print("Triggered by S3:", json.dumps(event))

    # 1️⃣ Extract bucket + object path
    bucket = event["Records"][0]["s3"]["bucket"]["name"]
    key = event["Records"][0]["s3"]["object"]["key"]

    # 2️⃣ Read uploaded attack JSON
    obj = s3.get_object(Bucket=bucket, Key=key)
    event_data = json.loads(obj["Body"].read())

    # 3️⃣ Apply detection
    attack_type = event_data.get("attack_type", "unknown")
    severity = "LOW"
    detected = False

    if attack_type == "port_scan" and detect_port_scan(event_data):
        severity, detected = "MEDIUM", True
    elif attack_type == "bruteforce" and detect_bruteforce(event_data):
        severity, detected = "HIGH", True
    elif attack_type == "sql_injection" and detect_sql_injection(event_data):
        severity, detected = "CRITICAL", True
    elif attack_type == "directory_traversal" and detect_directory_traversal(event_data):
        severity, detected = "HIGH", True
    elif attack_type == "dos_attack" and detect_dos(event_data):
        severity, detected = "CRITICAL", True

    # 4️⃣ Save alert if detected
    if detected:
        item = save_alert(event_data, severity)
        print("ALERT GENERATED:", item)
    else:
        print("No threat detected.")
