import json
import boto3
from datetime import datetime

dynamodb = boto3.resource("dynamodb")
alerts_table = dynamodb.Table("alerts")

# -------------------------
# MITRE ATT&CK MAPPING
# -------------------------
MITRE_MAP = {
    "port_scan": "T1046 - Network Service Scanning",
    "bruteforce": "T1110 - Brute Force",
    "sql_injection": "T1505 - Server-Side Injection",
    "directory_traversal": "T1083 - File and Directory Discovery",
    "dos_attack": "T1499 - Endpoint Denial of Service",
    "normal": "None"
}

# =====================================
# DETECTION LOGIC
# =====================================

def detect_port_scan(event):
    ports = event.get("ports_scanned", [])
    if len(ports) > 10:
        return True
    return False

def detect_bruteforce(event):
    attempts = event.get("attempts", 0)
    if attempts >= 5:
        return True
    return False

def detect_sql_injection(event):
    payload = event.get("payload", "")
    patterns = ["' OR '1'='1", "DROP TABLE", "UNION SELECT"]
    return any(p in payload for p in patterns)

def detect_directory_traversal(event):
    path = event.get("path", "")
    return "../" in path or "..\\" in path

def detect_dos(event):
    rate = event.get("packet_rate", 0)
    if rate > 1000:
        return True
    return False

# =====================================
# STORE ALERT IN DYNAMODB
# =====================================
def save_alert(event, severity):
    alert_item = {
        "alert_id": str(datetime.utcnow().timestamp()).replace(".", ""),
        "timestamp": str(datetime.utcnow()),
        "source_ip": event.get("source_ip", "unknown"),
        "attack_type": event["attack_type"],
        "severity": severity,
        "mitre_tag": MITRE_MAP[event["attack_type"]],
        "raw_event": json.dumps(event)
    }

    alerts_table.put_item(Item=alert_item)
    return alert_item


# =====================================
# LAMBDA HANDLER
# =====================================
def lambda_handler(event, context):

    # Kinesis sends data in Records[]
    for record in event["Records"]:
        payload = record["kinesis"]["data"]
        event_data = json.loads(base64.b64decode(payload))

        attack_type = event_data.get("attack_type", "unknown")
        severity = "LOW"
        detected = False

        # Run detections
        if attack_type == "port_scan":
            if detect_port_scan(event_data):
                severity = "MEDIUM"
                detected = True

        elif attack_type == "bruteforce":
            if detect_bruteforce(event_data):
                severity = "HIGH"
                detected = True

        elif attack_type == "sql_injection":
            if detect_sql_injection(event_data):
                severity = "CRITICAL"
                detected = True

        elif attack_type == "directory_traversal":
            if detect_directory_traversal(event_data):
                severity = "HIGH"
                detected = True

        elif attack_type == "dos_attack":
            if detect_dos(event_data):
                severity = "CRITICAL"
                detected = True

        # SAVE RESULTS
        if detected:
            saved = save_alert(event_data, severity)
            print("ALERT GENERATED:", saved)
        else:
            print("No threat detected for:", attack_type)

    return {"status": "processed"}
