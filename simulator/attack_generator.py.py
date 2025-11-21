import random
import time
import json
import requests
import simpy
from datetime import datetime

# 🔴 Replace this after Phase 4 (API Gateway setup)
API_URL = "https://your_api_url_here.amazonaws.com/attack"

# ------------------------------
# Attack Types and Generators
# ------------------------------

def generate_port_scan(env, send_event):
    while True:
        event = {
            "timestamp": str(datetime.utcnow()),
            "attack_type": "port_scan",
            "source_ip": f"192.168.1.{random.randint(2, 254)}",
            "destination_ip": "10.0.0.12",
            "ports_scanned": random.sample(range(20, 1050), random.randint(5, 20))
        }
        send_event(event)
        yield env.timeout(random.uniform(1, 3))


def generate_bruteforce(env, send_event):
    while True:
        event = {
            "timestamp": str(datetime.utcnow()),
            "attack_type": "bruteforce",
            "source_ip": f"172.16.0.{random.randint(2, 254)}",
            "target_user": random.choice(["admin", "root", "test", "guest"]),
            "attempts": random.randint(1, 5)
        }
        send_event(event)
        yield env.timeout(random.uniform(2, 5))


def generate_sql_injection(env, send_event):
    while True:
        event = {
            "timestamp": str(datetime.utcnow()),
            "attack_type": "sql_injection",
            "source_ip": f"100.64.0.{random.randint(2, 254)}",
            "payload": random.choice(["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT * FROM creds; --"]),
        }
        send_event(event)
        yield env.timeout(random.uniform(5, 10))


def generate_directory_traversal(env, send_event):
    while True:
        event = {
            "timestamp": str(datetime.utcnow()),
            "attack_type": "directory_traversal",
            "source_ip": f"203.0.113.{random.randint(2, 254)}",
            "path": random.choice(["../../etc/passwd", "../../../var/log", "../../../../windows/system32"])
        }
        send_event(event)
        yield env.timeout(random.uniform(3, 8))


def generate_dos(env, send_event):
    while True:
        event = {
            "timestamp": str(datetime.utcnow()),
            "attack_type": "dos_attack",
            "source_ip": f"198.51.100.{random.randint(2, 254)}",
            "packet_rate": random.randint(500, 2000)
        }
        send_event(event)
        yield env.timeout(random.uniform(0.5, 1.5))


def generate_normal_traffic(env, send_event):
    while True:
        event = {
            "timestamp": str(datetime.utcnow()),
            "attack_type": "normal",
            "source_ip": f"10.0.0.{random.randint(1, 254)}",
            "status": "ok"
        }
        send_event(event)
        yield env.timeout(random.uniform(0.2, 1.0))


# --------------------------------
# Function to send event to AWS
# --------------------------------
def send_event_to_api(event):
    try:
        response = requests.post(API_URL, json=event)
        print("Sent:", event["attack_type"], "Status:", response.status_code)

    except Exception as e:
        print("Failed to send event:", e)


# ------------------------------
# Main Simulation Setup
# ------------------------------

def main():
    env = simpy.Environment()

    # Register generation processes
    env.process(generate_port_scan(env, send_event_to_api))
    env.process(generate_bruteforce(env, send_event_to_api))
    env.process(generate_sql_injection(env, send_event_to_api))
    env.process(generate_directory_traversal(env, send_event_to_api))
    env.process(generate_dos(env, send_event_to_api))
    env.process(generate_normal_traffic(env, send_event_to_api))

    print("Attack Simulator Started...")
    env.run()


if __name__ == "__main__":
    main()
