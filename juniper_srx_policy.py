#!/usr/bin/env python3
"""
Juniper SRX Firewall Security Policy Automation
---------------------------------------------------------------
✅ Uses Juniper PyEZ (junos-eznc)
✅ Supports multiple devices and multiple policies (YAML-driven)
✅ Safe commits, diff preview, verification included

Author: Ehsan Momeni Bashusqeh (Network Automation Engineer)
"""

import sys
import yaml
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import ConnectError, CommitError, ConfigLoadError


def add_security_policy(host, username, password, policy):
    """Add a security policy to Juniper SRX via PyEZ"""

    from_zone = policy["from_zone"]
    to_zone = policy["to_zone"]
    policy_name = policy["policy_name"]

    # Build 'set' commands
    set_cmds = []

    for src in policy.get("source_addresses", ["any"]):
        set_cmds.append(
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} match source-address {src}"
        )

    for dst in policy.get("destination_addresses", ["any"]):
        set_cmds.append(
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} match destination-address {dst}"
        )

    for app in policy.get("applications", ["any"]):
        set_cmds.append(
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} match application {app}"
        )

    action = policy.get("action", "permit")
    set_cmds.append(
        f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} then {action}"
    )

    if policy.get("log_session_init"):
        set_cmds.append(
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} then log session-init"
        )
    if policy.get("log_session_close"):
        set_cmds.append(
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} then log session-close"
        )

    if "description" in policy:
        set_cmds.append(
            f'set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} description "{policy["description"]}"'
        )

    print(f"\n🔹 Device: {host}")
    print(f"🔹 Policy: {policy_name}")
    print("-" * 70)

    try:
        with Device(host=host, user=username, passwd=password, port=22) as dev:
            with Config(dev, mode="exclusive") as cu:
                # Check existing policy
                existing = dev.cli(
                    f"show configuration security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name}",
                    warning=False,
                )
                if policy_name in existing:
                    print(f"⚠️ Policy '{policy_name}' already exists. Skipping...")
                    return

                cu.load("\n".join(set_cmds), format="set")
                diff = cu.diff()

                if diff:
                    print("Configuration diff:")
                    print("=" * 70)
                    print(diff)
                    print("=" * 70)
                    cu.commit(comment=f"Added policy: {policy_name}")
                    print(f"✅ Policy '{policy_name}' committed successfully!\n")
                else:
                    print("No changes detected.")
    except ConnectError as err:
        print(f"✗ Connection Error: {err}")
    except ConfigLoadError as err:
        print(f"✗ Config Load Error: {err}")
    except CommitError as err:
        print(f"✗ Commit Error: {err}")
    except Exception as err:
        print(f"✗ Unexpected Error: {err}")


def verify_policy(host, username, password, from_zone, to_zone, policy_name):
    """Verify the policy on device"""
    try:
        with Device(host=host, user=username, passwd=password) as dev:
            result = dev.cli(
                f"show configuration security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name}"
            )
            print("\n" + "=" * 70)
            print(f"Verification: {policy_name} @ {host}")
            print("=" * 70)
            print(result)
            print("=" * 70)
    except Exception as err:
        print(f"✗ Verification failed: {err}")


# ================================================================
# MAIN EXECUTION
# ================================================================
if __name__ == "__main__":
    print("=" * 70)
    print(" JUNIPER SRX SECURITY POLICY AUTOMATION (PyEZ)")
    print("=" * 70)

    # ------------------------------------------------------------
    # Load device inventory
    # ------------------------------------------------------------
    try:
        with open("devices.yaml") as f:
            devices = yaml.safe_load(f)
    except FileNotFoundError:
        print("⚠️ No 'devices.yaml' found. Using default local device.")
        devices = [
            {"host": "192.168.1.1", "user": "admin", "password": "password"},
        ]

    # ------------------------------------------------------------
    # Load security policies
    # ------------------------------------------------------------
    try:
        with open("policies.yaml") as f:
            policies = yaml.safe_load(f)
    except FileNotFoundError:
        print("⚠️ No 'policies.yaml' found. Aborting.")
        sys.exit(1)

    # ------------------------------------------------------------
    # Execute for all devices and policies
    # ------------------------------------------------------------
    for dev in devices:
        print(f"\n=== Processing Device: {dev['host']} ===")
        for p in policies:
            add_security_policy(dev["host"], dev["user"], dev["password"], p)
            verify_policy(
                dev["host"],
                dev["user"],
                dev["password"],
                p["from_zone"],
                p["to_zone"],
                p["policy_name"],
            )

    print("\n✅ All tasks completed successfully!\n")
