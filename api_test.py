#!/usr/bin/env python3
"""
check_datastore.py

Tests whether a vCenter/ESXi account can see a specific datastore via the
API. Useful for verifying service account permissions before deployment.

Usage:
    python3 check_datastore.py <host> <user> [datastore_name]

    host           - vCenter or ESXi hostname/IP
    user           - vCenter username (e.g. svc-watcher@vsphere.local)
    datastore_name - (optional) exact datastore name to search for;
                     omit to list all visible datastores

Examples:
    # Check a specific datastore
    python3 check_datastore.py vcenter.local svc-watcher@vsphere.local ESX_1_SSD_Data3

    # List all visible datastores
    python3 check_datastore.py vcenter.local svc-watcher@vsphere.local
"""

import sys
import ssl
import getpass

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 check_datastore.py <host> <user> [datastore_name]")
        sys.exit(1)

    host           = sys.argv[1]
    user           = sys.argv[2]
    datastore_name = sys.argv[3] if len(sys.argv) > 3 else None

    # Hidden password prompt — never echoed to the terminal
    pwd = getpass.getpass(f"Password for {user}@{host}: ")

    print(f"\nConnecting to {host}...")
    ctx = ssl._create_unverified_context()

    try:
        si = SmartConnect(host=host, user=user, pwd=pwd, sslContext=ctx)
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)

    print(f"Connected. (apiType: {si.content.about.apiType})\n")

    try:
        content   = si.RetrieveContent()
        container = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.Datastore], True
        )
        datastores = container.view

        if not datastores:
            print("No datastores visible to this account.")
            sys.exit(0)

        if datastore_name:
            # Search for a specific datastore by exact name
            ds = next((d for d in datastores if d.name == datastore_name), None)
            if ds:
                free_gb  = round(ds.summary.freeSpace / 1024 ** 3, 2)
                total_gb = round(ds.summary.capacity / 1024 ** 3, 2)
                print(f"[OK] Found datastore: {ds.name}")
                print(f"     Type:       {ds.summary.type}")
                print(f"     Capacity:   {total_gb} GB")
                print(f"     Free space: {free_gb} GB")
                print(f"     URL:        {ds.summary.url}")
            else:
                print(f"[NOT FOUND] Datastore '{datastore_name}' was not found.")
                print("This account either cannot see it or the name doesn't match exactly.")
                print("\nDatastores this account CAN see:")
                for d in sorted(datastores, key=lambda x: x.name):
                    print(f"  - {d.name}")
        else:
            # List all visible datastores
            print(f"{'Name':<30} {'Type':<10} {'Free GB':>10} {'Total GB':>10}")
            print("-" * 65)
            for ds in sorted(datastores, key=lambda x: x.name):
                free_gb  = round(ds.summary.freeSpace / 1024 ** 3, 2)
                total_gb = round(ds.summary.capacity / 1024 ** 3, 2)
                print(f"{ds.name:<30} {ds.summary.type:<10} {free_gb:>10} {total_gb:>10}")
            print(f"\nTotal visible: {len(datastores)} datastore(s)")

    finally:
        Disconnect(si)


if __name__ == "__main__":
    main()
