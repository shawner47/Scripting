# Baseline Subnet NSG - Rule List

Built from nsg-newdc-devaccess (the domain controller's working NSG) with the
AD-specific rules removed, plus SSH and RDP added using the combined source
addresses already in use across the NSGs reviewed on 2026-09-28.

This list is also implemented in New-BaselineNSG_v1.0.ps1, which creates it as
a new NSG in Azure. The script does not attach the NSG anywhere.

## Rules

| Name | Direction | Protocol | Source | Source Port | Destination | Dest Port |
|---|---|---|---|---|---|---|
| Allow-ICMPv4-in | Inbound | ICMP | 10.10.4.0/23, 10.10.6.0/24, 10.150.0.0/21, 10.20.30.0/24, 10.99.0.0/16, 172.16.0.0/16, 172.30.20.0/22, 172.31.20.0/22, 192.168.0.0/16 | * | * | * |
| Allow-Tanium1 | Inbound | (any) | (same as above) | * | * | 139 |
| Allow-SMB | Inbound | TCP | (same as above) | * | * | 445 |
| Allow-SSH-in | Inbound | TCP | 192.168.4.0/24, 209.198.200.228 | * | * | 22 |
| Allow-RDP-in | Inbound | TCP | 192.168.4.0/24, 209.198.200.228 | * | * | 3389 |
| AllowOutToPrivateSubnets | Outbound | (any) | * | * | 10.10.4.0/23, 10.10.6.0/24, 10.150.0.0/21, 10.99.0.0/16, 172.16.100.0/24, 192.168.0.0/16, 209.198.200.140/32, 209.198.200.141/32, 209.198.200.228/32 | * |

## Where each rule came from

- **Allow-ICMPv4-in, Allow-Tanium1, Allow-SMB, AllowOutToPrivateSubnets** - carried over unchanged from nsg-newdc-devaccess, the NSG attached to MGL-AZ-DC06's NIC.
- **Allow-SSH-in** - the only SSH rule found in the review (MGL-DEV-OEAAPP1-nsg, Allow-DC-HQ-SSH-in). Needed because Linux VMs also run in Azure.
- **Allow-RDP-in** - combined from two different sources already in production: 209.198.200.228 (MGL-DEV-OEASQL-nsg, MGL-DEV-OEAWEB1-nsg, rule RDP-from-Corp) and 192.168.4.0/24 (MGL-AZ-DC06-nsg, rule HQ-VLAN4-RDP-in).

## Removed from nsg-newdc-devaccess as domain-controller-specific

Kerberos (88 TCP/UDP), RPC Endpoint Mapper (135), LDAP (389 TCP/UDP), Global
Catalog (3268-3269), Kerberos password (464 TCP/UDP), LDAPS (636), Dynamic RPC
(49152-65535).

## Decisions still open

- **AllowOutToPrivateSubnets** is a broad outbound allow (any port, to the
  full private-subnet list). Kept as-is per your decision on 2026-09-28,
  noted as easy to narrow later if needed.
- **Attachment** - this rule set is not yet attached to any subnet or NIC.
  Deciding which subnets get it, and whether it replaces or supplements the
  existing per-VM NSGs, is a separate step.
