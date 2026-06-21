# Windows Endpoint Setup Path

Phase 1 uses a Windows VM endpoint as the recommended victim machine for telemetry generation. A physical Windows endpoint is supported only as an alternative for later hardware-realistic testing.

This document defines endpoint assumptions, networking, required software, setup checks, safety notes, and acceptance criteria. It does not install Sysmon, implement the Sysmon baseline, or add the Atomic Red Team runner.

## Recommended Architecture

```text
Developer host
  Docker Desktop / Docker Engine
    Elasticsearch: http://localhost:9200
    Kibana:        http://localhost:5601
    Logstash HTTP: http://localhost:8080

Windows 10/11 VM endpoint
  Local administrator account
  Windows event channels
  PowerShell logging
  Sysmon installed later by Issue 03
  Atomic Red Team configured later by Issue 04
        |
        | HTTP/event forwarding to EDR_LOGSTASH_URL
        v
Developer host Logstash published port
```

The VM is the telemetry source. The developer host runs the Elastic lab and receives endpoint events through the Logstash HTTP ingest boundary.

Use these endpoint-specific values when documenting or running local checks:

```powershell
$env:EDR_DOCKER_HOST_IP = "<developer-host-ip-reachable-from-vm>"
$env:EDR_LOGSTASH_URL = "http://$env:EDR_DOCKER_HOST_IP:8080"
$env:EDR_KIBANA_URL = "http://$env:EDR_DOCKER_HOST_IP:5601"
```

Do not hardcode these values in scripts or documentation examples beyond placeholders. The correct host IP depends on VM networking mode.

## Physical Endpoint Alternative

A physical Windows endpoint can generate more realistic hardware and user-environment telemetry, but it is not recommended for Phase 1.

Use a physical endpoint only when:

- The machine contains no personal, production, or sensitive data.
- You can tolerate endpoint changes caused by adversary emulation.
- You have a reliable rollback or reimage path.
- Local firewall, VPN, AV, EDR, and corporate policies will not interfere with lab traffic.

Physical endpoints are harder to reset, harder to reproduce, and riskier for Atomic Red Team execution. Keep them as an advanced validation option after the VM path is stable.

## VM Networking Modes

### Bridged Networking

The VM appears as a peer on the same LAN as the developer host.

Use when:

- The VM needs simple access to the developer host by LAN IP.
- The LAN is trusted and isolated enough for lab traffic.
- You want the least confusing first setup.

Checks:

```powershell
Test-NetConnection $env:EDR_DOCKER_HOST_IP -Port 8080
Invoke-RestMethod -Uri "$env:EDR_LOGSTASH_URL" -Method Post -ContentType "application/json" -Body '{"message":"endpoint-network-check"}'
```

Risks:

- The VM may be visible to other devices on the LAN.
- Lab activity may interact with network monitoring outside the lab.

### NAT Networking

The VM reaches external networks through the hypervisor NAT. The developer host must still be reachable from inside the guest.

Use when:

- You want the VM less exposed than bridged mode.
- Your hypervisor provides a stable host-accessible address.

Checks:

```powershell
ipconfig
Test-NetConnection $env:EDR_DOCKER_HOST_IP -Port 8080
```

Risks:

- `localhost` inside the VM points to the VM, not the developer host.
- Host IP discovery differs across Hyper-V, VMware, and VirtualBox.

### Host-Only Networking

The VM can communicate with the developer host on an isolated virtual network.

Use when:

- You want the safest lab isolation.
- Internet access is not required from the endpoint during the current task.
- Dependencies are pre-downloaded or routed through a controlled second adapter.

Checks:

```powershell
Test-NetConnection $env:EDR_DOCKER_HOST_IP -Port 8080
Test-NetConnection $env:EDR_DOCKER_HOST_IP -Port 5601
```

Risks:

- Installing software from the internet may require a second adapter or manual transfer.
- Misconfigured routing can make the endpoint unable to reach Logstash.

## Required Software

Developer host:

- Docker Desktop or Docker Engine.
- Docker Compose v2.
- The Phase 1 Elastic lab from `docker-compose.yml`.
- Published Logstash HTTP ingest port `8080`.
- Enough memory for Elastic Stack plus a Windows VM. Use 16 GB host RAM as a practical minimum; 32 GB is better.

Windows VM endpoint:

- Windows 10 or Windows 11, Pro or Enterprise preferred.
- Local administrator access.
- PowerShell 5.1 or newer.
- Windows Event Log service enabled.
- Network access to the developer host Logstash port.
- Sysmon package available for Issue 03, but not installed by this issue.
- Atomic Red Team prerequisites available for Issue 04, but no runner is implemented by this issue.

Recommended hypervisors:

- Hyper-V
- VMware Workstation
- VirtualBox

## Setup Checklist

### Developer Host

- [ ] Start Docker Desktop or Docker Engine.
- [ ] Start the Elastic lab with `scripts/setup/deploy_stack.sh` or `docker compose up -d`.
- [ ] Confirm services are healthy with `docker compose ps`.
- [ ] Identify the developer host IP reachable from the VM.
- [ ] Confirm local Logstash is listening on port `8080`.
- [ ] Confirm Windows firewall on the developer host allows inbound TCP `8080` from the VM network.

### Windows VM Endpoint

- [ ] Create or boot a Windows 10/11 VM.
- [ ] Use a local administrator account for endpoint setup.
- [ ] Select a VM networking mode: bridged, NAT, or host-only.
- [ ] Set `EDR_DOCKER_HOST_IP`, `EDR_LOGSTASH_URL`, and `EDR_KIBANA_URL` in the endpoint session.
- [ ] Verify connectivity to Logstash:

```powershell
Test-NetConnection $env:EDR_DOCKER_HOST_IP -Port 8080
```

- [ ] Send a safe fixture event to Logstash:

```powershell
$body = ConvertTo-Json -Compress -InputObject @{
  message = "windows-endpoint-connectivity-check"
  endpoint.role = "phase-1-vm"
}

Invoke-RestMethod -Uri $env:EDR_LOGSTASH_URL -Method Post -ContentType "application/json" -Body $body
```

- [ ] Confirm the event appears in Elasticsearch index `edr-raw-events-*`.
- [ ] Enable or verify required Windows event channels before later telemetry work:
  - Security
  - Windows PowerShell
  - Microsoft-Windows-PowerShell/Operational
  - Microsoft-Windows-WMI-Activity/Operational

### PowerShell Logging

PowerShell script block and module logging are required for later ART telemetry. Document the current state before changing policy.

Check current policy visibility:

```powershell
Get-ExecutionPolicy -List
Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational"
```

Enable operational channel if needed:

```powershell
wevtutil sl Microsoft-Windows-PowerShell/Operational /e:true
```

Group Policy or registry-based script block logging may be enabled in a later endpoint hardening script. For this issue, record whether it is enabled and confirm the operational channel is available.

### WMI Activity Logging

Enable the WMI Activity operational channel if needed:

```powershell
wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true
Get-WinEvent -ListLog "Microsoft-Windows-WMI-Activity/Operational"
```

### Security Channel

The Security channel should be present by default. Later work can add audit policy configuration if needed.

Check availability:

```powershell
Get-WinEvent -ListLog Security
```

## Security And Safety Notes

- Use a VM snapshot before installing endpoint telemetry tools or running adversary emulation.
- Do not run Atomic Red Team tests on a personal or production Windows host for Phase 1.
- Keep the VM isolated from sensitive networks.
- Prefer host-only or NAT networking when you do not need LAN visibility.
- Avoid storing credentials, API keys, personal files, or production data inside the victim VM.
- Treat generated telemetry as potentially sensitive because it includes hostnames, usernames, process paths, command lines, and network data.
- Keep Windows Defender or other security controls in a known state and document deviations. Do not disable protections casually.
- Revert to a clean snapshot after tests that alter registry, scheduled tasks, files, services, or PowerShell policy.
- Do not expose Logstash, Elasticsearch, or Kibana ports to untrusted networks in Phase 1.

## Acceptance Criteria

Issue 02 is complete when:

- [ ] Documentation clearly recommends a Windows VM endpoint for Phase 1.
- [ ] Physical Windows endpoint usage is documented only as an alternative.
- [ ] Developer host steps are separated from Windows endpoint steps.
- [ ] Required Windows version and administrator assumptions are documented.
- [ ] VM networking modes are documented with tradeoffs and verification commands.
- [ ] Endpoint-specific values use `EDR_DOCKER_HOST_IP`, `EDR_LOGSTASH_URL`, and related environment variables.
- [ ] PowerShell, Security, and WMI event channel requirements are documented.
- [ ] A safe connectivity fixture can be posted from the VM to Logstash.
- [ ] The runbook lists manual decisions the human must confirm: hypervisor, VM network mode, developer host IP, firewall rule, and snapshot strategy.

## Out Of Scope

- Installing Sysmon or replacing `collection/sysmon/sysmon_config.xml`.
- Implementing the Sysmon telemetry baseline.
- Installing or running Atomic Red Team.
- Implementing the Atomic Red Team runner.
- Implementing Elastic Agent, Winlogbeat, or production event forwarding.
- Implementing ECS normalization.
