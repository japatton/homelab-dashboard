# Claude Integration Sandbox

This directory is the write sandbox for Claude Code subprocess invocations.

When an unknown device or service is detected that the system cannot classify,
the backend may invoke the Claude Code CLI with write access scoped to this
directory only. Generated integration files appear here in a "staged" state.

## Review process

1. A notification appears on the device node in the Network Map
2. The ClaudeIntegrationCard shows a diff preview of the generated file
3. Click **Apply** to move the file into the active integrations path and rebuild
4. Click **Reject** to discard the generated code

## File naming convention

`{device_type}_{service_name}_integration.py`

Example: `portainer_api_integration.py`

## What's generated

Each integration file exports an `enrich(ip, port)` async function that returns
a list of `DeviceService` objects with display names, versions, and launch URLs.
The backend loads these at startup via dynamic import.

## Security

- Claude subprocess runs with `--allowedTools Edit,Write` scoped to this directory
- No credentials or internal API addresses are passed to the subprocess
- All generated code is human-reviewed before activation
- An append-only audit log records every approve/reject action
