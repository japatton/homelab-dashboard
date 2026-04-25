from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import textwrap
import uuid
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# Where approved integrations live
INTEGRATIONS_DIR = Path(os.getenv("INTEGRATIONS_DIR", "/opt/homelab-dashboard/integrations/devices"))


def _build_prompt(device_context: dict) -> str:
    ip = device_context.get("ip", "unknown")
    ports = device_context.get("open_ports", [])
    services = device_context.get("services", [])
    banners = device_context.get("banners", {})
    os_guess = device_context.get("os_guess", "")
    hostname = device_context.get("hostname", "")

    service_lines = "\n".join(
        f"  - port {s.get('port')}/{s.get('protocol','tcp')}: {s.get('name','unknown')} {s.get('version','')}"
        for s in services
    ) or "\n".join(f"  - port {p}" for p in ports)

    banner_lines = "\n".join(f"  - port {p}: {b}" for p, b in banners.items()) if banners else "  none captured"

    return textwrap.dedent(f"""\
        You are analyzing an unknown device on a home lab network.

        Device details:
          IP: {ip}
          Hostname: {hostname or "(none)"}
          OS guess: {os_guess or "(unknown)"}
          Open ports / services:
        {service_lines}
          Banners:
        {banner_lines}

        Task:
        1. Identify what this device likely is (be specific — e.g. "Portainer container management UI").
        2. Write a single Python file called `integration.py` that provides:
           - A constant `DEVICE_TYPE: str` (e.g. "server", "iot", "camera")
           - A constant `DEVICE_LABEL: str` (human-readable name)
           - An async function `enrich(ip: str) -> list[dict]` that queries the
             device's API/service and returns a list of DeviceService-compatible
             dicts with keys: port, protocol, name, version, launch_url.

        Constraints:
          - Use only httpx for HTTP calls (already installed).
          - Handle connection errors gracefully (return [] on any exception).
          - No print statements, no interactive input.
          - File must be syntactically valid Python 3.10+.

        Write the file now.
    """)


async def run_via_cli(prompt: str, sandbox: Path) -> Optional[str]:
    """Invoke the `claude` CLI in a sandbox directory. Returns stdout or None on failure."""
    claude_bin = shutil.which("claude")
    if not claude_bin:
        return None

    try:
        proc = await asyncio.create_subprocess_exec(
            claude_bin,
            "--print",
            "--allowedTools", "Write,Edit,Read",
            "--no-update-check",
            prompt,
            cwd=str(sandbox),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "CLAUDE_NONINTERACTIVE": "1"},
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        if proc.returncode != 0:
            log.warning("claude CLI exited %d: %s", proc.returncode, stderr.decode()[:300])
            return None
        return stdout.decode(errors="replace")
    except asyncio.TimeoutError:
        log.warning("claude CLI timed out")
        try:
            proc.kill()  # type: ignore[union-attr]
        except Exception:
            pass
        return None
    except Exception as e:
        log.warning("claude CLI error: %s", e)
        return None


async def run_via_sdk(prompt: str, sandbox: Path) -> Optional[str]:
    """Use the Anthropic Python SDK to generate the integration file directly."""
    try:
        import anthropic

        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            return None

        client = anthropic.AsyncAnthropic(api_key=api_key)
        message = await client.messages.create(
            model="claude-opus-4-7",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )

        content = message.content[0].text if message.content else ""
        # Extract the Python code block
        code = _extract_code_block(content)
        if code:
            (sandbox / "integration.py").write_text(code)
        return content

    except ImportError:
        log.warning("anthropic package not installed")
        return None
    except Exception as e:
        log.warning("SDK run failed: %s", e)
        return None


def _extract_code_block(text: str) -> str:
    """Pull the first ```python ... ``` block from LLM output."""
    import re
    m = re.search(r"```(?:python)?\n(.*?)```", text, re.DOTALL)
    if m:
        return m.group(1).strip()
    # Fallback: look for lines that look like Python
    lines = text.splitlines()
    code_lines = [l for l in lines if l.startswith(("import ", "from ", "async def ", "def ", "DEVICE_", "#"))]
    return "\n".join(code_lines) if len(code_lines) > 4 else ""


def _build_diff(file_path: Path, content: str) -> str:
    lines = content.splitlines()
    added = "\n".join(f"+{l}" for l in lines)
    return f"--- /dev/null\n+++ {file_path.name}\n@@ -0,0 +1,{len(lines)} @@\n{added}"


async def run_device_analysis(device_context: dict) -> dict:
    """
    Run Claude analysis for an unknown device.
    Returns a dict suitable for inserting into claude_staged_changes.
    """
    prompt = _build_prompt(device_context)
    sandbox = Path(tempfile.mkdtemp(prefix="homelab-claude-"))

    try:
        # Try CLI first, then SDK
        output = await run_via_cli(prompt, sandbox) or await run_via_sdk(prompt, sandbox)

        integration_file = sandbox / "integration.py"

        if not integration_file.exists():
            # Neither CLI nor SDK produced a file — generate a placeholder
            log.info("No integration file generated; creating placeholder")
            ip = device_context.get("ip", "unknown")
            ports = device_context.get("open_ports", [])
            placeholder = textwrap.dedent(f"""\
                # Auto-generated placeholder — review and complete manually
                DEVICE_TYPE = "unknown"
                DEVICE_LABEL = "Unknown Device ({ip})"

                async def enrich(ip: str) -> list[dict]:
                    # TODO: implement service discovery for ports {ports}
                    return []
            """)
            integration_file.write_text(placeholder)
            output = output or "(generated via placeholder)"

        content = integration_file.read_text()
        diff = _build_diff(integration_file, content)

        # Derive reason from LLM output or build a default
        reason = _extract_reason(output or "", device_context)

        return {
            "sandbox_dir": str(sandbox),
            "generated_files": [str(integration_file)],
            "diff_preview": diff,
            "reason": reason,
        }

    except Exception as e:
        log.error("run_device_analysis failed: %s", e)
        shutil.rmtree(sandbox, ignore_errors=True)
        raise


def _extract_reason(output: str, ctx: dict) -> str:
    """Pull a one-line device identification from the LLM output."""
    for line in output.splitlines():
        l = line.strip().lower()
        if any(k in l for k in ("this device", "device is", "appears to be", "likely", "identified")):
            return line.strip()[:200]
    ip = ctx.get("ip", "unknown")
    ports = ctx.get("open_ports", [])
    return f"Unknown device at {ip} with open ports {ports} — integration generated for review."


async def apply_change(change_id: str, sandbox_dir: str, generated_files: list[str]) -> list[str]:
    """
    Copy approved generated files from sandbox to the integrations directory.
    Returns list of destination paths.
    """
    INTEGRATIONS_DIR.mkdir(parents=True, exist_ok=True)
    copied = []
    for src_path in generated_files:
        src = Path(src_path)
        if not src.exists():
            log.warning("Generated file missing: %s", src)
            continue
        # Namespace by change_id to avoid collisions
        dest = INTEGRATIONS_DIR / f"{change_id[:8]}_{src.name}"
        shutil.copy2(src, dest)
        copied.append(str(dest))
        log.info("Applied integration file: %s", dest)

    shutil.rmtree(sandbox_dir, ignore_errors=True)
    return copied
