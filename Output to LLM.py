#!/usr/bin/env python3
"""
nmap_to_llama.py
- Validate IP input
- Run nmap (XML output)
- Parse important fields (open ports, services, versions, host info)
- Send a concise prompt to local Ollama (Llama 3.1) for analysis
"""

#chat transcript used: https://chatgpt.com/share/69041cad-5b04-8013-81df-2438c29ed0ca

import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import requests
import textwrap
import sys
import shutil

OLLAMA_URL = "http://localhost:11434/v1/chat/completions"  # OpenAI-style endpoint Ollama supports
MODEL = "llama3.1:8b"  # change if needed
NMAP_ARGS = ["-sV", "-O", "-Pn", "-oX", "-"]  # service/version detection, OS, no ping, output XML to stdout


def validate_ip(ip_str: str) -> str:
    """Validate IPv4 or IPv6; raise ValueError if invalid."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return str(ip)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip_str}")


def check_prereqs():
    """Ensure nmap is available."""
    if not shutil.which("nmap"):
        raise EnvironmentError("nmap not found in PATH. Please install nmap and retry.")


def run_nmap(ip: str, extra_args=None, timeout=120) -> str:
    """Run nmap and return XML output as string."""
    if extra_args is None:
        extra_args = []
    cmd = ["nmap"] + NMAP_ARGS + extra_args + [ip]
    # example: nmap -sV -O -Pn -oX - 1.2.3.4
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        # nmap returns non-zero for some benign reasons; include stderr for debugging
        raise RuntimeError(f"nmap error (code {proc.returncode}):\n{proc.stderr.strip()}")
    return proc.stdout


def parse_nmap_xml(xml_text: str) -> dict:
    """
    Parse nmap XML and extract a concise summary.
    Returns dict with host_info and ports list.
    """
    root = ET.fromstring(xml_text)
    # nmaprun -> host (we'll handle first host)
    host = root.find("host")
    if host is None:
        return {"hostnames": [], "addresses": [], "ports": [], "os": None, "raw_host_state": None}

    # addresses
    addresses = []
    for addr in host.findall("address"):
        addr_type = addr.get("addrtype")
        addresses.append({"addr": addr.get("addr"), "type": addr_type})

    # hostnames
    hostnames = []
    hn = host.find("hostnames")
    if hn is not None:
        for name in hn.findall("hostname"):
            hostnames.append({"name": name.get("name"), "type": name.get("type")})

    # status
    status = host.find("status")
    host_state = status.get("state") if status is not None else None

    # ports
    ports = []
    ports_node = host.find("ports")
    if ports_node is not None:
        for p in ports_node.findall("port"):
            portid = p.get("portid")
            proto = p.get("protocol")
            state_node = p.find("state")
            state = state_node.get("state") if state_node is not None else None
            service_node = p.find("service")
            service = {}
            if service_node is not None:
                service = {
                    "name": service_node.get("name"),
                    "product": service_node.get("product"),
                    "version": service_node.get("version"),
                    "extrainfo": service_node.get("extrainfo"),
                    "conf": service_node.get("conf"),
                }
            ports.append({"port": int(portid), "proto": proto, "state": state, "service": service})

    # os (best-guess)
    os_node = host.find("os")
    os_guess = None
    if os_node is not None:
        osmatch = os_node.find("osmatch")
        if osmatch is not None:
            os_guess = {"name": osmatch.get("name"), "accuracy": osmatch.get("accuracy")}

    return {
        "host_state": host_state,
        "addresses": addresses,
        "hostnames": hostnames,
        "ports": ports,
        "os_guess": os_guess,
    }


def build_prompt(summary: dict, raw_xml: str = None, max_chars=3000) -> str:
    """
    Build a prompt to send to Llama for analysis.
    We include a concise summary and optionally the (truncated) raw XML for deeper parsing.
    """
    header = "You are a cybersecurity analyst. Examine the nmap scan results for potential issues and next steps.\n"
    host_info = []
    for a in summary["addresses"]:
        host_info.append(f"- {a['type']}: {a['addr']}")
    if summary["hostnames"]:
        host_info.append("- hostnames: " + ", ".join(h["name"] for h in summary["hostnames"]))
    if summary["os_guess"]:
        host_info.append(f"- OS guess: {summary['os_guess']['name']} (accuracy {summary['os_guess']['accuracy']})")
    host_info.append(f"- Host state: {summary.get('host_state')}")
    host_block = "Host info:\n" + "\n".join(host_info)

    ports_block_lines = []
    for p in sorted(summary["ports"], key=lambda x: x["port"]):
        svc = p["service"]
        svc_desc = svc.get("name") if svc else None
        prod_ver = ""
        if svc and svc.get("product"):
            prod_ver = f" ({svc.get('product')}{' ' + svc.get('version') if svc.get('version') else ''})"
        ports_block_lines.append(f" - {p['port']}/{p['proto']} {p['state']}: {svc_desc or ''}{prod_ver}")

    ports_block = "Open/filtered ports and services:\n" + ("\n".join(ports_block_lines) if ports_block_lines else " - none found")

    prompt = textwrap.dedent(
        f"""{header}
{host_block}

{ports_block}

Please:
1) Give a short (3-6 bullet) prioritized list of security implications for the services found.
2) Suggest immediate next steps (tools/commands/config changes) to investigate or mitigate (be practical).
3) Indicate any false positives or caveats you think might be present based only on nmap output.

Be concise and avoid full exploit instructions.

"""
    )

    # Optionally attach truncated raw xml (for deeper context)
    if raw_xml:
        raw_to_attach = raw_xml.strip()
        if len(raw_to_attach) > max_chars:
            raw_to_attach = raw_to_attach[: max_chars] + "\n...[truncated]"
        prompt += "\n\nAdditional raw nmap output (truncated):\n" + raw_to_attach

    return prompt


def ask_llama(prompt: str) -> str:
    """Send prompt to local Ollama (Llama 3.1) and return assistant's reply."""
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "You are an expert cybersecurity analyst."},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 800,
        "temperature": 0.2,
    }
    resp = requests.post(OLLAMA_URL, json=payload, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    # Ollama returns an OpenAI-like shape: choices[0].message.content
    try:
        return data["choices"][0]["message"]["content"]
    except Exception:
        # Fallback: return raw text
        return resp.text


def main():
    check_prereqs()
    if len(sys.argv) >= 2:
        ip_in = sys.argv[1]
    else:
        ip_in = input("Enter target IP (IPv4/IPv6): ").strip()

    try:
        ip = validate_ip(ip_in)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"Running nmap against {ip} ... (this can take a while)")
    try:
        xml = run_nmap(ip)
    except Exception as e:
        print("nmap failed:", e)
        sys.exit(1)

    summary = parse_nmap_xml(xml)
    prompt = build_prompt(summary, raw_xml=xml, max_chars=2000)

    print("Asking Llama to analyze results...")
    try:
        analysis = ask_llama(prompt)
    except Exception as e:
        print("Failed to query Llama:", e)
        sys.exit(1)

    print("\n=== Llama Analysis ===\n")
    print(analysis)
    print("\n=== End ===\n")


if __name__ == "__main__":
    main()
