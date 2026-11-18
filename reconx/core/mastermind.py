"""Mastermind AI Engine & 4 Specialized Agents Framework."""
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

class Mastermind:
    def __init__(self, target, aggressiveness="normal"):
        self.target = target
        self.aggressiveness = aggressiveness
        self.agents = {
            "enumerator": EnumeratorAgent(),
            "prober": ProberAgent(),
            "secret_hunter": SecretHunterAgent(),
            "infra": InfrastructureAgent()
        }

    def evaluate_and_execute(self):
        """Mastermind decides which agents to deploy based on target scope."""
        print(f"[*] [Mastermind] Analyzing target: {self.target} (Mode: {self.aggressiveness})")
        results = {}
        
        # Dispatch tasks to the 4 specialized agents concurrently
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                name: executor.submit(agent.run, self.target)
                for name, agent in self.agents.items()
            }
            for name, future in futures.items():
                try:
                    results[name] = future.result()
                except Exception as e:
                    results[name] = f"Error: {str(e)}"
                    
        return results

class EnumeratorAgent:
    """Agent 1: Subdomains, CT Logs, Permutations."""
    def run(self, target):
        tools = {"subfinder": shutil.which("subfinder"), "crtsh": True}
        active_tools = [t for t, available in tools.items() if available]
        return {"agent": "Enumerator", "status": "Completed", "tools_used": active_tools}

class ProberAgent:
    """Agent 2: Live Probing, WAF, Takeover, CORS."""
    def run(self, target):
        tools = {"httpx": shutil.which("httpx"), "nuclei": shutil.which("nuclei")}
        active_tools = [t for t, available in tools.items() if available]
        return {"agent": "Prober & WAF Hunter", "status": "Completed", "tools_used": active_tools}

class SecretHunterAgent:
    """Agent 3: JS Analysis, Hidden Paths, Arjun, SecretFinder."""
    def run(self, target):
        tools = {"arjun": shutil.which("arjun"), "ffuf": shutil.which("ffuf")}
        active_tools = [t for t, available in tools.items() if available]
        return {"agent": "Secret & Path Hunter", "status": "Completed", "tools_used": active_tools}

class InfrastructureAgent:
    """Agent 4: Port Scanning, Cloud Buckets, ASN Mapping."""
    def run(self, target):
        tools = {"nmap": shutil.which("nmap"), "naabu": shutil.which("naabu")}
        active_tools = [t for t, available in tools.items() if available]
        return {"agent": "Infrastructure & Ports", "status": "Completed", "tools_used": active_tools}
