import sys
# Python 3.14+ compatibility workaround for google protobuf upb C-extension TypeError
sys.modules['google._upb._message'] = None

import os
import json
import sqlite3
import datetime
from typing import List, Optional
import requests
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import google.generativeai as genai

# Setup FastAPI App
app = FastAPI(
    title="TInSOW Backend",
    description="Threat Intel & SecOps Workspace Backend API",
    version="1.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json"
)


# Workspace Paths
# For Vercel/serverless environments, use /tmp for SQLite database if writable, or local directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("DB_PATH", "/tmp/intel.db" if os.environ.get("VERCEL") else os.path.join(BASE_DIR, "intel.db"))
CONFIG_PATH = os.environ.get("CONFIG_PATH", "/tmp/config.json" if os.environ.get("VERCEL") else os.path.join(BASE_DIR, "config.json"))
STATIC_DIR = os.environ.get("STATIC_DIR", os.path.join(BASE_DIR, "public"))


# -------------------------------------------------------------
# DATABASE INITIALIZATION & OPERATIONS
# -------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create analysis runs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analysis_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_name TEXT NOT NULL,
        summary TEXT,
        technical_details TEXT,
        affected_systems TEXT, -- JSON serialized list
        risk_score INTEGER,
        risk_justification TEXT,
        mitre_attack TEXT, -- JSON serialized list
        indicators TEXT, -- JSON serialized list
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Create generated artifacts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER,
        artifact_type TEXT, -- 'siem' or 'soar'
        platform TEXT,
        name TEXT,
        content TEXT,
        explanation TEXT,
        FOREIGN KEY(run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
    )
    """)
    
    conn.commit()
    conn.close()

# Initialize Database on import safely
try:
    # Ensure directory for DB exists
    db_dir = os.path.dirname(DB_PATH)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    init_db()
except Exception as e:
    print(f"Database initialization warning: {e}", sys.stderr)


# -------------------------------------------------------------
# CONFIGURATION SETTINGS
# -------------------------------------------------------------
def get_config():
    if not os.path.exists(CONFIG_PATH):
        default_config = {
            "gemini_api_key": os.environ.get("GEMINI_API_KEY", ""),
            "otx_api_key": os.environ.get("OTX_API_KEY", ""),
            "model": "gemini-3.5-flash"
        }
        try:
            config_dir = os.path.dirname(CONFIG_PATH)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)
            with open(CONFIG_PATH, "w") as f:
                json.dump(default_config, f, indent=4)
        except Exception as e:
            print(f"Error writing default config: {e}", sys.stderr)
        return default_config

    
    with open(CONFIG_PATH, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {
                "gemini_api_key": "",
                "otx_api_key": "",
                "model": "gemini-3.5-flash"
            }

def save_config(config_data):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config_data, f, indent=4)

# -------------------------------------------------------------
# PYDANTIC SCHEMAS FOR INTERACTION
# -------------------------------------------------------------
class ConfigPayload(BaseModel):
    gemini_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    model: Optional[str] = "gemini-3.5-flash"

class CvePayload(BaseModel):
    cve_id: str

class OtxPayload(BaseModel):
    indicator_type: str
    indicator_value: str

class RawPayload(BaseModel):
    text: str

# -------------------------------------------------------------
# STRUCTURING GEMINI RESPONSE SCHEMAS (Pydantic v2 Compatible)
# -------------------------------------------------------------
class MitreTechnique(BaseModel):
    tactic: str = Field(description="The MITRE ATT&CK Tactic (e.g., Initial Access, Execution)")
    technique_id: str = Field(description="The MITRE ATT&CK Technique ID (e.g., T1566)")
    technique_name: str = Field(description="The MITRE ATT&CK Technique Name (e.g., Phishing)")
    justification: str = Field(description="Brief explanation of why this technique applies to the threat")

class IndicatorOfCompromise(BaseModel):
    type: str = Field(description="Type of IOC: IP, Domain, Hash-MD5, Hash-SHA256, FilePath, RegistryKey, URL, Hostname")
    value: str = Field(description="The value of the indicator")
    description: str = Field(description="What this indicator represents")

class SiemRule(BaseModel):
    platform: str = Field(description="Target platform: Sigma, Elastic EQL, Splunk SPL")
    name: str = Field(description="A descriptive name for the detection rule")
    content: str = Field(description="The actual rule code/markup matching the target platform format")
    explanation: str = Field(description="Explanation of what this rule detects and how it works")

class SoarPlaybook(BaseModel):
    platform: str = Field(description="Target platform: Shuffle Workflow, Python Script")
    name: str = Field(description="A descriptive name for the SOAR playbook")
    content: str = Field(description="The actual playbook content (YAML configuration or Python code)")
    explanation: str = Field(description="Explanation of the response steps in this playbook")

class ThreatAnalysisResponse(BaseModel):
    threat_name: str = Field(description="Name of the threat, CVE, or malware campaign")
    summary: str = Field(description="High-level executive summary of the threat")
    technical_details: str = Field(description="Detailed technical description of the threat vector and behavior")
    affected_systems: List[str] = Field(description="List of operating systems, software, or hardware affected")
    risk_score: int = Field(description="A calculated risk score from 0 to 100 based on severity and exploitability")
    risk_justification: str = Field(description="Justification for the risk score, referencing CVSS or impact metrics")
    mitre_attack: List[MitreTechnique] = Field(description="Mapped MITRE ATT&CK techniques")
    indicators: List[IndicatorOfCompromise] = Field(description="Extracted Indicators of Compromise (IOCs)")
    siem_rules: List[SiemRule] = Field(description="Generated SIEM rules for detection")
    soar_playbooks: List[SoarPlaybook] = Field(description="Generated SOAR playbooks for automated response")

# -------------------------------------------------------------
# GEMINI AI SERVICE CONNECTIVITY
# -------------------------------------------------------------
SYSTEM_INSTRUCTION = """
You are a Cyber Threat Intelligence (CTI) AI Analyst. Your task is to analyze threat information, calculate a risk score (0-100) aligned with the MITRE ATT&CK framework, extract indicators of compromise (IOCs), and generate SIEM detection rules and SOAR response playbooks.

Your output MUST be a valid JSON object matching the requested schema structure. Do not include markdown wraps like ```json in the actual output if using response_mime_type="application/json".

For SIEM rules:
1. Always generate a SIGMA rule in valid YAML. Make sure to specify titles, descriptions, logsource (product, service), detection selections, condition, falsepositives, level.
2. Generate Elastic EQL or Splunk SPL queries that look like real, ready-to-deploy detection rules.

For SOAR playbooks:
1. Generate a Shuffle Workflow in clean YAML format representing the automation nodes (triggers, OTX reputation checking, host isolation, Slack alerts, firewall blocks).
2. Generate a Python script that contains ready-to-run automation logic using common packages (requests, subprocess, json) for API blocks, endpoint isolation (e.g., netsh, iptables), or notifications.

Ensure the highest quality of technical descriptions, threat modeling mapping, and rule formats.
"""

def generate_threat_analysis(prompt: str, config: dict) -> ThreatAnalysisResponse:
    api_key = config.get("gemini_api_key")
    if not api_key:
        raise HTTPException(status_code=400, detail="Gemini API Key is not configured. Go to Settings.")
    
    model_name = config.get("model", "gemini-3.5-flash")
    
    try:
        genai.configure(api_key=api_key)
        
        # Configure model
        model = genai.GenerativeModel(
            model_name=model_name,
            system_instruction=SYSTEM_INSTRUCTION
        )
        
        # Call model with structured JSON schema constraints
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                response_mime_type="application/json",
                response_schema=ThreatAnalysisResponse
            )
        )
        
        # Parse the JSON response
        result_json = json.loads(response.text)
        return ThreatAnalysisResponse(**result_json)
        
    except Exception as e:
        print(f"Error calling Gemini: {e}")
        # Try raw prompt JSON request if schema parsing failed directly
        try:
            model = genai.GenerativeModel(model_name=model_name, system_instruction=SYSTEM_INSTRUCTION)
            response = model.generate_content(
                f"{prompt}\n\nPlease respond with valid JSON matching the schema representation: {ThreatAnalysisResponse.model_json_schema()}"
            )
            result_json = json.loads(response.text)
            return ThreatAnalysisResponse(**result_json)
        except Exception as inner_e:
            raise HTTPException(status_code=500, detail=f"Gemini API failure: {str(e)} -> fallback: {str(inner_e)}")

# -------------------------------------------------------------
# SAVE RUNS TO DATABASE
# -------------------------------------------------------------
def save_analysis_run(analysis: ThreatAnalysisResponse) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Save the analysis run
    cursor.execute("""
    INSERT INTO analysis_runs (
        threat_name, summary, technical_details, affected_systems, 
        risk_score, risk_justification, mitre_attack, indicators
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        analysis.threat_name,
        analysis.summary,
        analysis.technical_details,
        json.dumps(analysis.affected_systems),
        analysis.risk_score,
        analysis.risk_justification,
        json.dumps([m.model_dump() for m in analysis.mitre_attack]),
        json.dumps([i.model_dump() for i in analysis.indicators])
    ))
    
    run_id = cursor.lastrowid
    
    # Save generated SIEM rules
    for rule in analysis.siem_rules:
        cursor.execute("""
        INSERT INTO artifacts (run_id, artifact_type, platform, name, content, explanation)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (run_id, 'siem', rule.platform, rule.name, rule.content, rule.explanation))
        
    # Save generated SOAR playbooks
    for playbook in analysis.soar_playbooks:
        cursor.execute("""
        INSERT INTO artifacts (run_id, artifact_type, platform, name, content, explanation)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (run_id, 'soar', playbook.platform, playbook.name, playbook.content, playbook.explanation))
        
    conn.commit()
    conn.close()
    return run_id

# -------------------------------------------------------------
# API ROUTING & LOGIC
# -------------------------------------------------------------
@app.get("/api/config")
def read_config_api():
    config = get_config()
    return {
        "gemini_configured": bool(config.get("gemini_api_key")),
        "otx_configured": bool(config.get("otx_api_key")),
        "model": config.get("model", "gemini-3.5-flash")
    }

@app.post("/api/config")
def write_config_api(payload: ConfigPayload):
    config = get_config()
    
    if payload.gemini_api_key is not None:
        config["gemini_api_key"] = payload.gemini_api_key
    if payload.otx_api_key is not None:
        config["otx_api_key"] = payload.otx_api_key
    if payload.model is not None:
        config["model"] = payload.model
        
    save_config(config)
    
    return {
        "gemini_configured": bool(config.get("gemini_api_key")),
        "otx_configured": bool(config.get("otx_api_key")),
        "model": config.get("model", "gemini-3.5-flash")
    }

@app.post("/api/test-connections")
def test_connections_api():
    config = get_config()
    gemini_key = config.get("gemini_api_key")
    otx_key = config.get("otx_api_key")
    
    results = {
        "gemini_ok": False,
        "gemini_model": config.get("model"),
        "gemini_error": None,
        "otx_ok": False,
        "otx_error": None
    }
    
    # Test Gemini
    if gemini_key:
        try:
            genai.configure(api_key=gemini_key)
            model = genai.GenerativeModel(model_name=config.get("model", "gemini-3.5-flash"))
            # Minimal prompt test
            response = model.generate_content("Respond with OK")
            if response.text:
                results["gemini_ok"] = True
        except Exception as e:
            results["gemini_error"] = str(e)
            
    # Test OTX
    if otx_key:
        try:
            # Query standard indicators endpoint test
            url = "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general"
            headers = {"X-OTX-API-KEY": otx_key}
            res = requests.get(url, headers=headers, timeout=5)
            if res.status_code == 200:
                results["otx_ok"] = True
            else:
                results["otx_error"] = f"HTTP {res.status_code}: {res.text[:100]}"
        except Exception as e:
            results["otx_error"] = str(e)
            
    return results

# Stats summary API
@app.get("/api/stats")
def get_stats_api():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM analysis_runs")
    total_analyzed = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM analysis_runs WHERE risk_score >= 70")
    high_risk = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM artifacts WHERE artifact_type = 'siem'")
    siem_rules = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM artifacts WHERE artifact_type = 'soar'")
    soar_playbooks = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "total_analyzed": total_analyzed,
        "high_risk": high_risk,
        "siem_rules": siem_rules,
        "soar_playbooks": soar_playbooks
    }

# History list API
@app.get("/api/history")
def get_history_api():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT id, threat_name, summary, risk_score, timestamp, indicators 
    FROM analysis_runs 
    ORDER BY timestamp DESC
    """)
    rows = cursor.fetchall()
    
    history_list = []
    for r in rows:
        try:
            iocs = json.loads(r["indicators"])
            ioc_count = len(iocs)
        except Exception:
            ioc_count = 0
            
        history_list.append({
            "id": r["id"],
            "threat_name": r["threat_name"],
            "summary": r["summary"],
            "risk_score": r["risk_score"],
            "timestamp": r["timestamp"],
            "ioc_count": ioc_count
        })
        
    conn.close()
    return history_list

# History detail API
@app.get("/api/history/{run_id}")
def get_history_detail_api(run_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,))
    run_row = cursor.fetchone()
    
    if not run_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Analysis run not found")
        
    cursor.execute("SELECT * FROM artifacts WHERE run_id = ?", (run_id,))
    art_rows = cursor.fetchall()
    
    siem_rules = []
    soar_playbooks = []
    
    for art in art_rows:
        art_data = {
            "platform": art["platform"],
            "name": art["name"],
            "content": art["content"],
            "explanation": art["explanation"]
        }
        if art["artifact_type"] == 'siem':
            siem_rules.append(art_data)
        else:
            soar_playbooks.append(art_data)
            
    result = {
        "threat_name": run_row["threat_name"],
        "summary": run_row["summary"],
        "technical_details": run_row["technical_details"],
        "affected_systems": json.loads(run_row["affected_systems"]),
        "risk_score": run_row["risk_score"],
        "risk_justification": run_row["risk_justification"],
        "mitre_attack": json.loads(run_row["mitre_attack"]),
        "indicators": json.loads(run_row["indicators"]),
        "siem_rules": siem_rules,
        "soar_playbooks": soar_playbooks
    }
    
    conn.close()
    return result

# Artifacts list (Exporter repo) API
@app.get("/api/artifacts")
def get_artifacts_api():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT a.id, a.artifact_type, a.platform, a.name, a.content, a.explanation, r.threat_name
    FROM artifacts a
    JOIN analysis_runs r ON a.run_id = r.id
    ORDER BY a.id DESC
    """)
    rows = cursor.fetchall()
    
    artifacts = []
    for r in rows:
        artifacts.append({
            "id": r["id"],
            "artifact_type": r["artifact_type"],
            "platform": r["platform"],
            "name": r["name"],
            "content": r["content"],
            "explanation": r["explanation"],
            "threat_name": r["threat_name"]
        })
        
    conn.close()
    return artifacts

# Recent CVE feed from CIRCL API (with hardcoded fallbacks)
@app.get("/api/cve-feed")
def get_cve_feed_api():
    fallback_feed = [
        {
            "id": "CVE-2024-3094",
            "description": "Backdoor in upstream xz-utils library (liblzma) starting in version 5.6.0. An attacker can inject malicious code into OpenSSH via systemd integration, enabling remote code execution.",
            "published_date": "2024-03-29",
            "cvss": 10.0
        },
        {
            "id": "CVE-2024-21626",
            "description": "In runc (container runtime) prior to version 1.1.12, container escaping is possible due to file descriptor leakage. An attacker can access host file systems from within the container.",
            "published_date": "2024-01-31",
            "cvss": 8.6
        },
        {
            "id": "CVE-2023-38831",
            "description": "Vulnerability in WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to open a benign file inside a ZIP archive containing specially crafted folders.",
            "published_date": "2023-08-24",
            "cvss": 7.8
        },
        {
            "id": "CVE-2024-6387",
            "description": "A signal handler race condition vulnerability in OpenSSH Server (sshd) allows remote unauthenticated code execution as root on glibc-based Linux systems (RegreSSHion).",
            "published_date": "2024-07-01",
            "cvss": 8.1
        },
        {
            "id": "CVE-2024-49113",
            "description": "Microsoft Windows MS-RPC Remote Code Execution Vulnerability (vulnerability enables unauthenticated lateral movement and threat propagation).",
            "published_date": "2024-10-08",
            "cvss": 9.8
        }
    ]
    
    try:
        # Fetch from CIRCL CVE API (returns recent 30 entries)
        res = requests.get("https://cve.circl.lu/api/last", timeout=4)
        if res.status_code == 200:
            cves = res.json()
            feed = []
            for cve in cves[:8]:
                # 1. Parse modern CVE JSON 5.0 format
                if "cveMetadata" in cve and "containers" in cve:
                    cve_id = cve["cveMetadata"].get("cveId", "Unknown")
                    
                    # Extract description
                    descriptions = cve["containers"].get("cna", {}).get("descriptions", [])
                    desc = descriptions[0].get("value", "No description available.") if descriptions else "No description available."
                    
                    # Extract date
                    pub_date = cve["cveMetadata"].get("datePublished", "N/A")[:10]
                    
                    # Extract CVSS
                    cvss = None
                    metrics = cve["containers"].get("cna", {}).get("metrics", [])
                    if metrics:
                        # Try parsing v4.0, v3.1, or v3.0 scores
                        for m in metrics:
                            if "cvssV4_0" in m:
                                cvss = m["cvssV4_0"].get("baseScore")
                                break
                            elif "cvssV3_1" in m:
                                cvss = m["cvssV3_1"].get("baseScore")
                                break
                            elif "cvssV3_0" in m:
                                cvss = m["cvssV3_0"].get("baseScore")
                                break
                    
                    feed.append({
                        "id": cve_id,
                        "description": desc,
                        "published_date": pub_date,
                        "cvss": cvss
                    })
                
                # 2. Parse legacy schema format
                else:
                    feed.append({
                        "id": cve.get("id"),
                        "description": cve.get("summary", "No description available."),
                        "published_date": cve.get("Published", "N/A")[:10] if cve.get("Published") else "N/A",
                        "cvss": cve.get("cvss")
                    })
            
            # Mix standard ones in if feed from CIRCL is small
            if len(feed) < 3:
                return fallback_feed
            return feed
    except Exception as e:
        print(f"CIRCL API down, returning fallback: {e}")
        
    return fallback_feed

# -------------------------------------------------------------
# SPECIFIC ANALYZERS (CVE, OTX, RAW TEXT)
# -------------------------------------------------------------
@app.post("/api/analyze/cve")
def analyze_cve_api(payload: CvePayload):
    config = get_config()
    cve_id = payload.cve_id.strip()
    
    # 1. Fetch details about the CVE
    cve_details = ""
    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        res = requests.get(url, timeout=5)
        if res.status_code == 200 and res.json():
            data = res.json()
            if "cveMetadata" in data and "containers" in data:
                cve_id_val = data["cveMetadata"].get("cveId", cve_id)
                # CVSS
                cvss_val = "Unknown"
                metrics = data["containers"].get("cna", {}).get("metrics", [])
                if metrics:
                    for m in metrics:
                        for cvss_key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                            if cvss_key in m:
                                cvss_val = m[cvss_key].get("baseScore", "Unknown")
                                break
                        if cvss_val != "Unknown":
                            break
                # Summary/Description
                descriptions = data["containers"].get("cna", {}).get("descriptions", [])
                summary_val = descriptions[0].get("value", "") if descriptions else ""
                # Vulnerable products
                vulnerable_list = []
                affected = data["containers"].get("cna", {}).get("affected", [])
                for aff in affected:
                    vendor = aff.get("vendor", "")
                    product = aff.get("product", "")
                    versions = [v.get("version", "") for v in aff.get("versions", [])]
                    vulnerable_list.append(f"{vendor} {product} ({', '.join(versions)})")
                vulnerable_products_val = ", ".join(vulnerable_list)
                # References
                refs = [r.get("url", "") for r in data["containers"].get("cna", {}).get("references", [])]
                references_val = ", ".join(refs)
                
                cve_details = f"Vulnerability ID: {cve_id_val}\n"
                cve_details += f"CVSS Score: {cvss_val}\n"
                cve_details += f"Summary: {summary_val}\n"
                cve_details += f"Vulnerable Products: {vulnerable_products_val[:1000]}\n"
                cve_details += f"References: {references_val[:800]}\n"
            else:
                cve_details = f"Vulnerability ID: {data.get('id')}\n"
                cve_details += f"CVSS Score: {data.get('cvss', 'Unknown')}\n"
                cve_details += f"Summary: {data.get('summary', '')}\n"
                cve_details += f"Vulnerable Products: {', '.join(data.get('vulnerable_configuration', []))[:1000]}\n"
                cve_details += f"References: {', '.join(data.get('references', []))[:800]}\n"
    except Exception as e:
        print(f"Failed to fetch CVE data: {e}")
        
    # Build prompt
    prompt = f"Analyze CVE: {cve_id}.\n"
    if cve_details:
        prompt += f"Here is the database record for this vulnerability:\n{cve_details}\n"
    else:
        prompt += f"I could not retrieve active API metadata for {cve_id}. Please use your internal database/knowledge base to analyze this vulnerability."
        
    prompt += "\nPlease perform the contextual analysis, score it, map MITRE ATT&CK techniques, extract relevant indicators (filenames, registry paths, network ports, etc.), and write SIEM Rules and SOAR Playbooks."
    
    # 2. Call Gemini
    analysis = generate_threat_analysis(prompt, config)
    
    # Override threat name to make sure it matches the input
    analysis.threat_name = cve_id
    
    # 3. Save to database
    save_analysis_run(analysis)
    
    return analysis

@app.post("/api/analyze/otx")
def analyze_otx_api(payload: OtxPayload):
    config = get_config()
    otx_key = config.get("otx_api_key")
    
    ind_type = payload.indicator_type
    ind_val = payload.indicator_value.strip()
    
    # 1. Fetch data from OTX
    otx_details = ""
    if otx_key:
        try:
            # Map type to OTX indicator format
            otx_type_map = {
                "IPv4": "IPv4",
                "domain": "domain",
                "hostname": "hostname",
                "file": "file",
                "url": "url"
            }
            mapped_type = otx_type_map.get(ind_type, "hostname")
            url = f"https://otx.alienvault.com/api/v1/indicators/{mapped_type}/{ind_val}/general"
            headers = {"X-OTX-API-KEY": otx_key}
            
            res = requests.get(url, headers=headers, timeout=6)
            if res.status_code == 200:
                data = res.json()
                pulse_info = data.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])
                
                otx_details = f"Indicator: {ind_val} (Type: {ind_type})\n"
                otx_details += f"OTX Reputation score/indicator matches: Found in {len(pulses)} pulses.\n"
                
                pulse_summaries = []
                for p in pulses[:5]: # Take first 5 pulses
                    p_desc = f"- Pulse: {p.get('name')} (Tags: {', '.join(p.get('tags', []))}). Description: {p.get('description', 'No desc')}"
                    pulse_summaries.append(p_desc)
                
                otx_details += "\n".join(pulse_summaries)
        except Exception as e:
            print(f"Failed to fetch OTX indicator data: {e}")
            
    # Prompt construction
    prompt = f"Analyze Threat Indicator: {ind_val} ({ind_type}).\n"
    if otx_details:
        prompt += f"Here is AlienVault OTX Threat Intelligence context:\n{otx_details}\n"
    else:
        prompt += f"I have no active AlienVault OTX API context for this indicator. Please evaluate this indicator based on common security intelligence parameters."
        
    prompt += "\nEvaluate potential behaviors associated with this threat, assign a risk score, map it to the MITRE ATT&CK chain, extract indicators, and draft SIEM Rules and SOAR Response Playbooks to isolate/alert/detect this indicator."
    
    # 2. Call Gemini
    analysis = generate_threat_analysis(prompt, config)
    
    # Override threat name
    analysis.threat_name = f"Indicator: {ind_val}"
    
    # 3. Save
    save_analysis_run(analysis)
    
    return analysis

@app.post("/api/analyze/raw")
def analyze_raw_api(payload: RawPayload):
    config = get_config()
    raw_text = payload.text.strip()
    
    prompt = f"Analyze the following Raw Threat Intelligence text/logs/bulletin:\n\n{raw_text}\n\n"
    prompt += "Extract the core vulnerability, threat actors, affected systems, map the behavior to MITRE ATT&CK techniques, extract any indicators of compromise (IOCs) such as IPs, URLs, file paths, hashes, and generate SIEM Rules (Sigma, Splunk SPL, Elastic EQL) and SOAR Response Playbooks."
    
    analysis = generate_threat_analysis(prompt, config)
    
    # Set standard threat name if empty
    if not analysis.threat_name or analysis.threat_name == "Unknown":
        analysis.threat_name = f"Raw Text Run {datetime.datetime.now().strftime('%Y%m%d-%H%M')}"
        
    save_analysis_run(analysis)
    
    return analysis

# -------------------------------------------------------------
# SERVING WEB FRONTEND FILES
# -------------------------------------------------------------
# Only mount static files and serve index HTML if NOT running in Vercel.
# Vercel's edge routers will handle this static file routing directly via vercel.json.
if not os.environ.get("VERCEL"):
    try:
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    except Exception as e:
        print(f"Static files mount warning: {e}", sys.stderr)

    @app.get("/", response_class=HTMLResponse)
    def get_dashboard_index():
        index_path = os.path.join(STATIC_DIR, "index.html")
        if not os.path.exists(index_path):
            return HTMLResponse("<h1>Index HTML File not found!</h1>", status_code=404)
        with open(index_path, "r") as f:
            return f.read()

# Start application server handler
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

