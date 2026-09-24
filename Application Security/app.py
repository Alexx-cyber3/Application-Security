import os
import uuid
from typing import Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Add local bin directory to PATH so bundled syft and cosign binaries can be discovered
_file_path = globals().get("__file__")
if _file_path:
    _current_dir = os.path.dirname(os.path.abspath(_file_path))
    _bin_dir = os.path.join(_current_dir, "bin")
    if os.path.exists(_bin_dir):
        _paths = os.environ.get("PATH", "").split(os.pathsep)
        if _bin_dir not in _paths:
            os.environ["PATH"] = _bin_dir + os.pathsep + os.environ.get("PATH", "")

from scanner import SecurityScanner, compute_sbom_diff
from installer import ToolManager

# Create FastAPI app
app = FastAPI(
    title="Software Supply Chain Attestation Engine",
    description="Scan dependencies, verify digital signatures, check vulnerabilities, and attest build compliance.",
    version="1.0.0"
)

# In-memory scan task database
scans = {}

class ScanRequest(BaseModel):
    repo_url: Optional[str] = None
    local_path: Optional[str] = None
    block_threshold: Optional[str] = "CRITICAL"

class DiffRequest(BaseModel):
    base_scan_id: str
    head_scan_id: str

def run_scan_task(scan_id: str, repo_url: Optional[str], local_path: Optional[str], block_threshold: str):
    """Background worker task to execute repository scan."""
    scans[scan_id]["status"] = "running"
    
    scanner = SecurityScanner(repo_url=repo_url, block_threshold=block_threshold, local_path=local_path)
    # Direct reference binding so the list updates live as logs are added by the scanner
    scans[scan_id]["logs"] = scanner.scan_logs
    
    res = scanner.run_full_scan()
    
    if res.get("success", False):
        scans[scan_id]["status"] = "completed"
        scans[scan_id]["result"] = res
    else:
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = res.get("error", "Unknown scanning failure.")

# Create static directories if they don't exist
os.makedirs("static", exist_ok=True)

@app.post("/api/scan")
def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Starts a supply chain verification scan on a repository or local folder."""
    repo_url = request.repo_url.strip() if request.repo_url else None
    local_path = request.local_path.strip() if request.local_path else None
    
    if not repo_url and not local_path:
        raise HTTPException(status_code=400, detail="Either a GitHub repository URL or Local directory path must be provided.")
        
    if repo_url and not repo_url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid GitHub repository URL.")
        
    if local_path and not os.path.exists(local_path):
        raise HTTPException(status_code=400, detail="The specified local directory path does not exist.")
        
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "id": scan_id,
        "status": "pending",
        "repo_url": repo_url if repo_url else f"Local Folder: {local_path}",
        "block_threshold": request.block_threshold,
        "logs": ["Starting scan worker initialization..."],
        "result": None,
        "error": None
    }
    
    # Run in background
    background_tasks.add_task(run_scan_task, scan_id, repo_url, local_path, request.block_threshold)
    
    return {"scan_id": scan_id, "status": "pending"}

@app.get("/api/scan/{scan_id}")
def get_scan_status(scan_id: str):
    """Get the live status and logs of a scan."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan task not found.")
        
    scan_data = scans[scan_id]
    return {
        "id": scan_data["id"],
        "status": scan_data["status"],
        "repo_url": scan_data["repo_url"],
        "block_threshold": scan_data["block_threshold"],
        "logs": scan_data["logs"],
        "error": scan_data["error"],
        "result": scan_data["result"]
    }

@app.get("/api/scans")
def list_completed_scans():
    """Retrieve a list of all completed scans available for comparison."""
    completed = [
        {
            "id": s["id"],
            "repo_url": s["repo_url"],
            "status": s["status"],
            "total_dependencies": s["result"]["verdict"]["summary"]["total_dependencies"] if s["result"] else 0,
            "risk_index": s["result"]["verdict"]["risk_index"] if s["result"] else 0
        }
        for s in scans.values() if s["status"] == "completed"
    ]
    return completed

@app.post("/api/scan/diff")
def diff_scans(request: DiffRequest):
    """Compute SBOM diff and supply chain drift between two completed scans."""
    if request.base_scan_id not in scans or scans[request.base_scan_id]["status"] != "completed":
        raise HTTPException(status_code=400, detail="Base scan not found or not completed.")
    if request.head_scan_id not in scans or scans[request.head_scan_id]["status"] != "completed":
        raise HTTPException(status_code=400, detail="Head scan not found or not completed.")
        
    base_res = scans[request.base_scan_id]["result"]
    head_res = scans[request.head_scan_id]["result"]
    
    diff_data = compute_sbom_diff(base_res, head_res)
    diff_data["base_repo_url"] = scans[request.base_scan_id]["repo_url"]
    diff_data["head_repo_url"] = scans[request.head_scan_id]["repo_url"]
    
    return diff_data

@app.get("/api/tools")
def get_tools_status():
    """Retrieve system status of Syft and Cosign."""
    return ToolManager.check_tools()

@app.post("/api/tools/install/{tool_name}")
def install_tool_endpoint(tool_name: str, background_tasks: BackgroundTasks):
    """Trigger background winget installation of a tool."""
    tool_name = tool_name.lower()
    if tool_name not in ["syft", "cosign"]:
        raise HTTPException(status_code=400, detail="Unsupported tool. Choose 'syft' or 'cosign'.")
        
    status = ToolManager.check_tools()
    if status[tool_name]["available"]:
        return {"success": True, "message": f"{tool_name} is already available."}
        
    def install_worker():
        ToolManager.install_tool(tool_name)
        
    background_tasks.add_task(install_worker)
    return {"success": True, "message": f"Installation of {tool_name} started in the background."}

@app.get("/api/report/{scan_id}", response_class=HTMLResponse)
def generate_audit_report(scan_id: str):
    """Generates an HTML report designed for printing/PDF saving."""
    if scan_id not in scans or scans[scan_id]["status"] != "completed":
        return "<h3>Scan report not available or scan is still running.</h3>", 404
        
    scan_data = scans[scan_id]
    res = scan_data["result"]
    verdict = res["verdict"]
    summary = verdict["summary"]
    deps = res["dependencies"]
    
    slsa = res.get("slsa_provenance", {})
    slsa_level_name = slsa.get("level_name", "Level 0 (Unverified)")
    slsa_details = slsa.get("details", "")
    
    # Sort dependencies: Vulnerable and Unsigned first
    sorted_deps = sorted(
        deps, 
        key=lambda d: (len(d.get("vulnerabilities", [])) > 0, not d.get("signature_verified", False), d.get("risk_score", 0)), 
        reverse=True
    )
    
    # Create HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Software Supply Chain Attestation Report</title>
        <meta charset="utf-8">
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                color: #333;
                line-height: 1.6;
                padding: 40px;
                background-color: #fafafa;
            }}
            .container {{
                max-width: 900px;
                margin: 0 auto;
                background: #fff;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.05);
                border-top: 8px solid;
                border-top-color: { "#d9534f" if verdict["status"] == "FAIL" else "#5cb85c" };
            }}
            .header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 2px solid #eee;
                padding-bottom: 20px;
                margin-bottom: 30px;
            }}
            .title {{
                margin: 0;
                font-size: 24px;
                font-weight: 700;
                color: #2c3e50;
            }}
            .meta-info {{
                font-size: 14px;
                color: #7f8c8d;
            }}
            .verdict-box {{
                background: { "#fdf7f7" if verdict["status"] == "FAIL" else "#f4faf4" };
                border: 1px solid { "#d9534f" if verdict["status"] == "FAIL" else "#5cb85c" };
                color: { "#a94442" if verdict["status"] == "FAIL" else "#3c763d" };
                padding: 20px;
                border-radius: 6px;
                margin-bottom: 20px;
                display: flex;
                align-items: center;
                justify-content: space-between;
            }}
            .verdict-title {{
                font-size: 20px;
                font-weight: bold;
                margin: 0 0 5px 0;
            }}
            .verdict-status {{
                font-size: 28px;
                font-weight: 900;
                padding: 10px 20px;
                border-radius: 4px;
                background: { "#d9534f" if verdict["status"] == "FAIL" else "#5cb85c" };
                color: white;
            }}
            .slsa-box {{
                background: #f8f9fa;
                border: 1px solid #e9ecef;
                padding: 14px 20px;
                border-radius: 6px;
                margin-bottom: 30px;
            }}
            .summary-cards {{
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 15px;
                margin-bottom: 30px;
            }}
            .card {{
                background: #f8f9fa;
                border: 1px solid #e9ecef;
                padding: 15px;
                text-align: center;
                border-radius: 6px;
            }}
            .card-val {{
                font-size: 24px;
                font-weight: bold;
                color: #2c3e50;
            }}
            .card-lbl {{
                font-size: 12px;
                color: #7f8c8d;
                text-transform: uppercase;
                margin-top: 5px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #eee;
            }}
            th {{
                background-color: #f8f9fa;
                color: #2c3e50;
                font-weight: bold;
            }}
            .badge {{
                display: inline-block;
                padding: 3px 8px;
                font-size: 11px;
                font-weight: bold;
                border-radius: 12px;
                text-transform: uppercase;
            }}
            .badge-success {{ background: #dff0d8; color: #3c763d; }}
            .badge-warning {{ background: #fcf8e3; color: #8a6d3b; }}
            .badge-danger {{ background: #f2dede; color: #a94442; }}
            .badge-info {{ background: #d9edf7; color: #31708f; }}
            .cve-item {{
                background: #fff8f8;
                border-left: 3px solid #d9534f;
                padding: 10px;
                margin-top: 8px;
                border-radius: 0 4px 4px 0;
                font-size: 13px;
            }}
            .print-btn {{
                background: #34495e;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                border-radius: 4px;
                cursor: pointer;
                float: right;
            }}
            @media print {{
                .print-btn {{ display: none; }}
                body {{ padding: 0; background: #fff; }}
                .container {{ box-shadow: none; padding: 0; border: none; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <button class="print-btn" onclick="window.print()">Print / Save PDF</button>
            <div class="header">
                <div>
                    <h1 class="title">Supply Chain Security Attestation Report</h1>
                    <div class="meta-info">Target Repository: {scan_data["repo_url"]}</div>
                </div>
                <div class="meta-info" style="text-align: right;">
                    <strong>Risk Index: {verdict["risk_index"]}/100</strong><br>
                    Policy: Block on {scan_data["block_threshold"]}
                </div>
            </div>
            
            <div class="verdict-box">
                <div>
                    <h3 class="verdict-title">Security Attestation Verdict</h3>
                    <p style="margin: 0;">{verdict["description"]}</p>
                </div>
                <div class="verdict-status">{verdict["status"]}</div>
            </div>

            <div class="slsa-box">
                <strong>SLSA Build Provenance:</strong> <span class="badge badge-info">{slsa_level_name}</span>
                <div style="font-size: 12px; color: #7f8c8d; margin-top: 4px;">{slsa_details}</div>
            </div>
                <div class="card">
                    <div class="card-val">{summary["total_dependencies"]}</div>
                    <div class="card-lbl">Dependencies</div>
                </div>
                <div class="card">
                    <div class="card-val" style="color: { '#3c763d' if summary['unsigned'] == 0 else '#d68910' }">
                        {summary["total_dependencies"] - summary["unsigned"]}
                    </div>
                    <div class="card-lbl">Signed Packages</div>
                </div>
                <div class="card">
                    <div class="card-val" style="color: { '#a94442' if summary['vulnerabilities']['total'] > 0 else '#3c763d' }">
                        {summary["vulnerabilities"]["total"]}
                    </div>
                    <div class="card-lbl">Vulnerabilities</div>
                </div>
                <div class="card">
                    <div class="card-val" style="color: { '#d9534f' if verdict['risk_index'] > 60 else '#5cb85c' }">
                        {verdict["risk_index"]}/100
                    </div>
                    <div class="card-lbl">Risk Score</div>
                </div>
            </div>
            
            <h2>Vulnerability Summary</h2>
            <div style="display: flex; gap: 10px; margin-bottom: 20px;">
                <span class="badge badge-danger">Critical: {summary["vulnerabilities"]["critical"]}</span>
                <span class="badge badge-warning" style="background-color: #f0ad4e; color: white;">High: {summary["vulnerabilities"]["high"]}</span>
                <span class="badge badge-warning">Medium: {summary["vulnerabilities"]["medium"]}</span>
                <span class="badge badge-info">Low: {summary["vulnerabilities"]["low"]}</span>
            </div>

            <h2>Dependency Breakdown</h2>
            <table>
                <thead>
                    <tr>
                        <th>Package Name</th>
                        <th>Version</th>
                        <th>Ecosystem</th>
                        <th>Signatures</th>
                        <th>Vulnerabilities</th>
                        <th>Risk</th>
                    </tr>
                </thead>
                <tbody>
    """
    
    for d in sorted_deps:
        sig_verified = d.get("signature_verified", False)
        sig_badge = f'<span class="badge badge-success">Verified ({d.get("signature_type")})</span>' if sig_verified else '<span class="badge badge-danger">Unsigned</span>'
        
        vulns = d.get("vulnerabilities", [])
        if vulns:
            highest_sev = "LOW"
            for v in vulns:
                if v["severity"] == "CRITICAL":
                    highest_sev = "CRITICAL"
                    break
                elif v["severity"] == "HIGH":
                    highest_sev = "HIGH"
                elif v["severity"] == "MEDIUM" and highest_sev != "HIGH":
                    highest_sev = "MEDIUM"
            
            bg_map = {"CRITICAL": "badge-danger", "HIGH": "badge-warning", "MEDIUM": "badge-warning", "LOW": "badge-info"}
            style_override = "background-color: #f0ad4e; color: white;" if highest_sev == "HIGH" else ""
            vuln_badge = f'<span class="badge {bg_map.get(highest_sev)}" style="{style_override}">{len(vulns)} Vuln ({highest_sev})</span>'
        else:
            vuln_badge = '<span class="badge badge-success">Clean</span>'
            
        risk_color = "#5cb85c"
        if d["risk_score"] > 60:
            risk_color = "#d9534f"
        elif d["risk_score"] > 30:
            risk_color = "#f0ad4e"
            
        html_content += f"""
                    <tr>
                        <td><strong>{d["name"]}</strong></td>
                        <td>{d["version"]}</td>
                        <td>{d["ecosystem"]}</td>
                        <td>{sig_badge}</td>
                        <td>{vuln_badge}</td>
                        <td style="color: {risk_color}; font-weight: bold;">{d["risk_score"]}/100</td>
                    </tr>
        """
        
        # If there are vulnerabilities, append detailed sub-row
        if vulns:
            html_content += """
                    <tr>
                        <td colspan="6" style="background-color: #fafafa; padding: 5px 15px 15px 15px;">
            """
            for v in vulns:
                html_content += f"""
                            <div class="cve-item">
                                <strong>{v["cve_id"]} ({v["severity"]} - CVSS: {v["cvss_score"]})</strong>: 
                                {v["summary"]}. <em>Fixed in version: {v["fixed_version"]}</em>
                            </div>
                """
            html_content += """
                        </td>
                    </tr>
            """
            
    html_content += """
                </tbody>
            </table>
            
            <div style="margin-top: 50px; text-align: center; font-size: 12px; color: #95a5a6; border-top: 1px solid #eee; padding-top: 20px;">
                Generated by Antigravity Supply Chain Attestation Engine.
            </div>
        </div>
    </body>
    </html>
    """
    
    return html_content

# Serve frontend
# Note: we will mount the static files folder AFTER defining routes, so API routes take precedence
app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    # Start the dev server
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
