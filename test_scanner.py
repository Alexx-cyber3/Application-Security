import os
import tempfile
import json
import pytest
import networkx as nx

# Add local bin directory to PATH so bundled syft and cosign binaries can be discovered
_file_path = globals().get("__file__")
if _file_path:
    _current_dir = os.path.dirname(os.path.abspath(_file_path))
    _bin_dir = os.path.join(_current_dir, "bin")
    if os.path.exists(_bin_dir):
        _paths = os.environ.get("PATH", "").split(os.pathsep)
        if _bin_dir not in _paths:
            os.environ["PATH"] = _bin_dir + os.pathsep + os.environ.get("PATH", "")

from scanner import SecurityScanner
from installer import ToolManager

def test_tool_manager_availability():
    """Verify tool availability functions return boolean results."""
    # We check that is_tool_available returns a boolean
    result = ToolManager.is_tool_available("non-existent-binary-12345")
    assert result is False
    
    status = ToolManager.check_tools()
    assert "syft" in status
    assert "cosign" in status
    assert isinstance(status["syft"]["available"], bool)

def test_manifest_parsing_requirements_txt():
    """Test parsing Python requirements.txt manifest files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        req_path = os.path.join(temp_dir, "requirements.txt")
        with open(req_path, "w") as f:
            f.write("# This is a comment\n")
            f.write("requests==2.25.1\n")
            f.write("jinja2>=2.11.3\n")
            f.write("flask==1.1.2 # inline comment\n")
            
        scanner = SecurityScanner("https://github.com/django/django")
        scanner.temp_dir = temp_dir
        
        scanner.parse_requirements_txt(req_path, "requirements.txt")
        
        assert len(scanner.dependencies) == 3
        
        # Verify package records
        requests_dep = next(d for d in scanner.dependencies if d["name"] == "requests")
        assert requests_dep["version"] == "2.25.1"
        assert requests_dep["ecosystem"] == "PyPI"
        assert requests_dep["purl"] == "pkg:pypi/requests@2.25.1"
        
        flask_dep = next(d for d in scanner.dependencies if d["name"] == "flask")
        assert flask_dep["version"] == "1.1.2"
        
        # Verify NetworkX graph matches
        assert scanner.graph.has_node("requirements.txt")
        assert scanner.graph.has_node("requests@2.25.1")
        assert scanner.graph.has_edge("requirements.txt", "requests@2.25.1")

def test_manifest_parsing_package_json():
    """Test parsing NPM package.json manifest files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        pkg_path = os.path.join(temp_dir, "package.json")
        pkg_data = {
            "name": "test-app",
            "dependencies": {
                "express": "^4.17.1",
                "lodash": "4.17.21"
            },
            "devDependencies": {
                "typescript": "~4.3.2"
            }
        }
        with open(pkg_path, "w") as f:
            json.dump(pkg_data, f)
            
        scanner = SecurityScanner("https://github.com/django/django")
        scanner.temp_dir = temp_dir
        
        scanner.parse_package_json(pkg_path, "package.json")
        
        assert len(scanner.dependencies) == 3
        
        express_dep = next(d for d in scanner.dependencies if d["name"] == "express")
        assert express_dep["version"] == "4.17.1"
        assert express_dep["ecosystem"] == "npm"
        
        typescript_dep = next(d for d in scanner.dependencies if d["name"] == "typescript")
        assert typescript_dep["version"] == "4.3.2"
        assert typescript_dep["ecosystem"] == "npm"
        
        assert scanner.graph.has_edge("package.json", "express@4.17.1")

def test_risk_score_calculation():
    """Test risk scores are calculated and capped correctly."""
    scanner = SecurityScanner("https://github.com/django/django")
    
    # 1. Signed dependency with no vulnerabilities
    dep_secure = {
        "name": "secure-pkg",
        "version": "1.0.0",
        "ecosystem": "PyPI",
        "signature_verified": True,
        "vulnerabilities": []
    }
    
    # 2. Unsigned dependency with 1 high vulnerability
    dep_risky = {
        "name": "risky-pkg",
        "version": "2.0.0",
        "ecosystem": "npm",
        "signature_verified": False,
        "vulnerabilities": [
            {"severity": "HIGH", "cvss_score": 8.5}
        ]
    }
    
    # 3. Signed dependency with multiple vulnerabilities (caps at 100)
    dep_critical = {
        "name": "crit-pkg",
        "version": "3.0.0",
        "ecosystem": "Cargo",
        "signature_verified": True,
        "vulnerabilities": [
            {"severity": "CRITICAL", "cvss_score": 9.8},
            {"severity": "CRITICAL", "cvss_score": 9.5},
            {"severity": "HIGH", "cvss_score": 7.5}
        ]
    }
    
    scanner.dependencies = [dep_secure, dep_risky, dep_critical]
    
    # Setup node definitions in graph
    for dep in scanner.dependencies:
        scanner.graph.add_node(f"{dep['name']}@{dep['version']}")
        
    scanner.calculate_risk_scores()
    
    # Assertions
    assert dep_secure["risk_score"] == 0
    
    # Unsigned (15) + High Vuln (30) = 45
    assert dep_risky["risk_score"] == 45
    
    # Signed (0) + 2x Crit Vuln (100) + 1x High Vuln (30) = 130 -> capped at 100
    assert dep_critical["risk_score"] == 100

def test_build_blocking_verdict():
    """Verify that build policy is applied correctly for allow/block decisions."""
    # Scenario A: Block policy is CRITICAL, we have a HIGH vulnerability
    scanner_a = SecurityScanner("https://github.com/django/django", block_threshold="CRITICAL")
    dep_high = {
        "name": "high-vuln-pkg",
        "version": "1.0.0",
        "ecosystem": "PyPI",
        "signature_verified": True,
        "vulnerabilities": [{"severity": "HIGH"}]
    }
    scanner_a.dependencies = [dep_high]
    scanner_a.calculate_risk_scores()
    verdict_a = scanner_a.determine_build_status()
    assert verdict_a["status"] == "PASS"  # Passed because HIGH is below CRITICAL threshold
    
    # Scenario B: Block policy is HIGH, we have a HIGH vulnerability
    scanner_b = SecurityScanner("https://github.com/django/django", block_threshold="HIGH")
    scanner_b.dependencies = [dep_high]
    scanner_b.calculate_risk_scores()
    verdict_b = scanner_b.determine_build_status()
    assert verdict_b["status"] == "FAIL"  # Blocked because severity matches threshold
    
    # Scenario C: Block policy is NONE, we have a CRITICAL vulnerability
    scanner_c = SecurityScanner("https://github.com/django/django", block_threshold="NONE")
    dep_crit = {
        "name": "crit-vuln-pkg",
        "version": "1.0.0",
        "ecosystem": "PyPI",
        "signature_verified": True,
        "vulnerabilities": [{"severity": "CRITICAL"}]
    }
    scanner_c.dependencies = [dep_crit]
    scanner_c.calculate_risk_scores()
    verdict_c = scanner_c.determine_build_status()
    assert verdict_c["status"] == "PASS"  # Passed because threshold is set to NONE (audit-only)

def test_slsa_provenance_verification():
    """Test SLSA provenance verification and level detection."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a mock provenance file
        prov_path = os.path.join(temp_dir, ".slsa-provenance.json")
        prov_data = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "builder": {"id": "https://github.com/slsa-framework/slsa-github-generator"}
        }
        with open(prov_path, "w") as f:
            json.dump(prov_data, f)
            
        scanner = SecurityScanner("https://github.com/django/django")
        scanner.temp_dir = temp_dir
        
        slsa_data = scanner.verify_slsa_provenance()
        assert slsa_data["level"] == "SLSA_LEVEL_3"
        assert slsa_data["verified"] is True
        assert "slsa-github-generator" in slsa_data["builder_id"]

def test_compute_sbom_diff():
    """Test SBOM diff logic for tracking added, removed, updated dependencies and risk deltas."""
    from scanner import compute_sbom_diff
    
    base_res = {
        "repo_url": "https://github.com/owner/repo",
        "verdict": {"risk_index": 20},
        "dependencies": [
            {"name": "requests", "version": "2.25.1", "ecosystem": "PyPI", "risk_score": 10},
            {"name": "flask", "version": "1.1.2", "ecosystem": "PyPI", "risk_score": 25}
        ]
    }
    
    head_res = {
        "repo_url": "https://github.com/owner/repo",
        "verdict": {"risk_index": 45},
        "dependencies": [
            {"name": "requests", "version": "2.26.0", "ecosystem": "PyPI", "risk_score": 0},  # Updated
            {"name": "django", "version": "3.2.0", "ecosystem": "PyPI", "risk_score": 5}        # Added (flask removed)
        ]
    }
    
    diff = compute_sbom_diff(base_res, head_res)
    
    assert diff["summary"]["added_count"] == 1
    assert diff["added_dependencies"][0]["name"] == "django"
    
    assert diff["summary"]["removed_count"] == 1
    assert diff["removed_dependencies"][0]["name"] == "flask"
    
    assert diff["summary"]["updated_count"] == 1
    assert diff["updated_dependencies"][0]["name"] == "requests"
    assert diff["updated_dependencies"][0]["old_version"] == "2.25.1"
    assert diff["updated_dependencies"][0]["new_version"] == "2.26.0"
    
    # Risk delta: 45 - 20 = 25
    assert diff["risk_delta"] == 25

def test_local_path_scan():
    """Verify scanner handles local paths without trying to clone a repository or clean up the local directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        req_path = os.path.join(temp_dir, "requirements.txt")
        with open(req_path, "w") as f:
            f.write("requests==2.25.1\n")
            
        scanner = SecurityScanner(local_path=temp_dir)
        assert scanner.is_local is True
        assert scanner.local_path == temp_dir
        
        # Mock methods that would trigger network requests to make the test offline-capable and fast
        scanner.verify_signatures = lambda: None
        scanner.verify_slsa_provenance = lambda: {}
        scanner.scan_vulnerabilities = lambda: None
        scanner.calculate_risk_scores = lambda: None
        scanner.determine_build_status = lambda: {"status": "PASS", "description": "Mocked", "risk_index": 0}
        
        res = scanner.run_full_scan()
        assert res["success"] is True
        assert scanner.temp_dir == temp_dir
        
        # Verify that cleanup is a no-op and did NOT delete the local path
        assert os.path.exists(req_path)

