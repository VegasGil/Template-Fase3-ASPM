import json
import os
import urllib.request
import ssl
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRIVY_JSON = ROOT / "trivy_results.json"
EPSS_JSON = Path(__file__).parent / "data" / "epss.json"
KEV_JSON = Path(__file__).parent / "data" / "kev.json"

SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "UNKNOWN": 0}

def load_json(path):
    if not path.exists():
        raise SystemExit(f"❌ Falta el archivo {path}.")
    return json.loads(path.read_text(encoding="utf-8-sig"))

def calculate_risk(severity: str, epss: float, in_kev: bool) -> float:
    base = SEVERITY_WEIGHT.get(severity.upper(), 0)
    epss_score = epss * 10
    kev_bonus = 20 if in_kev else 0
    return base + epss_score + kev_bonus

def send_to_splunk(findings):
    """Envía las vulnerabilidades priorizadas a Splunk vía HTTP Event Collector."""
    splunk_host = os.environ.get("SPLUNK_HOST")
    splunk_token = os.environ.get("SPLUNK_TOKEN")
    
    if not splunk_host or not splunk_token:
        print("⚠️ No se configuraron SPLUNK_HOST o SPLUNK_TOKEN. Saltando envío a SIEM.")
        return

    print("[*] Enviando resultados priorizados a Splunk...")
    url = f"https://{splunk_host}:8088/services/collector/event"
    
    context = ssl._create_unverified_context()
    
    for f in findings[:5]:
        payload = {"event": f, "sourcetype": "aspm_prioritized"}
        req = urllib.request.Request(url, method="POST")
        req.add_header("Authorization", f"Splunk {splunk_token}")
        req.add_header("Content-Type", "application/json")
        
        try:
            with urllib.request.urlopen(req, data=json.dumps(payload).encode(), context=context) as response:
                pass
        except Exception as e:
            print(f"❌ Error enviando a Splunk: {e}")
            
    print("✅ Envío a Splunk finalizado.")

def main():
    print("[*] Cargando datos de EPSS y KEV...")
    epss_db = load_json(EPSS_JSON)
    kev_db = set(load_json(KEV_JSON))
    
    print("[*] Cargando resultados del escáner (Trivy)...")
    trivy_data = load_json(TRIVY_JSON)

    findings = []
    
    # DEPURACIÓN: Vemos si Trivy encontró algo
    results = trivy_data.get("Results", [])
    print(f"[*] Trivy analizó {len(results)} archivos/entornos.")
    
    if len(results) == 0:
        print("⚠️ Trivy no encontró archivos (¿subiste el package.json?).")
        
    for result in results:
        for vuln in result.get("Vulnerabilities", []):
            cve = vuln.get("VulnerabilityID")
            pkg = vuln.get("PkgName")
            sev = vuln.get("Severity", "UNKNOWN")
            
            epss_val = epss_db.get(cve, 0.0)
            in_kev = cve in kev_db
            
            risk_score = calculate_risk(sev, epss_val, in_kev)
            
            findings.append({
                "cve": cve, "package": pkg, "severity": sev,
                "epss": epss_val, "kev": in_kev, "risk_score": risk_score
            })

    findings.sort(key=lambda x: x["risk_score"], reverse=True)

    print("\n=== RANKING DE RIESGO (ASPM) ===\n")
    if len(findings) == 0:
        print("No hay vulnerabilidades para mostrar.")
    else:
        print(f"{'CVE':<16} | {'Paquete':<12} | {'Sev':<8} | {'EPSS':<6} | {'KEV':<3} | {'Risk':<4}")
        print("-" * 65)
        for f in findings:
            kev_str = "SÍ" if f["kev"] else "no"
            print(f"{f['cve']:<16} | {f['package']:<12} | {f['severity']:<8} | {f['epss']:<6.3f} | {kev_str:<3} | {f['risk_score']:<4.1f}")

    if findings:
        send_to_splunk(findings)

if __name__ == "__main__":
    main()