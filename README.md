# Template: Fase 3 - ASPM (Application Security Posture Management)

Plantilla base para priorizar vulnerabilidades basándose en el riesgo real de explotación, no solo en la severidad (CRITICAL/HIGH).

## ¿Qué incluye?
- **Inteligencia de Amenazas:** Descarga automática de las bases de datos de EPSS (probabilidad de exploit) y CISA KEV (vulnerabilidades explotadas en el mundo real).
- **Motor de Priorización:** Script en Python que cruza los resultados de Trivy con EPSS y KEV para calcular un "Risk Score".
- **CI/CD:** Workflow de GitHub Actions que ejecuta todo el proceso y muestra el ranking en los logs.

## Cómo usar esta plantilla
1. Usa este repositorio como plantilla.
2. Sube los cambios (`git push`).
3. Ve a la pestaña "Actions" y abre el paso **"Prioritize Vulnerabilities"** para ver la tabla de riesgo en tiempo real.