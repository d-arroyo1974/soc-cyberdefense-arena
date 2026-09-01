# Esquemas y Arquitectura SOC CyberDefense Arena
**Organización:** NetChile Corp / Soluciones Tecnológicas SPA  
**Entorno Operativo:** SOC / SIEM / NIDS / DFIR  

---

## 1. Diagrama de Topología de Red y Flujo de Telemetría SOC

```mermaid
flowchart TD
    subgraph Internet_Untrusted ["Zona Externa (Internet / Atacantes)"]
        Attacker["Actor Malicioso / C2 Server<br>IP: 198.51.100.77"]
    end

    subgraph Perimeter ["Perímetro & Inspección NIDS"]
        Firewall["Firewall Perimetral / WAF<br>iptables + Active Response"]
        Suricata["Suricata NIDS Sensor<br>Interface Promiscua (DPI)"]
    end

    subgraph Internal_Network ["Infraestructura Interna NetChile Corp (10.0.0.0/24)"]
        WebServer["Servidor Web & API (srv-web-prod)<br>IP: 10.0.0.25 (Debian 12)<br>Wazuh Agent ID: 001"]
        DBServer["Base de Datos Core (srv-db-core)<br>IP: 10.0.0.30 (Ubuntu 22.04)<br>Wazuh Agent ID: 002"]
        DomainCtrl["Controlador de Dominio (dc-win2022)<br>IP: 10.0.0.15 (Windows Server 2022)<br>Wazuh Agent ID: 003"]
    end

    subgraph SOC_Operations ["Centro de Operaciones de Seguridad (SOC)"]
        WazuhManager["Wazuh Manager / Indexer / Dashboard<br>IP: 10.0.0.10"]
        SOC_Tier1["Analista SOC Tier 1<br>(Triage & Monitoreo)"]
        SOC_Tier2["Incident Responder Tier 2<br>(DFIR & Playbooks)"]
        SOC_Tier3["Lead DevSecOps Tier 3<br>(Threat Hunting & GRC)"]
    end

    %% Conexiones de Tráfico
    Attacker -->|Explotación RCE / Log4j| Firewall
    Firewall -->|Tráfico Inspeccionado| WebServer
    Firewall -.->|Copia en Espejo SPAN| Suricata
    Suricata -->|eve.json logs| WazuhManager

    %% Telemetría de Agentes
    WebServer -->|Logs & FIM syscheck| WazuhManager
    DBServer -->|Logs & FIM syscheck| WazuhManager
    DomainCtrl -->|Security.evtx 4624/4697/4688| WazuhManager

    %% Acciones de Respuesta Activa
    WazuhManager -.->|Active Response Block IP| Firewall

    %% Acceso Analistas
    WazuhManager --> SOC_Tier1
    WazuhManager --> SOC_Tier2
    WazuhManager --> SOC_Tier3
```

---

## 2. Flujo de Datos y Pipeline de Evaluación Automatizada

```mermaid
sequenceDiagram
    autonumber
    actor Estudiante as Equipo de Estudiantes
    participant Repo as Repositorio Docente
    participant Autograder as Pipeline Grader (grader.py)
    participant Gemini as Google GenAI (Gemini 2.5 Flash)
    participant CSV as consolidado_notas.csv

    Estudiante->>Repo: Completa plantilla_informe.txt en entregas/
    Estudiante->>Autograder: Ejecuta evaluación académica
    Autograder->>Autograder: Lee variables de entorno (GEMINI_API_KEY)
    alt Clave Gemini Presente
        Autograder->>Gemini: Envía informe + System Instructions Lead SOC Auditor
        Gemini-->>Autograder: Retorna JSON estructurado (Pydantic Schema)
    else Clave Ausente / Offline
        Autograder->>Autograder: Ejecuta motor determinístico con rúbrica oficial
    end
    Autograder->>Autograder: Calcula Nota Chilena (1.0 a 7.0 al 60% exigencia)
    Autograder->>CSV: Registra veredicto, puntajes y observaciones
    Autograder-->>Estudiante: Muestra tabla consolidada en consola
```
