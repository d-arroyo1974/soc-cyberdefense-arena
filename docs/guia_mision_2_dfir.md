# Guía Formativa - Misión 2: DFIR & Análisis Forense Digital
**Asignatura:** Ciberseguridad Defensiva (OCY1105 / CSY6122 / CSY1102)  
**Entorno:** NetChile Corp / Soluciones Tecnológicas SPA  
**Rol:** Incident Responder & Forensics Analyst  

---

## 1. Alcance Forense y Cadena de Custodia

El objetivo de la Misión 2 es recolectar, validar y correlacionar evidencia digital ante una intrusión sospechosa en los activos de NetChile Corp, identificando la persistencia y los mecanismos de comunicación de los atacantes.

---

## 2. Artefactos y Metodología Forense

### 2.1 Hashes Criptográficos (Integridad & Threat Intelligence)
Todo artefacto o binario sospechoso debe ser documentado mediante su hash SHA-256 para evitar colisiones y consultar plataformas de inteligencia de amenazas:
```powershell
# Obtención de hash en PowerShell
Get-FileHash -Algorithm SHA256 "C:\Windows\Temp\updater_payload.exe"
```
```bash
# Obtención de hash en Linux
sha256sum /tmp/malicious_elf
```

### 2.2 Auditoría de Event IDs de Windows Security
Los siguientes eventos del visor de sucesos (`Security.evtx`) son obligatorios para reconstruir la línea de tiempo:

1. **Event ID 4624 (Inicio de Sesión Exitoso):**
   - **Logon Type 2 (Interactive):** Acceso directo por consola local.
   - **Logon Type 3 (Network):** Acceso a recursos compartidos (SMB/RPC).
   - **Logon Type 10 (RemoteInteractive):** Conexión vía Escritorio Remoto (RDP).
   - Datos clave: Usuario, Nombre de Estación de Trabajo, Dirección IP de Origen.

2. **Event ID 4697 (Instalación de un Servicio en el Sistema):**
   - Indica establecimiento de persistencia o escalamiento de privilegios a nivel SYSTEM (Técnica MITRE ATT&CK T1543.003).
   - Datos clave: `ServiceName`, `ServiceFileName` (ruta y parámetros del binario ejecutado).

3. **Event ID 4688 (Creación de Nuevos Procesos):**
   - Requiere auditoría de línea de comandos habilitada (*Audit Process Creation with CommandLine*).
   - Permite detectar ejecución ofuscada de `powershell.exe -EncodedCommand`, `cmd.exe`, `vssadmin.exe`, `certutil.exe -urlcache`.

### 2.3 Análisis de Tráfico de Red con Wireshark y tshark
Inspección profunda de capturas PCAP (`tshark` en modo CLI):

- **Filtro HTTP POST (Detección de Tráfico C2 / Exfiltración):**
  ```bash
  tshark -r capture.pcap -Y 'http.request.method == "POST"' -T fields -e frame.time -e ip.src -e ip.dst -e http.request.uri -e http.file_data
  ```
- **Filtro DNS (Consultas Anómalas / DGA / DNS Tunneling):**
  ```bash
  tshark -r capture.pcap -Y 'dns.flags.response == 0 && dns.qry.name matches ".*\\.c2domain\\.xyz"' -T fields -e dns.qry.name
  ```
- **Filtro ICMP (Túneles de Exfiltración / Ping Beacons):**
  ```bash
  tshark -r capture.pcap -Y 'icmp.type == 8 && frame.len > 128' -T fields -e ip.src -e ip.dst -e data.text
  ```

### 2.4 Análisis Forense de Registros Linux (`/var/log/auth.log`)
Auditoría de autenticación y privilegios:
```bash
# Detección de ataques de fuerza bruta SSH
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr

# Detección de accesos exitosos anómalos
grep "Accepted" /var/log/auth.log

# Detección de abuso de comandos privilegiados
grep "sudo:" /var/log/auth.log
```

---

## 3. Entregables de la Misión 2
1. Diligenciamiento de la sección 2 en [`templates/plantilla_informe.txt`](file:///C:/Users/cloud/soc-autograder/templates/plantilla_informe.txt).
2. Completar el Playbook de Respuesta a Incidentes en [`templates/playbook_ransomware_template.md`](file:///C:/Users/cloud/soc-autograder/templates/playbook_ransomware_template.md).
