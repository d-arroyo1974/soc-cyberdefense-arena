# Playbook de Respuesta a Incidentes: Ransomware & Exfiltración de Datos
**Estándar:** NIST SP 800-61 Rev. 2 (*Computer Security Incident Handling Guide*)  
**Organización:** NetChile Corp / Soluciones Tecnológicas SPA  
**Asignatura:** Ciberseguridad Defensiva (OCY1105 / CSY6122 / CSY1102)  
**Versión:** 1.0  
**Clasificación:** Confidencial - Uso Interno CSIRT / SOC  

---

## 1. Fase 1: Preparación (Preparation)

### 1.1 Herramientas y Accesos Críticos
- [ ] Credenciales de emergencia almacenadas en bóveda segura (KeePass / CyberArk) fuera de Active Directory.
- [ ] Acceso a consolas de administración: Wazuh SIEM Dashboard, Firewall de Perímetro, EDR y backups inmutables.
- [ ] Servidores 'Jump Box' forenses aislados con herramientas preinstaladas (`tshark`, `Volatility`, `Sysinternals Suite`, `YARA`, `FTK Imager`).

### 1.2 Líneas Base de Seguridad y Políticas de Respaldo
- [ ] Política de copias de seguridad 3-2-1-1-0 (3 copias, 2 medios distintos, 1 offsite, 1 inmutable/air-gapped, 0 errores en pruebas de restauración).
- [ ] Reglas de detección activadas en NIDS (Suricata) y FIM (Wazuh syscheck).

---

## 2. Fase 2: Detección e Identificación (Detection & Analysis)

### 2.1 Indicadores de Compromiso (IoCs) & Triage Inicial
- **Vectores de Entrada Comunes:** Phishing con credenciales robadas, servicios RDP/SSH expuestos, explotación de vulnerabilidades perimetrales (ej. Log4j CVE-2021-44228).
- **Extracción de Hashes Criptográficos:**
  ```powershell
  Get-FileHash -Path "C:\Windows\Temp\malware.exe" -Algorithm SHA256
  ```
- **Auditoría de Eventos de Seguridad de Windows:**
  - `Event ID 4624`: Validar Logon Types (Type 10 RDP o Type 3 Network) y cuentas anómalas.
  - `Event ID 4697`: Servicios recién registrados para persistencia maliciosa.
  - `Event ID 4688`: Procesos sospechosos (`powershell.exe`, `cmd.exe`, `vssadmin.exe delete shadows`, `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures`).

### 2.2 Telemetría de Red y NIDS (Suricata & Wireshark)
- Inspeccionar eventos en `/var/log/suricata/eve.json` filtrando por `event_type == "alert"`.
- Filtrar tráfico con `tshark` para aislar canales de Comando y Control (C2):
  ```bash
  tshark -r incident.pcap -Y 'http.request.method == "POST" || dns.flags.response == 0'
  ```

---

## 3. Fase 3: Contención (Containment)

### 3.1 Contención a Corto Plazo (Aislamiento Inmediato)
- [ ] **Aislamiento de Red:** Desconectar interfaces de red de hosts infectados (aislamiento por EDR o apagado de puertos de switch VLAN).
- [ ] **Bloqueo Perimetral:** Aplicar bloqueo inmediato de IPs y dominios C2 en el Firewall/WAF mediante script de Wazuh Active Response.
- [ ] **Congelamiento de Identidades:** Deshabilitar cuentas de usuario o de servicio comprometidas (`svc_backup`) y forzar revocación de tokens Kerberos/OAuth.

### 3.2 Contención a Largo Plazo
- [ ] Aislar el segmento de servidores de bases de datos mediante microsegmentación.
- [ ] Bloquear tráfico lateral SMB (TCP 445), RPC (TCP 135) y RDP (TCP 3389) entre endpoints.

---

## 4. Fase 4: Erradicación (Eradication)

### 4.1 Limpieza de Artefactos y Persistencia
- [ ] Terminar procesos maliciosos en memoria identificados por telemetría.
- [ ] Eliminar servicios maliciosos instalados (consultados en `Event ID 4697` y clave de registro `HKLM\SYSTEM\CurrentControlSet\Services`).
- [ ] Remover tareas programadas sospechosas (`schtasks /query /fo LIST /v`).
- [ ] Parchear la vulnerabilidad de acceso inicial (ej. actualizar librerías vulnerables o cerrar puertos innecesarios).

---

## 5. Fase 5: Recuperación (Recovery)

### 5.1 Restauración Segura de Sistemas
- [ ] Reinstalación de sistemas operativos desde imágenes doradas (*Golden Images*) verificadas.
- [ ] Restauración de bases de datos desde el último respaldo inmutable limpio verificado.
- [ ] Reconfiguración de contraseñas de todos los administradores y cuentas de servicio.

### 5.2 Monitoreo Reforzado Post-Recuperación
- [ ] Mantener monitoreo en tiempo real vía Wazuh SIEM con alertas de severidad nivel $\ge 10$ durante al menos 14 días.
- [ ] Validar integridad de archivos del sistema mediante FIM continuo.

---

## 6. Fase 6: Lecciones Aprendidas (Post-Incident Activity)

### 6.1 Reunión Post-Mortem y Documentación
- [ ] ¿Cuál fue el tiempo total de detección (MTTD) y tiempo de respuesta (MTTR)?
- [ ] ¿Cómo se desempeñaron las alertas del SIEM y NIDS ante la intrusión?
- [ ] ¿Qué controles cuantitativos adicionales se deben implementar conforme al análisis de $CBA$ y gestión del riesgo?
- [ ] Actualización del presente Playbook y socialización con el equipo del SOC.
