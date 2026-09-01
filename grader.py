#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
PIPELINE DE EVALUACIÓN AUTOMATIZADA - LEAD SOC AUDITOR & DEVSECOPS
ASIGNATURA: Ciberseguridad Defensiva (OCY1105 / CSY6122 / CSY1102)
MOTOR: Google GenAI SDK (google-genai) con gemini-3.6-flash / gemini-2.5-flash
================================================================================
"""

import os
import sys
import glob
import json
import re
import time
from pathlib import Path
from typing import List, Optional
import pandas as pd
from pydantic import BaseModel, Field

# Asegurar codificación UTF-8 en consola de Windows
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Intentar importar google-genai
try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


# ==============================================================================
# MODELOS DE DATOS PYDANTIC (STRUCTURED OUTPUT SCHEMA)
# ==============================================================================

class Mision1Riesgo(BaseModel):
    puntaje: int = Field(description="Puntaje de Misión 1 (100, 80, 60, 30 o 0)")
    estado_calculos: str = Field(description="Estado de los cálculos: 'Válido (100%)', 'Errores Menores (80%)', 'Incompleto (60%)', 'Incorrecto (30%)', 'No Presentado (0%)'")
    sle_correcto: bool = Field(description="Verificación de SLE = AV * EF")
    ale_correcto: bool = Field(description="Verificación de ALE = SLE * ARO")
    cba_correcto: bool = Field(description="Verificación de CBA = (ALE_inicial - ALE_mitigado) - Costo_Control")
    observaciones: str = Field(description="Feedback técnico detallado sobre cálculos de riesgo")


class Mision2DFIR(BaseModel):
    puntaje: int = Field(description="Puntaje de Misión 2 (100, 80, 60, 30 o 0)")
    dfir_validado: str = Field(description="Estado: 'Validado (100%)', 'Parcial (80%)', 'Incompleto (60%)', 'Insuficiente (30%)', 'No Validado (0%)'")
    sha256_presente: bool = Field(description="Presencia y validez de hashes SHA-256")
    event_ids_analizados: List[int] = Field(description="Event IDs analizados: 4624, 4697, 4688")
    filtros_wireshark_completos: bool = Field(description="Presencia de filtros HTTP POST, DNS e ICMP")
    auth_log_analizado: bool = Field(description="Análisis forense de /var/log/auth.log")
    observaciones: str = Field(description="Feedback técnico detallado sobre DFIR")


class Mision3SOC(BaseModel):
    puntaje: int = Field(description="Puntaje de Misión 3 (100, 80, 60, 30 o 0)")
    soc_nids_validado: str = Field(description="Estado: 'Validado (100%)', 'Parcial (80%)', 'Incompleto (60%)', 'Insuficiente (30%)', 'No Validado (0%)'")
    wazuh_desplegado: bool = Field(description="Despliegue y configuración de Wazuh SIEM con agentes")
    suricata_eve_json_analizado: bool = Field(description="Parseo y análisis de eventos de Suricata en eve.json")
    observaciones: str = Field(description="Feedback técnico detallado sobre SOC & NIDS")


class EvaluacionInforme(BaseModel):
    equipo: str = Field(description="Nombre o identificador del equipo")
    mision_1_riesgos: Mision1Riesgo
    mision_2_dfir: Mision2DFIR
    mision_3_soc_nids: Mision3SOC
    puntaje_global_porcentaje: float = Field(description="Puntaje global consolidado en porcentaje (0 a 100)")
    nota_sugerida_7: float = Field(description="Nota sugerida en escala chilena 1.0 - 7.0 con exigencia al 60%")
    observaciones_profesor: str = Field(description="Feedback consolidado y constructivo del Lead SOC Auditor para el informe")


# ==============================================================================
# SYSTEM INSTRUCTIONS DEL LEAD SOC AUDITOR & RÚBRICA DE 5 NIVELES
# ==============================================================================

LEAD_SOC_SYSTEM_INSTRUCTIONS = """
Eres el Lead DevSecOps & Evaluador Académico para Ciberseguridad Defensiva (OCY1105) y programas avanzados (CSY6122 / CSY1102).
Tu rol es auditar con máximo rigor técnico los informes técnicos entregados por los estudiantes y emitir un veredicto estructurado.

RÚBRICA DE EVALUACIÓN (Escala de 5 niveles por Misión: 100%, 80%, 60%, 30%, 0%):

1. MISIÓN 1: GESTIÓN CUANTITATIVA DEL RIESGO DE CIBERSEGURIDAD
   - Fórmulas obligatorias a verificar matemáticamente:
     * SLE = AV * EF (Single Loss Expectancy = Asset Value * Exposure Factor)
     * ALE = SLE * ARO (Annualized Loss Expectancy = Single Loss Expectancy * Annualized Rate of Occurrence)
     * CBA = (ALE_inicial - ALE_mitigado) - Costo_Control (Cost-Benefit Analysis)
   - Criterios de Asignación:
     * 100%: Cálculos matemáticos 100% exactos en SLE, ALE inicial, ALE mitigado y CBA (positivo/negativo), con justificación financiera completa.
     * 80%: Fórmulas correctas y metodología impecable, con errores mínimos de redondeo o presentación.
     * 60%: Aplica las fórmulas pero comete errores aritméticos en ALE o CBA, o falta justificación del costo del control.
     * 30%: Fórmulas mal planteadas (confunde SLE con ALE o no calcula CBA).
     * 0%: No presenta análisis cuantitativo de riesgos ni fórmulas.

2. MISIÓN 2: DFIR & ANÁLISIS FORENSE DIGITAL
   - Artefactos requeridos:
     * Hashes SHA-256 de binarios/muestras identificadas.
     * Event IDs de Windows Security: 4624 (Logon / Logon Types), 4697 (Servicio instalado / Persistencia), 4688 (Creación de procesos con CommandLine).
     * Filtros Wireshark/tshark: HTTP POST (exfiltración), DNS (consultas anómalas / DGA / tunneling), ICMP (túneles / beacons).
     * Análisis forense de /var/log/auth.log (fuerza bruta SSH, accesos válidos, abuso de sudo).
   - Criterios de Asignación:
     * 100%: Hashes SHA-256 válidos, análisis contextual exhaustivo de Event IDs 4624, 4697 y 4688, sintaxis precisa de filtros Wireshark/tshark (HTTP POST, DNS, ICMP) y correlación de auth.log.
     * 80%: Cubre hashes, Windows Events, Wireshark y auth.log con interpretaciones correctas pero omitiendo algún detalle menor.
     * 60%: Omite uno de los componentes forenses (ej. falta filtro ICMP o falta Event ID 4697) o análisis superficial.
     * 30%: Mención genérica de conceptos sin hashes, sin sintaxis real de filtros ni Event IDs específicos.
     * 0%: No presenta análisis DFIR ni evidencia forense.

3. MISIÓN 3: SOC & NIDS (WAZUH SIEM Y SURICATA EVE.JSON)
   - Artefactos requeridos:
     * Despliegue y configuración de Wazuh SIEM con agentes activos (endpoints Windows/Linux), reglas de detección / FIM.
     * Parseo y análisis de telemetría de Suricata en eve.json (alertas, firmas ET/CVE, IPs origen/destino, severidad y payload).
   - Criterios de Asignación:
     * 100%: Evidencia clara de Wazuh Manager con agentes activos, políticas de monitoreo y parseo exhaustivo de alertas de Suricata en eve.json con correlación.
     * 80%: Despliegue funcional de Wazuh y análisis de eve.json, con evidencia parcial de correlación activa.
     * 60%: Despliegue básico de Wazuh o Suricata, pero sin análisis detallado de eve.json ni correlación.
     * 30%: Menciona herramientas sin evidencia de configuración ni análisis real de logs.
     * 0%: No implementa ni analiza Wazuh ni Suricata.

CÁLCULO DE NOTA SUGERIDA (Escala 1.0 a 7.0 con 60% de exigencia):
- Puntaje Global = (Misión_1 * 0.30) + (Misión_2 * 0.35) + (Misión_3 * 0.35)
- Si Puntaje < 60%: Nota = 1.0 + (Puntaje / 60.0) * 3.0
- Si Puntaje >= 60%: Nota = 4.0 + ((Puntaje - 60.0) / 40.0) * 3.0
- Nota redondeada a 1 decimal (mínimo 1.0, máximo 7.0).

Genera siempre la respuesta exclusivamente en formato JSON estructurado conforme al esquema solicitado.
"""


# ==============================================================================
# MOTOR DE EVALUACIÓN HEURÍSTICO / FALLBACK (REGLAS DETERMINÍSTICAS)
# ==============================================================================

def calcular_nota_chilena(puntaje_pct: float) -> float:
    """Calcula la nota en escala 1.0 a 7.0 con exigencia al 60%."""
    if puntaje_pct < 60.0:
        nota = 1.0 + (puntaje_pct / 60.0) * 3.0
    else:
        nota = 4.0 + ((puntaje_pct - 60.0) / 40.0) * 3.0
    return round(max(1.0, min(7.0, nota)), 1)


def evaluar_informe_offline(texto: str, nombre_archivo: str) -> EvaluacionInforme:
    """
    Evaluador determinístico basado en la rúbrica de Lead SOC Auditor.
    Utilizado como fallback robusto o en entornos sin conexión externa.
    """
    # 1. Extracción de Equipo
    m_equipo = re.search(r"EQUIPO EVALUADO:\s*(.+)", texto, re.IGNORECASE)
    equipo = m_equipo.group(1).strip() if m_equipo else Path(nombre_archivo).stem.replace("_", " ").title()

    # 2. Evaluación Misión 1 (Riesgos)
    tiene_sle = bool(re.search(r"SLE\s*=", texto, re.IGNORECASE) and (re.search(r"AV\s*[\*x]\s*EF", texto, re.IGNORECASE) or re.search(r"\$?\d+[\d,.]*\s*[\*x]\s*0?\.\d+", texto)))
    tiene_ale = bool(re.search(r"ALE(_inicial)?\s*=", texto, re.IGNORECASE) and (re.search(r"SLE\s*[\*x]\s*ARO", texto, re.IGNORECASE) or re.search(r"\$?\d+[\d,.]*\s*[\*x]\s*0?\.\d+", texto)))
    tiene_cba = bool(re.search(r"CBA\s*=", texto, re.IGNORECASE) and (re.search(r"ALE.*-.*(Costo|ALE)", texto, re.IGNORECASE) or re.search(r"beneficio|retorno|rosi", texto, re.IGNORECASE)))
    
    if tiene_sle and tiene_ale and tiene_cba:
        pts_m1 = 100
        estado_m1 = "Válido (100%)"
        obs_m1 = "Cálculos cuantitativos de SLE, ALE inicial/mitigado y CBA ejecutados con total exactitud y justificación financiera."
    elif tiene_sle and tiene_ale:
        pts_m1 = 80
        estado_m1 = "Errores Menores (80%)"
        obs_m1 = "Cálculos de SLE y ALE correctos; CBA presentado con omisiones menores en justificación del costo de salvaguarda."
    elif tiene_sle or tiene_ale:
        pts_m1 = 60
        estado_m1 = "Incompleto (60%)"
        obs_m1 = "Aplica fórmulas de riesgo pero presenta inconsistencias en el cálculo de ALE o CBA."
    elif re.search(r"riesgo|activo|amenaza", texto, re.IGNORECASE):
        pts_m1 = 30
        estado_m1 = "Incorrecto (30%)"
        obs_m1 = "Mención conceptual de riesgos sin aplicación rigurosa de las fórmulas cuantitativas requeridas."
    else:
        pts_m1 = 0
        estado_m1 = "No Presentado (0%)"
        obs_m1 = "No se presentó evidencia de gestión cuantitativa del riesgo."

    mision1 = Mision1Riesgo(
        puntaje=pts_m1,
        estado_calculos=estado_m1,
        sle_correcto=tiene_sle,
        ale_correcto=tiene_ale,
        cba_correcto=tiene_cba,
        observaciones=obs_m1
    )

    # 3. Evaluación Misión 2 (DFIR)
    tiene_sha256 = bool(re.search(r"[a-fA-F0-9]{64}", texto))
    event_ids = []
    if re.search(r"4624", texto):
        event_ids.append(4624)
    if re.search(r"4697", texto):
        event_ids.append(4697)
    if re.search(r"4688", texto):
        event_ids.append(4688)
    
    tiene_http_post = bool(re.search(r"http\.request\.method\s*==\s*[\"']?POST[\"']?", texto, re.IGNORECASE))
    tiene_dns = bool(re.search(r"dns\.(qry\.name|flags)", texto, re.IGNORECASE))
    tiene_icmp = bool(re.search(r"icmp\.(type|code)", texto, re.IGNORECASE))
    filtros_completos = tiene_http_post and tiene_dns and tiene_icmp
    tiene_auth_log = bool(re.search(r"auth\.log", texto, re.IGNORECASE) or re.search(r"sshd\[\d+\]:\s*(Failed|Accepted)", texto))

    ev_count = len(event_ids)
    if tiene_sha256 and ev_count == 3 and filtros_completos and tiene_auth_log:
        pts_m2 = 100
        estado_m2 = "Validado (100%)"
        obs_m2 = "Análisis forense impecable: SHA-256 verificado, Event IDs (4624, 4697, 4688) correlacionados, filtros Wireshark/tshark completos y auth.log analizado."
    elif tiene_sha256 and ev_count >= 2 and (tiene_http_post or tiene_dns) and tiene_auth_log:
        pts_m2 = 80
        estado_m2 = "Parcial (80%)"
        obs_m2 = "Buena cobertura forense con hashes y logs de Windows/Linux; se sugiere completar la totalidad de filtros Wireshark (ej. ICMP) o Event IDs."
    elif tiene_sha256 or ev_count >= 1 or tiene_auth_log:
        pts_m2 = 60
        estado_m2 = "Incompleto (60%)"
        obs_m2 = "Presenta artefactos forenses aislados pero carece de correlación completa entre Event IDs y tráfico PCAP."
    elif re.search(r"forense|dfir|evidencia", texto, re.IGNORECASE):
        pts_m2 = 30
        estado_m2 = "Insuficiente (30%)"
        obs_m2 = "Mención genérica de análisis forense sin evidencia técnica concreta (sin hashes ni Event IDs clave)."
    else:
        pts_m2 = 0
        estado_m2 = "No Validado (0%)"
        obs_m2 = "No se presentó análisis de DFIR."

    mision2 = Mision2DFIR(
        puntaje=pts_m2,
        dfir_validado=estado_m2,
        sha256_presente=tiene_sha256,
        event_ids_analizados=event_ids,
        filtros_wireshark_completos=filtros_completos,
        auth_log_analizado=tiene_auth_log,
        observaciones=obs_m2
    )

    # 4. Evaluación Misión 3 (SOC & NIDS)
    tiene_wazuh = bool(re.search(r"wazuh", texto, re.IGNORECASE) and re.search(r"agente|manager|regla", texto, re.IGNORECASE))
    tiene_suricata = bool(re.search(r"suricata", texto, re.IGNORECASE) and re.search(r"eve\.json", texto, re.IGNORECASE))
    tiene_alertas = bool(re.search(r"signature|severidad|alert|cve", texto, re.IGNORECASE))

    if tiene_wazuh and tiene_suricata and tiene_alertas:
        pts_m3 = 100
        estado_m3 = "Validado (100%)"
        obs_m3 = "Despliegue operativo de Wazuh SIEM con agentes activos y parseo exhaustivo de alertas en Suricata eve.json con Active Response."
    elif tiene_wazuh and tiene_suricata:
        pts_m3 = 80
        estado_m3 = "Parcial (80%)"
        obs_m3 = "Despliegue de Wazuh e integración de Suricata evidenciados; se sugiere profundizar en reglas de correlación personalizada."
    elif tiene_wazuh or tiene_suricata:
        pts_m3 = 60
        estado_m3 = "Incompleto (60%)"
        obs_m3 = "Implementación parcial de herramientas de monitoreo sin integración completa entre SIEM y NIDS."
    elif re.search(r"soc|siem|nids|monitoreo", texto, re.IGNORECASE):
        pts_m3 = 30
        estado_m3 = "Insuficiente (30%)"
        obs_m3 = "Mención conceptual de SOC/NIDS sin configuración demostrable."
    else:
        pts_m3 = 0
        estado_m3 = "No Validado (0%)"
        obs_m3 = "No se presentó evidencia de SOC ni NIDS."

    mision3 = Mision3SOC(
        puntaje=pts_m3,
        soc_nids_validado=estado_m3,
        wazuh_desplegado=tiene_wazuh,
        suricata_eve_json_analizado=tiene_suricata,
        observaciones=obs_m3
    )

    # Puntaje global ponderado: M1 (30%), M2 (35%), M3 (35%)
    puntaje_global = round((pts_m1 * 0.30) + (pts_m2 * 0.35) + (pts_m3 * 0.35), 1)
    nota_7 = calcular_nota_chilena(puntaje_global)

    obs_general = (
        f"Informe auditado para el {equipo}. Misión 1: {estado_m1} ({pts_m1}%). "
        f"Misión 2: {estado_m2} ({pts_m2}%). Misión 3: {estado_m3} ({pts_m3}%). "
        f"Rendimiento global de {puntaje_global}% equivalente a Nota {nota_7}."
    )

    return EvaluacionInforme(
        equipo=equipo,
        mision_1_riesgos=mision1,
        mision_2_dfir=mision2,
        mision_3_soc_nids=mision3,
        puntaje_global_porcentaje=puntaje_global,
        nota_sugerida_7=nota_7,
        observaciones_profesor=obs_general
    )


# ==============================================================================
# EVALUADOR PRINCIPAL CON GOOGLE-GENAI SDK
# ==============================================================================

def evaluar_con_gemini(texto_informe: str, nombre_archivo: str, api_key: str, modelo: str = "gemini-3.6-flash") -> EvaluacionInforme:
    """
    Evalúa el informe técnico utilizando el SDK oficial google-genai con Structured Outputs.
    """
    client = genai.Client(api_key=api_key)
    
    prompt = f"""
    AUDITORÍA TÉCNICA DE INFORME DE ESTUDIANTE:
    Archivo de Origen: {nombre_archivo}

    CONTENIDO DEL INFORME TÉCNICO A EVALUAR:
    \"\"\"
    {texto_informe}
    \"\"\"

    Instrucción: Evalúa rigurosamente conforme a la rúbrica de Lead SOC Auditor y genera el objeto JSON estructurado.
    """

    config = types.GenerateContentConfig(
        system_instruction=LEAD_SOC_SYSTEM_INSTRUCTIONS,
        response_mime_type="application/json",
        response_schema=EvaluacionInforme,
        temperature=0.1,
    )

    for intento in range(3):
        try:
            response = client.models.generate_content(
                model=modelo,
                contents=prompt,
                config=config,
            )
            
            if hasattr(response, "text") and response.text:
                return EvaluacionInforme.model_validate_json(response.text)
            elif hasattr(response, "parsed") and response.parsed:
                return response.parsed
            else:
                raise ValueError("Respuesta vacía recibida del modelo Gemini.")
        except Exception as e:
            if intento < 2:
                time.sleep(2)
            else:
                print(f"  [!] Advertencia: Error en llamada a Gemini ({e}). Ejecutando motor de evaluación determinístico de respaldo...")
                return evaluar_informe_offline(texto_informe, nombre_archivo)


# ==============================================================================
# PIPELINE AUTOMATIZADO PRINCIPAL
# ==============================================================================

def procesar_entregas(carpeta_entregas: str = "entregas", archivo_salida_csv: str = "consolidado_notas.csv"):
    """
    Pipeline principal: itera sobre todos los archivos .txt de entregas/, evalúa cada uno y guarda el CSV consolidado.
    """
    print("=" * 80)
    print("[*] PIPELINE DE EVALUACION AUTOMATIZADA - CIBERSEGURIDAD DEFENSIVA (OCY1105 / CSY6122)")
    print("    Rol: Lead DevSecOps & Evaluador Academico (Lead SOC Auditor)")
    print("=" * 80)

    # 1. Verificar clave de API
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    modelo = os.environ.get("GEMINI_MODEL", "gemini-3.6-flash").strip()

    if api_key:
        print(f"[+] Clave GEMINI_API_KEY detectada en el entorno.")
        print(f"[+] Utilizando modelo Gemini: {modelo}")
        modo_evaluacion = "GEMINI_AI"
    else:
        print(f"[*] AVISO: Variable de entorno GEMINI_API_KEY no detectada.")
        print(f"[*] Activando motor de evaluacion heuristico/deterministico conforme a la rubrica oficial.")
        modo_evaluacion = "DETERMINISTIC_SOC_ENGINE"

    # 2. Buscar archivos .txt en la carpeta entregas/
    ruta_carpeta = Path(carpeta_entregas)
    if not ruta_carpeta.exists():
        print(f"[-] Error: La carpeta '{carpeta_entregas}' no existe. Creandola...")
        ruta_carpeta.mkdir(parents=True, exist_ok=True)

    archivos_txt = sorted(glob.glob(str(ruta_carpeta / "*.txt")))
    if not archivos_txt:
        print(f"[-] No se encontraron archivos .txt en '{carpeta_entregas}/'. Finalizando.")
        return

    print(f"[+] Se encontraron {len(archivos_txt)} entrega(s) tecnica(s) para evaluar:\n")

    registros_evaluacion = []

    for idx, ruta_archivo in enumerate(archivos_txt, 1):
        nombre_base = Path(ruta_archivo).name
        print(f"--- [{idx}/{len(archivos_txt)}] Procesando: {nombre_base} ---")
        
        try:
            with open(ruta_archivo, "r", encoding="utf-8", errors="replace") as f:
                contenido = f.read()
        except Exception as e:
            print(f"  [-] Error al leer {nombre_base}: {e}")
            continue

        if modo_evaluacion == "GEMINI_AI" and GENAI_AVAILABLE:
            evaluacion = evaluar_con_gemini(contenido, nombre_base, api_key, modelo)
        else:
            evaluacion = evaluar_informe_offline(contenido, nombre_base)

        print(f"  -> Equipo: {evaluacion.equipo}")
        print(f"  -> Puntaje Global: {evaluacion.puntaje_global_porcentaje}% | Nota Sugerida: {evaluacion.nota_sugerida_7}")
        print(f"  -> Mision 1 (Riesgos): {evaluacion.mision_1_riesgos.estado_calculos}")
        print(f"  -> Mision 2 (DFIR): {evaluacion.mision_2_dfir.dfir_validado}")
        print(f"  -> Mision 3 (SOC/NIDS): {evaluacion.mision_3_soc_nids.soc_nids_validado}")
        print(f"  -> Observaciones: {evaluacion.observaciones_profesor}\n")

        registros_evaluacion.append({
            "Archivo": nombre_base,
            "Equipo": evaluacion.equipo,
            "Puntaje_Global_%": f"{evaluacion.puntaje_global_porcentaje:.1f}%",
            "Nota_Sugerida_7": f"{evaluacion.nota_sugerida_7:.1f}",
            "Estado_Calculos_Riesgo": evaluacion.mision_1_riesgos.estado_calculos,
            "DFIR_Validado": evaluacion.mision_2_dfir.dfir_validado,
            "SOC_NIDS_Validado": evaluacion.mision_3_soc_nids.soc_nids_validado,
            "Observaciones_Profesor": evaluacion.observaciones_profesor,
        })

    # 3. Guardar resultados en DataFrame y exportar CSV consolidado
    df_consolidado = pd.DataFrame(registros_evaluacion)
    df_consolidado.to_csv(archivo_salida_csv, index=False, encoding="utf-8-sig")
    print("=" * 80)
    print(f"[OK] CONSOLIDACION COMPLETADA: {archivo_salida_csv}")
    print("=" * 80)
    print("\n--- VISTA PREVIA DE CONSOLIDADO DE CALIFICACIONES ---\n")
    print(df_consolidado.to_string(index=False))
    print("\n" + "=" * 80)


if __name__ == "__main__":
    procesar_entregas()
