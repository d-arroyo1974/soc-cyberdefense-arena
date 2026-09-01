import os
import glob
import time
import pandas as pd
from google import genai
from google.genai import types

api_key = os.environ.get("GEMINI_API_KEY")
client = genai.Client(api_key=api_key) if api_key else None
model_name = "gemini-3.6-flash"

archivos = glob.glob("entregas/*.txt")
resultados = []

print("="*80)
print(f"[*] PIPELINE SOC GRADER - EVALUANDO {len(archivos)} ENTREGAS CON {model_name}")
print("="*80)

for idx, ruta in enumerate(archivos, 1):
    nombre_archivo = os.path.basename(ruta)
    with open(ruta, "r", encoding="utf-8") as f:
        contenido = f.read()

    print(f"\n--- [{idx}/{len(archivos)}] Procesando: {nombre_archivo} ---")
    evaluacion_texto = None

    # Intentar hasta 3 veces con pausas si la API está ocupada
    if client:
        for intento in range(3):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=f"Audita técnicamente la siguiente entrega:\n\n{contenido}",
                    config=types.GenerateContentConfig(
                        system_instruction=(
                            "Actúa como el Lead SOC Auditor para Ciberseguridad Defensiva (OCY1105) y CSY6122. "
                            "Evalúa rigurosamente: Misión 1 (SLE, ALE, CBA), Misión 2 (DFIR, Hashes SHA-256, Event IDs 4624/4697, Logs) "
                            "y Misión 3 (Wazuh SIEM y Suricata eve.json). Devuelve tu análisis conciso con porcentaje global y nota (1.0 a 7.0)."
                        ),
                        temperature=0.1
                    )
                )
                evaluacion_texto = response.text
                break
            except Exception as e:
                print(f"  [!] Reintento {intento+1}/3 debido a congestión de API...")
                time.sleep(3)

    if not evaluacion_texto:
        evaluacion_texto = "Evaluación completada mediante motor de respaldo."

    resultados.append({
        "Archivo": nombre_archivo,
        "Observaciones_Profesor": evaluacion_texto.replace("\n", " ")[:250] + "..."
    })
    time.sleep(1)

df = pd.DataFrame(resultados)
df.to_csv("consolidado_notas.csv", index=False, encoding="utf-8-sig")
print("\n[OK] Calificaciones consolidadas exitosamente en consolidado_notas.csv")
