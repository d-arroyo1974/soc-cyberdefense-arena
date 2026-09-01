# Guía Formativa - Misión 1: Gestión Cuantitativa del Riesgo (GRC)
**Asignatura:** Ciberseguridad Defensiva (OCY1105 / CSY6122 / CSY1102)  
**Entorno:** NetChile Corp / Soluciones Tecnológicas SPA  
**Rol:** Lead DevSecOps & Risk Analyst  

---

## 1. Fundamentos del Análisis Cuantitativo del Riesgo

En el marco de la gestión de riesgos corporativos (ISO 27005 / NIST SP 800-30), la evaluación cuantitativa traduce los impactos de ciberseguridad en métricas monetarias directas. Esto permite a la dirección técnica presentar casos de negocio sólidos ante el Directorio (C-Level).

---

## 2. Fórmulas Obligatorias y Metodología

### 2.1 Pérdida Única Esperada ($SLE$)
Representa la pérdida económica total ante una única ocurrencia de un incidente de seguridad.

$$\mathbf{SLE = AV \times EF}$$

- **$AV$ (*Asset Value*):** Valor total del activo en dólares (costo de reposición, valor de los datos, lucro cesante y multas regulatorias).
- **$EF$ (*Exposure Factor*):** Porcentaje de pérdida que experimentaría el activo si la amenaza se materializa (ej. $0.40 = 40\%$).

### 2.2 Pérdida Anualizada Esperada Inicial ($ALE_{inicial}$)
Representa el costo económico estimado por año que la organización sufriría por una amenaza sin controles adicionales.

$$\mathbf{ALE = SLE \times ARO}$$

- **$ARO$ (*Annualized Rate of Occurrence*):** Frecuencia con la que se proyecta que ocurra la amenaza en un año (ej. $0.5$ = 1 vez cada 2 años; $2.0$ = 2 veces al año).

### 2.3 Pérdida Anualizada Mitigada ($ALE_{mitigado}$)
Cálculo del riesgo residual tras implementar una salvaguarda tecnológica o procedimental:

$$SLE_{mitigado} = AV \times EF_{mitigado}$$
$$ALE_{mitigado} = SLE_{mitigado} \times ARO_{mitigado}$$

### 2.4 Análisis Costo-Beneficio ($CBA$) & Retorno de Inversión en Seguridad ($ROSI$)
Mide el beneficio económico neto anual que genera la implementación del control:

$$\mathbf{CBA = (ALE_{inicial} - ALE_{mitigado}) - Costo\_Control}$$

$$\mathbf{ROSI = \left(\frac{(ALE_{inicial} - ALE_{mitigado}) - Costo\_Control}{Costo\_Control}\right) \times 100\%}$$

- **Criterio de Decisión:**
  - Si $CBA > 0$: La inversión en seguridad genera un ahorro financiero neto y se recomienda su aprobación.
  - Si $CBA \le 0$: El costo del control supera las pérdidas que previene; se debe evaluar una salvaguarda alternativa.

---

## 3. Ejemplo Práctico de Aplicación

| Parámetro | Escenario Inicial (Sin Control) | Escenario Mitigado (Con EDR + WAF + MFA) |
| :--- | :--- | :--- |
| **Activo ($AV$)** | Servidor Transaccional (\$500,000 USD) | Servidor Transaccional (\$500,000 USD) |
| **Factor de Exposición ($EF$)** | 40% ($0.40$) | 5% ($0.05$) |
| **$SLE$** | $\$500,000 \times 0.40 = \$200,000$ USD | $\$500,000 \times 0.05 = \$25,000$ USD |
| **Tasa de Ocurrencia ($ARO$)** | 0.5 (1 cada 2 años) | 0.1 (1 cada 10 años) |
| **$ALE$** | $\$200,000 \times 0.5 = \$100,000$ USD/año | $\$25,000 \times 0.1 = \$2,500$ USD/año |
| **Costo Anual del Control** | $\$0$ | $\$15,000$ USD/año |
| **Beneficio Neto ($CBA$)** | - | $(\$100,000 - \$2,500) - \$15,000 = \mathbf{\$82,500\text{ USD/año}}$ |
| **$ROSI$** | - | $(\$82,500 / \$15,000) \times 100\% = \mathbf{550\%}$ |

---

## 4. Entregables de la Misión 1
1. Diligenciamiento de la sección 1 en [`templates/plantilla_informe.txt`](file:///C:/Users/cloud/soc-autograder/templates/plantilla_informe.txt).
2. Registro en [`templates/matriz_riesgos_cba.csv`](file:///C:/Users/cloud/soc-autograder/templates/matriz_riesgos_cba.csv) de al menos 3 activos evaluados.
