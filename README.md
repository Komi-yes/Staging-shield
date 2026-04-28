# Staging Shield

**Modelo de Evaluación de Seguridad para Entornos de Preproducción**

Programa cliente CLI escrito en Go que automatiza la verificación de las **36
Security Verification Rules (SVR)** del modelo, calcula el **Security Score**
con la fórmula oficial y produce un veredicto de aptitud (Apto / No Apto).

---

## ¿Qué resuelve?

Los entornos de staging son frecuentemente vector de ataque porque heredan
configuraciones débiles, secretos en código y conectividad indebida con
producción. Este cliente evalúa un entorno objetivo en cuatro dominios:

| Dominio | Reglas | Foco |
|--------|:------:|------|
| **NET** — Red y aislamiento | 10 | DNS, puertos, segmentación, TLS, prod-isolation |
| **HAR** — Hardening de host y plataforma | 10 | Banners, headers, debug expuesto, binarios |
| **IAM** — Identidades, acceso y secretos | 8 | Secretos en repo, credenciales por defecto, MFA |
| **MON** — Monitoreo, integridad y trazabilidad | 8 | Logs, alertas, evidencia, historial comparable |

---

## Modelo de Scoring

Cada SVR aporta al score con tres factores:

```
Score = 100 × Σ(c · w · d) ÷ Σ(w · d)
```

- `c` — cumplimiento: **1.0** (Cumple) · **0.5** (Parcial) · **0.0** (No cumple).
- `w` — peso por severidad: **3** (Alta) · **2** (Media) · **1** (Baja).
- `d` — peso del dominio (1.0 por defecto, ajustable).

**Aptitud** (`Apto = 1`) requiere que **ninguna SVR crítica esté en "No
cumple"**. Las reglas críticas son: SVR-NET-01, NET-02, NET-04, NET-05, NET-08,
IAM-01, IAM-04. Si una sola de ellas falla, el entorno es **No Apto**
independientemente del valor numérico del score.

---

## Instalación

### Desde código fuente

Requiere Go 1.21 o superior.

```bash
git clone <repo> staging-shield
cd staging-shield
go build -o staging-shield
./staging-shield version
```

### Build multiplataforma

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o dist/staging-shield-linux-amd64

# macOS
GOOS=darwin GOARCH=arm64 go build -o dist/staging-shield-darwin-arm64

# Windows
GOOS=windows GOARCH=amd64 go build -o dist/staging-shield-windows-amd64.exe
```

El binario es **autocontenido** (no requiere dependencias externas en runtime,
la plantilla HTML del reporte está embebida con `//go:embed`).

---

## Uso rápido

### 1. Con archivo de configuración (recomendado)

```bash
staging-shield scan --config examples/config.yaml --html-out reporte.html --verbose
```

### 2. Solo con flags

```bash
staging-shield scan \
  --name "staging-pagos" \
  --domain staging.miempresa.com \
  --ports 80,443,8080 \
  --repo /ruta/al/repo \
  --prod-refs 10.0.0.50,db-prod.miempresa.com \
  --html-out reporte.html
```

### 3. Ver historial de corridas

```bash
staging-shield history --env staging-pagos --last 10
```

---

## Comandos disponibles

```
staging-shield
├── scan       Ejecuta evaluación completa (5 módulos)
├── history    Lista corridas previas y muestra evolución del score
└── version    Versión + plataforma + tamaño del catálogo SVR
```

### `scan` — flags principales

| Flag | Descripción |
|------|-------------|
| `-c`, `--config` | Ruta a YAML con configuración del entorno |
| `-n`, `--name` | Nombre del entorno (obligatorio si no hay config) |
| `-d`, `--domain` | Dominio objetivo |
| `--ip` | IP del servidor objetivo |
| `-p`, `--ports` | Puertos esperados (CSV: `80,443,8080`) |
| `-r`, `--repo` | Ruta local al repositorio (escaneo de secretos) |
| `--prod-refs` | IPs/hosts de producción para validar aislamiento |
| `--admin-interfaces` | Puertos/rutas administrativos esperados |
| `--html-out` | Archivo HTML de salida |
| `--json-out` | Archivo JSON adicional de salida |
| `--history-dir` | Directorio de historial (default: `~/.staging-shield/history`) |
| `--no-save` | No guarda snapshot |
| `--no-color` | Desactiva colores ANSI |
| `-v`, `--verbose` | Trazas detalladas de descubrimiento |
| `--fail-on-noapt` | Exit code 2 si Apto=0 (útil en pipelines CI/CD) |

---

## Esquema del archivo de configuración

Ver `examples/config.yaml` para un ejemplo completo y comentado.

```yaml
environment:
  name: "staging-pagos"
  type: "staging"
  stack: "web"
target:
  domain: "staging.miempresa.com"
  ip: "10.20.30.40"
expected_ports: [80, 443]
repository:
  path: "/ruta/al/repo"
production:
  references: ["10.0.0.50", "db-prod.miempresa.com"]
admin_interfaces: ["9090", "/admin"]
```

---

## Arquitectura interna

El cliente está organizado en **5 módulos** que se ejecutan en pipeline:

```
┌──────────┐    ┌──────────────┐    ┌────────────┐    ┌─────────┐    ┌──────────┐
│ Entrada  │ →  │ Descubrimiento│ → │ Validación │ →  │ Scoring │ →  │ Reporte  │
│  (YAML)  │    │ (DNS/Net/Repo)│   │  (36 SVR)  │    │ (Score) │    │ (Cons/HTML/JSON)│
└──────────┘    └──────────────┘    └────────────┘    └─────────┘    └──────────┘
```

| Paquete | Responsabilidad |
|---------|-----------------|
| `internal/config` | Parseo y validación de YAML/flags. Construye `EvalContext`. |
| `internal/discovery` | Sondas activas: DNS, escaneo de puertos (50 workers concurrentes), TLS, headers HTTP, banners, secretos en repo, alcance a prod, exposición admin, servicios legacy. |
| `internal/rules` | Catálogo completo de las 36 SVR + dispatcher de validadores. |
| `internal/scoring` | Aplica fórmula de score, score por dominio y aptitud crítica. |
| `internal/storage` | Persistencia JSON del historial en `~/.staging-shield/history`. |
| `internal/report` | Salida en consola con ANSI colors + reporte HTML autocontenido. |

---

## Cobertura de automatización

De las 36 SVR, el cliente automatiza ~17 **completamente** y otras varias en
modo **semi-automático** (recolecta evidencia, marca para revisión humana). Las
reglas que requieren juicio humano (políticas, procedimientos, propietarios)
quedan en estado **`manual_requerido`** con la evidencia disponible para que un
evaluador la complete posteriormente. Estas reglas no contaminan el score (el
cálculo solo considera Cumple / Parcial / No cumple).

La cobertura automatizada se reporta como **AutoCoverage** en cada corrida,
permitiendo verificar SVR-MON-08 (alcance del modelo es transparente).

---

## Salidas

### Consola

Resumen coloreado con:

- Score global con barra de progreso.
- Score por dominio.
- Veredicto Apto/No Apto.
- Listado priorizado de fallos (severidad descendente).
- Hallazgos críticos destacados.

### HTML

Reporte responsivo con tema oscuro, embebido en el binario. Incluye:

- Header con score, dominio scores, aptitud.
- Tabla completa de las 36 SVR con su estado, severidad, evidencia y notas.
- Sección de descubrimiento (puertos, TLS, headers, secretos redactados).

### JSON (historial)

Cada corrida se guarda como `{env-slug}-{timestamp}.json` y contiene:

- Versión del catálogo + nombre/stack/target del entorno.
- Stats agregadas (score global + por dominio + status counts + críticas).
- Resultados detallados por SVR.
- Evidencia técnica completa.

Esto cumple **SVR-MON-05** (corridas comparables a lo largo del tiempo).

---

## Integración en CI/CD

```yaml
# Ejemplo: bloquear merges si staging no es Apto
- name: Evaluar staging
  run: |
    staging-shield scan \
      --config .ci/staging.yaml \
      --html-out staging-report.html \
      --no-color \
      --fail-on-noapt
```

`--fail-on-noapt` devuelve exit code `2` cuando `Apto = 0`, lo cual hace fallar
el pipeline y bloquea la promoción del entorno.

---

## Limitaciones del modelo

Documentadas en el proyecto y respetadas en el cliente:

- El cliente **observa desde fuera** del entorno: ciertas SVR (configuración
  interna del SO, IAM cloud-side) requieren acceso privilegiado y se marcan
  como manuales con instrucciones para el evaluador.
- Los pesos de dominio son ajustables (`scoring.DomainWeight`) para
  calibraciones empíricas futuras.
- El detector de secretos prioriza precisión sobre exhaustividad: usa 12
  patrones bien definidos y redacta los hallazgos en los reportes.
- El escaneo de puertos cubre los ~70 puertos más comunes + los declarados
  en `expected_ports`. No es un sustituto de un escaneo completo con nmap.

---

## Licencia

Trabajo académico. Uso libre con atribución.
