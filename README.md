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

Requiere Go 1.21 o superior.

### Linux / macOS (bash, zsh)

```bash
git clone <repo> staging-shield
cd staging-shield
go build -o staging-shield
./staging-shield version
```

### Windows (PowerShell)

PowerShell **no** entiende la sintaxis bash `VAR=valor cmd` y **no** ejecuta
binarios sin extensión `.exe`. Use los comandos siguientes tal cual:

```powershell
git clone <repo> staging-shield
cd staging-shield
go build -o staging-shield.exe
.\staging-shield.exe version
```

Errores típicos en PowerShell y su causa:

| Síntoma | Causa | Corrección |
|---------|-------|------------|
| `'GOOS=windows' no se reconoce como nombre de un cmdlet` | Sintaxis bash en PowerShell | `$env:GOOS="windows"; go build -o ...` (o simplemente omitirlo: en Windows ya es el default) |
| Windows abre un diálogo "Elija un programa para abrir este archivo" | Compiló como `staging-shield` sin `.exe` | Recompile con `go build -o staging-shield.exe` |
| `'staging-shield' no se reconoce como nombre de un cmdlet` | PowerShell no busca en el directorio actual | Use `.\staging-shield.exe ...` (con `.\`) |

### Build multiplataforma

```bash
# Linux / macOS (bash):
GOOS=linux  GOARCH=amd64 go build -o dist/staging-shield-linux-amd64
GOOS=darwin GOARCH=arm64 go build -o dist/staging-shield-darwin-arm64
GOOS=windows GOARCH=amd64 go build -o dist/staging-shield-windows-amd64.exe
```

```powershell
# Windows (PowerShell):
$env:GOOS="linux";   $env:GOARCH="amd64"; go build -o dist/staging-shield-linux-amd64
$env:GOOS="darwin";  $env:GOARCH="arm64"; go build -o dist/staging-shield-darwin-arm64
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -o dist/staging-shield-windows-amd64.exe
```

El binario es **autocontenido** (no requiere dependencias externas en runtime,
la plantilla HTML del reporte está embebida con `//go:embed`).

---

## Uso rápido

### 1. Con archivo de configuración (recomendado)

```bash
# Linux / macOS:
./staging-shield scan --config examples/config.yaml --html-out reporte.html --verbose
```

```powershell
# Windows (PowerShell):
.\staging-shield.exe scan --config examples\config.yaml --html-out reporte.html --verbose
```

Ver `examples/config.yaml` (incluido en el repo) para un ejemplo completo y comentado
del formato de entrada.

### 2. Solo con flags

```bash
./staging-shield scan \
  --name "staging-pagos" \
  --domain staging.miempresa.com \
  --ports 80,443,8080 \
  --repo /ruta/al/repo \
  --prod-refs 10.0.0.50,db-prod.miempresa.com \
  --html-out reporte.html
```

### 3. Ver historial de corridas

```bash
./staging-shield history --env staging-pagos --last 10
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

## Cobertura

El cliente reporta **tres métricas de cobertura** en cada corrida:

- **Cobertura automática** — % de SVR resueltas por el motor (DNS, puertos, TLS, headers, escaneo de secretos consciente de git, etc.).
- **Cobertura manual** — % de SVR resueltas por veredicto humano vía `--review` o desde el centro de revisión del HTML.
- **Cobertura total** — la suma de las dos anteriores. Es la métrica que debe acompañar al Security Score: un score de 90 con cobertura del 30% no significa lo mismo que con cobertura del 90%.

De las 36 SVR, el cliente automatiza **17 de forma estándar** (DNS, puertos, TLS, headers, secretos con git-awareness, probes de interfaces admin) o **24 con modo invasivo `--local-host-scan`** activado. Las restantes dependen de juicio humano (políticas, procedimientos, acceso a infraestructura interna). Para que las manuales no queden fuera del cálculo, el cliente expone dos vías de revisión:

### Centro de revisión interactivo (HTML)

El reporte HTML incluye un panel donde cada SVR manual o sin evidencia tiene controles **Cumple / Cumple parcialmente / No cumple / No aplica** más un campo de evidencia. Al cambiar un veredicto, ya sea con un click o por **Importar revisión** desde un YAML:

- El score por dominio, score global y aptitud se recalculan en vivo.
- La cobertura total sube reflejando el progreso de la revisión.
- **Cada porcentaje que cambia destella brevemente en azul** para que sea visible que el recálculo ocurrió y no solo se actualizaron las tarjetas.
- El toast de confirmación incluye el score y cobertura nuevos: `"✓ 8 veredictos aplicados — Score 72.8 · Cobertura 52.8%"`.
- Cuando termina, **Exportar revisión** descarga un archivo YAML que la CLI puede consumir.

Por encima de la sección de fallas, el HTML muestra también una sección **"SVR que cumplen y su evidencia"** agrupada por dominio. Lista cada regla en estado *Cumple* o *Cumple parcialmente* junto con la evidencia técnica que el motor usó para puntuarla, de modo que el lector del reporte pueda auditar de dónde sale el Security Score y no solo qué reglas fallan.

### Archivo de revisión (CLI)

```bash
staging-shield scan --config staging.yaml --review revision.yaml
```

El archivo `revision.yaml` (formato en `examples/review.yaml`) contiene veredictos persistentes que se aplican antes del scoring. Esto cierra el ciclo: el evaluador revisa interactivamente en el HTML, exporta el YAML, lo commitea junto con la configuración del entorno, y la próxima corrida ya parte con esa evidencia incorporada — la cobertura no se pierde entre ejecuciones.

---

## Detección de secretos consciente de git

El validador SVR-IAM-04 (secretos en código) y SVR-IAM-07 (variables sensibles) **no penalizan archivos `.env` solo locales**. Un `.env` en `.gitignore` con credenciales de desarrollo es la práctica recomendada, no una falla. La lógica:

| Estado del `.env` | SVR-IAM-07 |
|---|---|
| Trackeado por git actualmente | **No cumple** (alta) — exposición pública. |
| Presente en historial git aunque hoy no esté | **No cumple** (alta) — recuperable de commits previos. |
| Existe en disco + en `.gitignore` | **Cumple** — práctica recomendada. |
| Existe en disco + no en `.gitignore` | **Cumple parcial** — riesgo latente de commit accidental. |
| No existe | **Cumple**. |

Los secretos detectados por patrón (AWS keys, tokens, URLs con credenciales) se etiquetan con su estado de exposición en el reporte HTML: solo los que están en archivos trackeados o en historial penalizan SVR-IAM-04. Cuando el repositorio no es git, los validadores caen al comportamiento previo (presencia en disco) y lo notifican en el reporte.

### Filtro de tests y placeholders

El detector ignora secretos que sean claramente fixtures de prueba. Quedan visibles en la tabla de evidencia pero **no penalizan el score**:

- **Archivos bajo rutas de test**: `test/`, `tests/`, `__tests__/`, `spec/`, `e2e/`, `cypress/`, `playwright/`, `fixtures/`, `mocks/`, `testdata/`, `examples/`.
- **Sufijos de archivos de test**: `.test.`, `.spec.`, `_test.`, `_spec.`, `-test.`.
- **Palabras placeholder en el valor**: `invalid`, `fake`, `dummy`, `placeholder`, `your-token`, `changeme`, `xxxx`, `<token>`, `lorem`, `abc123`, etc.

Así, un literal como `Bearer invalid-token-for-test` dentro de `tasks.http.integration.test.js` no genera falso positivo.

---

## Modo invasivo: `--local-host-scan`

Automatiza **5 reglas adicionales de hardening** que requieren leer estado del sistema. **Solo inspecciona el equipo donde corre el cliente; nunca hosts remotos.** Activación:

```bash
# CLI
./staging-shield scan --config config.yaml --local-host-scan

# YAML
local_host_scan: true
```

Al activarlo:

1. **stderr muestra un banner de advertencia** con la lista exacta de cosas que va a leer del sistema, imposible de ignorar.
2. **El HTML genera una sección dedicada** con todos los hallazgos y una pill naranja en el encabezado.
3. **Cada regla automatizada incluye en su evidencia** el comando o archivo consultado.

### Reglas que pasan de manual a automático

| Regla | Verificación |
|-------|--------------|
| **SVR-HAR-03** | Lee `/etc/ssh/sshd_config` real (PermitRootLogin, PasswordAuthentication) en vez de inferir por banner. |
| **SVR-HAR-04** | Cuenta paquetes pendientes vía `apt list --upgradable`, `dnf check-update`, `pacman -Qu`. Diferencia actualizaciones de seguridad cuando el gestor lo permite. |
| **SVR-HAR-05** | Detecta `ufw`, `firewalld`, `nftables` o `iptables`, verifica si está activo y si la política default es deny. |
| **SVR-HAR-08** | Comprueba permisos de `/etc/shadow`, `/etc/sudoers`, claves SSH del host, `authorized_keys` de root contra la línea base CIS §6.1–6.2. |
| **SVR-HAR-10** | Verifica si `auditd` está activo; usa `systemd-journald` como fallback. |
| **SVR-MON-01** | Inventaria logs en `/var/log` y comprueba si hay `logrotate` configurado. |

### Cuándo activarlo

- ✅ Pipeline CI/CD que corre **on the staging host** (Jenkins agent, GitHub Actions self-hosted runner sobre el servidor).
- ✅ Auditoría manual conectado por SSH al servidor de staging.
- ❌ **No** desde tu laptop apuntando a un staging remoto — leería tu laptop, no el servidor.

Si lo activas accidentalmente desde una máquina equivocada, el banner amarillo del HTML te advierte que los resultados describen al evaluador, no al objetivo.

---

## Modo remoto SSH: `--ssh-target` (pensado para CI/CD)

Mismas verificaciones que `--local-host-scan` pero ejecutadas contra un host remoto vía SSH. Pensado para pipelines de CI/CD que NO corren sobre el propio servidor de staging.

```bash
# Llave en disco
./staging-shield scan \
  --config staging.yaml \
  --ssh-target staging-shield@staging.miempresa.com \
  --ssh-key ~/.ssh/staging-shield-key \
  --ssh-sudo

# Llave desde variable de entorno (patrón CI/CD)
export STAGING_SHIELD_SSH_KEY="$(cat ~/.ssh/staging-shield-key)"
./staging-shield scan \
  --config staging.yaml \
  --ssh-target staging-shield@staging.miempresa.com \
  --ssh-sudo
```

Cómo funciona: el cliente abre una sesión SSH usando el binario `ssh` del sistema. Para cada comando que necesita ejecutar remotamente (apt list, ufw status, etc.), abre una conexión, ejecuta el comando, lee la salida, cierra. Igual para lectura de archivos (`cat` remoto) y `stat`. La evidencia recopilada se almacena en los mismos campos que el modo local, y los validadores no necesitan saber qué modo se usó.

**Configuración del host objetivo:** ver [`docs/host-setup.md`](docs/host-setup.md). En resumen: crear un usuario dedicado `staging-shield`, autorizar la llave pública con `from=` para restringir el origen, y dar `sudo NOPASSWD` **solo** a los 6-8 comandos específicos que el cliente necesita. **NO** se otorga sudo total.

### Integración con CI/CD

#### GitHub Actions

El proyecto incluye un workflow listo en `.github/workflows/staging-shield.yml`. Configurar tres secrets (`Settings → Secrets and variables → Actions`):

| Secret | Valor |
|--------|-------|
| `STAGING_SSH_KEY` | Contenido completo de la llave privada (incluyendo `-----BEGIN...-----` y `-----END...-----`). |
| `STAGING_SSH_TARGET` | `staging-shield@<host>`. |
| `STAGING_DOMAIN` | (opcional) Dominio público del entorno. |

El workflow corre en cada push a `main`, en cada PR, semanalmente (cron), y bajo demanda (workflow_dispatch). En PRs deja un comentario con el Security Score y los scores por dominio. Si alguna SVR crítica falla (`--fail-on-noapt`), el job falla y bloquea el merge.

El reporte HTML completo queda como artifact descargable de cada corrida durante 30 días.

#### GitLab CI

```yaml
staging-scan:
  image: golang:1.21
  variables:
    STAGING_SHIELD_SSH_KEY: $STAGING_SSH_KEY_VAR  # var del proyecto, masked
  script:
    - go build -o staging-shield
    - ./staging-shield scan
        --config examples/config.yaml
        --ssh-target "$STAGING_SSH_TARGET"
        --ssh-sudo
        --html-out staging-shield-report.html
        --fail-on-noapt
  artifacts:
    paths: [staging-shield-report.html]
    expire_in: 30 days
    when: always
```

#### Jenkins

Usar `withCredentials([sshUserPrivateKey(...)])` para inyectar la llave como archivo temporal y pasarla con `--ssh-key`. Ejemplo completo en `docs/host-setup.md`.

### Modelo de seguridad del modo SSH

| Riesgo | Mitigación incorporada |
|--------|----------------------|
| Llave en logs del CI | El cliente la escribe a temp file 0600. El secret se enmascara en logs de GitHub Actions/GitLab. Nunca se imprime. |
| Comando arbitrario vía sudo | sudoers con paths absolutos y argumentos exactos. El cliente quotea cada arg con `'...'` para evitar inyección. |
| MITM en primera conexión | `StrictHostKeyChecking=accept-new`: acepta primera conexión, rechaza si la llave del host cambia después. |
| Llave comprometida | `from=` en `authorized_keys` restringe origen. Sudo limitado a los comandos del escáner. Recomendación: rotar cada 90 días. |
| Lectura del repo desde el host | El cliente NUNCA copia archivos del repo al host remoto. El escaneo de secretos corre 100% en el runner del CI. |

---

## Salidas

### Consola

Resumen coloreado con:

- Score global con barra de progreso.
- Score por dominio.
- Veredicto Apto/No Apto.
- Listado priorizado de fallos (severidad descendente).
- Hallazgos críticos destacados.

### HTML interactivo

Reporte responsivo con tema oscuro, embebido en el binario. Incluye:

- Header con score, score por dominio (con barras), cobertura total/auto/manual y aptitud.
- **Centro de revisión manual** con barra de progreso y controles Cumple / Parcial / No cumple / No aplica para cada SVR pendiente. El score, la cobertura y la aptitud se recalculan en vivo al marcar veredictos.
- Botones de **Exportar revisión** (genera el YAML que la CLI consume con `--review`) e **Importar revisión**.
- Tabla completa de las 36 SVR con estado, severidad, evidencia, notas y, donde aplique, los controles de revisión.
- Sección de evidencia técnica con puertos, TLS, headers, secretos redactados (con columna de exposición trackeado/historial/local) y archivos `.env` analizados con su estado de tracking en git.

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
