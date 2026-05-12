# Configuración del host de staging para Staging Shield (modo remoto)

Esta guía describe cómo preparar el servidor de staging para aceptar las
verificaciones del modo `--ssh-target` desde un pipeline de CI/CD u otro
equipo de evaluación.

## Resumen del flujo

1. Crear un usuario dedicado en el host de staging (no usar `root`).
2. Generar un par de llaves SSH dedicadas para staging-shield.
3. Autorizar la llave pública en el usuario del paso 1.
4. Conceder `sudo NOPASSWD` solo para los comandos que el escáner necesita.
5. Cargar la llave privada como secret en el CI/CD.

## Paso 1 — Crear usuario dedicado

```bash
# En el host de staging, como root o con sudo:
sudo useradd -m -s /bin/bash staging-shield
sudo passwd -l staging-shield   # bloquea login con password
```

Justificación: separar este usuario del resto de cuentas de servicio
facilita auditar exactamente qué hace el escáner y revocar acceso si la
llave se compromete sin afectar otros sistemas.

## Paso 2 — Generar llaves dedicadas

Hacer esto en una máquina segura (no en el servidor de staging, no en CI).

```bash
ssh-keygen -t ed25519 -N "" -C "staging-shield@miempresa.com" \
  -f ~/.ssh/staging-shield-key
```

Resultado:
- `staging-shield-key` (privada, **secreta**)
- `staging-shield-key.pub` (pública, segura de compartir)

## Paso 3 — Autorizar la llave pública

```bash
# En el host de staging, como root:
sudo mkdir -p /home/staging-shield/.ssh
sudo chmod 700 /home/staging-shield/.ssh

# Copiar el contenido del .pub al authorized_keys
sudo tee /home/staging-shield/.ssh/authorized_keys < ~/staging-shield-key.pub > /dev/null

sudo chmod 600 /home/staging-shield/.ssh/authorized_keys
sudo chown -R staging-shield:staging-shield /home/staging-shield/.ssh
```

Opcional pero recomendado: restringir desde dónde puede conectarse esta
llave. Editar la línea en `authorized_keys` con el siguiente prefijo:

```
from="192.168.0.0/16,10.0.0.0/8",no-agent-forwarding,no-port-forwarding,no-X11-forwarding ssh-ed25519 AAAA... staging-shield@miempresa.com
```

Si el CI/CD tiene IPs estáticas o un rango conocido (Self-hosted runners,
GitLab runners propios, IPs documentadas de GitHub Actions), restrinja
con `from=`. Si usa GitHub-hosted runners el rango es muy amplio y
dinámico — en ese caso confíe en la llave + sudo restringido.

## Paso 4 — Sudo NOPASSWD solo para comandos necesarios

El escáner solo usa sudo para 3-4 comandos. NUNCA dé sudo total. Cree el
archivo `/etc/sudoers.d/staging-shield` con `sudo visudo -f` y este
contenido exacto:

```
# Comandos que staging-shield necesita ejecutar con sudo.
# El cliente usa "sudo -n" (no-password), así que NOPASSWD es obligatorio.
# Si agrega herramientas, mantenga esta lista lo más corta posible.

staging-shield ALL=(root) NOPASSWD: /usr/bin/cat /etc/ssh/sshd_config
staging-shield ALL=(root) NOPASSWD: /usr/bin/cat /etc/shadow
staging-shield ALL=(root) NOPASSWD: /usr/bin/cat /etc/sudoers
staging-shield ALL=(root) NOPASSWD: /usr/sbin/iptables -S
staging-shield ALL=(root) NOPASSWD: /usr/sbin/iptables-save
staging-shield ALL=(root) NOPASSWD: /usr/sbin/ip6tables -S
staging-shield ALL=(root) NOPASSWD: /usr/sbin/nft list ruleset
staging-shield ALL=(root) NOPASSWD: /usr/sbin/ufw status
staging-shield ALL=(root) NOPASSWD: /usr/sbin/ufw status verbose
```

Verifique que el archivo está sintácticamente correcto:

```bash
sudo visudo -c -f /etc/sudoers.d/staging-shield
```

Salida esperada: `/etc/sudoers.d/staging-shield: parsed OK`

## Paso 5 — Cargar la llave en el CI/CD

### GitHub Actions

1. Ir a **Settings → Secrets and variables → Actions → New repository secret**.
2. Crear `STAGING_SSH_KEY` con el contenido **completo** de la llave privada
   (incluye `-----BEGIN OPENSSH PRIVATE KEY-----` y `-----END OPENSSH PRIVATE KEY-----`).
3. Crear `STAGING_SSH_TARGET` con el valor `staging-shield@<host>` (ej:
   `staging-shield@staging.miempresa.com`).
4. (Opcional) `STAGING_DOMAIN` con el dominio público del entorno.

El workflow `.github/workflows/staging-shield.yml` ya consume estos
secrets automáticamente.

### GitLab CI

`Settings → CI/CD → Variables`:
- `STAGING_SHIELD_SSH_KEY` (Protected, Masked si la UI lo permite)
- `STAGING_SHIELD_SSH_TARGET`

En `.gitlab-ci.yml`:

```yaml
staging-scan:
  image: golang:1.21
  script:
    - go build -o staging-shield
    - ./staging-shield scan
        --config examples/config.yaml
        --ssh-target "$STAGING_SHIELD_SSH_TARGET"
        --ssh-sudo
        --html-out staging-shield-report.html
        --fail-on-noapt
  artifacts:
    paths: [staging-shield-report.html]
    expire_in: 30 days
    when: always
```

### Jenkins

`Manage Jenkins → Credentials → System → Global credentials`:
- Tipo: **SSH Username with private key**
- ID: `staging-shield-ssh-key`
- Username: `staging-shield`
- Private Key: pegar el contenido de la llave

En `Jenkinsfile`:

```groovy
pipeline {
  agent { docker { image 'golang:1.21' } }
  environment {
    STAGING_SSH_TARGET = 'staging-shield@staging.miempresa.com'
  }
  stages {
    stage('Build') {
      steps { sh 'go build -o staging-shield' }
    }
    stage('Security Scan') {
      steps {
        withCredentials([sshUserPrivateKey(
          credentialsId: 'staging-shield-ssh-key',
          keyFileVariable: 'SSH_KEY')]) {
          sh '''
            ./staging-shield scan \
              --config examples/config.yaml \
              --ssh-target "$STAGING_SSH_TARGET" \
              --ssh-key "$SSH_KEY" \
              --ssh-sudo \
              --html-out staging-shield-report.html \
              --fail-on-noapt
          '''
        }
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'staging-shield-report.html', allowEmptyArchive: true
      publishHTML([
        reportDir: '.',
        reportFiles: 'staging-shield-report.html',
        reportName: 'Staging Shield'
      ])
    }
  }
}
```

## Verificación

Desde su máquina local, antes de invocar el CI:

```bash
# Test de conectividad SSH básica
ssh -i ~/.ssh/staging-shield-key staging-shield@<host> "echo OK"

# Test de sudo permitido sin password
ssh -i ~/.ssh/staging-shield-key staging-shield@<host> "sudo -n cat /etc/sudoers.d/staging-shield"

# Test del scan completo
./staging-shield scan \
  --config examples/config.yaml \
  --ssh-target staging-shield@<host> \
  --ssh-key ~/.ssh/staging-shield-key \
  --ssh-sudo \
  --html-out /tmp/reporte.html
```

Si los tres comandos funcionan, el CI/CD también lo hará.

## Rotación de llaves

Recomendación: rote la llave cada 90 días.

```bash
# 1. Generar nueva llave
ssh-keygen -t ed25519 -N "" -f ~/.ssh/staging-shield-key-new

# 2. Agregar la nueva pública al authorized_keys SIN borrar la antigua
sudo tee -a /home/staging-shield/.ssh/authorized_keys < ~/.ssh/staging-shield-key-new.pub

# 3. Actualizar el secret en el CI/CD con el contenido de staging-shield-key-new

# 4. Una corrida exitosa del CI/CD valida la llave nueva

# 5. Eliminar la llave anterior del authorized_keys
sudo sed -i '/COMENTARIO-DE-LA-LLAVE-VIEJA/d' /home/staging-shield/.ssh/authorized_keys

# 6. Destruir la llave privada vieja
shred -u ~/.ssh/staging-shield-key
```

## Modelo de amenaza considerado

| Amenaza | Mitigación |
|---------|-----------|
| Llave comprometida | Acceso limitado a un usuario con sudo de solo lectura sobre archivos específicos. `from=` en `authorized_keys` cuando posible. Rotación periódica. |
| Comando arbitrario vía sudo | `sudoers` con paths absolutos y argumentos fijos. Ningún comando soportado puede ejecutar shell. |
| Lectura de secretos del repo | El cliente NUNCA envía el contenido del repo al host remoto; el escaneo de secretos corre localmente en el runner del CI. |
| Persistencia del atacante en el host | El usuario no tiene shell útil (algunos despliegues lo restringen a `/usr/bin/rssh` o un wrapper). Sin sudo total ni privilegios sobre cron, systemd, etc. |
| Llave en logs del CI | `secrets.STAGING_SSH_KEY` en GitHub Actions está enmascarado en los logs. El cliente la escribe a un temp file 0600 y nunca la imprime. |
