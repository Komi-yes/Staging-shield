// Package config implementa el Módulo 1 (Entrada) del programa cliente.
// Carga los datos del entorno a evaluar desde un archivo YAML y/o desde
// flags de la línea de comandos, los valida y construye el EvalContext.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/stagingshield/staging-shield/internal/context"
	"gopkg.in/yaml.v3"
)

// FileConfig refleja la estructura del archivo YAML de configuración.
// Se diseñó para que un evaluador pueda describir un entorno sin tocar código.
type FileConfig struct {
	Environment struct {
		Name  string `yaml:"name"`
		Type  string `yaml:"type"`
		Stack string `yaml:"stack"`
	} `yaml:"environment"`

	Target struct {
		Domain string `yaml:"domain"`
		IP     string `yaml:"ip"`
	} `yaml:"target"`

	ExpectedPorts []int `yaml:"expected_ports"`

	Repository struct {
		Path string `yaml:"path"`
	} `yaml:"repository"`

	Production struct {
		// IPs o nombres de host de producción contra los cuales NO debería existir
		// conectividad desde staging. Se prueban TCP a puertos comunes.
		References []string `yaml:"references"`
	} `yaml:"production"`

	AdminInterfaces []string `yaml:"admin_interfaces"`

	// LocalHostScan activa el modo invasivo de verificación local. Solo
	// inspecciona el host donde corre el cliente, NUNCA hosts remotos.
	// Lee paquetes, configuración de SSH, firewall local, permisos de
	// archivos sensibles, etc. Solo tiene sentido activarlo cuando el
	// equipo donde corre el cliente ES el host de staging (típico en
	// despliegues self-hosted o pipelines CI/CD que corren ON el servidor).
	LocalHostScan bool `yaml:"local_host_scan"`

	// SSH activa el modo remoto: los mismos chequeos del modo invasivo
	// pero ejecutados contra un host remoto via SSH. Pensado para CI/CD
	// que corre en otra máquina distinta del servidor de staging.
	// Para configurar la llave privada se prefiere la variable de entorno
	// STAGING_SHIELD_SSH_KEY (contenido de la llave) en vez del YAML, para
	// no commitear secretos al repositorio.
	SSH struct {
		Target  string `yaml:"target"`   // user@host
		Port    int    `yaml:"port"`     // 22 default
		KeyPath string `yaml:"key_path"` // ruta a llave; preferir STAGING_SHIELD_SSH_KEY
		UseSudo bool   `yaml:"use_sudo"` // sudo -n para comandos privilegiados
	} `yaml:"ssh"`

	// Serverless declara que el entorno es serverless / FaaS / managed.
	// Cuando es true, el cliente marca automáticamente como "No aplica"
	// un conjunto fijo de reglas de hardening de host cuya gestión es
	// responsabilidad del proveedor. La lista vive en código y NO es
	// configurable desde aquí — esa decisión pertenece al modelo, no a
	// la configuración del usuario.
	Serverless bool `yaml:"serverless"`
}

// Load lee y valida un archivo YAML, devolviendo un EvalContext listo para
// ser pasado al módulo de descubrimiento.
func Load(path string) (*context.EvalContext, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer archivo de configuración: %w", err)
	}

	var fc FileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("YAML inválido: %w", err)
	}

	return Build(fc)
}

// Build valida una FileConfig y la convierte en EvalContext.
func Build(fc FileConfig) (*context.EvalContext, error) {
	if strings.TrimSpace(fc.Environment.Name) == "" {
		return nil, fmt.Errorf("environment.name es obligatorio")
	}
	if strings.TrimSpace(fc.Target.Domain) == "" && strings.TrimSpace(fc.Target.IP) == "" {
		return nil, fmt.Errorf("debe proporcionar target.domain o target.ip")
	}

	// Normaliza el dominio: acepta con o sin esquema
	domain := strings.TrimSpace(fc.Target.Domain)
	if domain != "" {
		if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
			domain = "https://" + domain
		}
		u, err := url.Parse(domain)
		if err != nil {
			return nil, fmt.Errorf("target.domain inválido: %w", err)
		}
		domain = u.Host
	}

	ip := strings.TrimSpace(fc.Target.IP)
	if ip != "" {
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("target.ip no es una IP válida: %s", ip)
		}
	}

	// Validar puertos esperados
	for _, p := range fc.ExpectedPorts {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("puerto esperado fuera de rango: %d", p)
		}
	}

	// Validar repo path si se proporcionó
	if fc.Repository.Path != "" {
		if info, err := os.Stat(fc.Repository.Path); err != nil {
			return nil, fmt.Errorf("repository.path no existe: %s", fc.Repository.Path)
		} else if !info.IsDir() {
			return nil, fmt.Errorf("repository.path debe ser un directorio: %s", fc.Repository.Path)
		}
	}

	envType := fc.Environment.Type
	if envType == "" {
		envType = "staging"
	}
	stack := fc.Environment.Stack
	if stack == "" {
		stack = "web"
	}

	ec := &context.EvalContext{
		EnvironmentName: fc.Environment.Name,
		EnvironmentType: envType,
		StackType:       stack,
		Timestamp:       time.Now(),
		Target:          domain,
		IPAddress:       ip,
		ExpectedPorts:   fc.ExpectedPorts,
		RepoPath:        fc.Repository.Path,
		ProductionRefs:  fc.Production.References,
		AdminInterfaces: fc.AdminInterfaces,
		LocalHostScan:   fc.LocalHostScan,
		SSHTarget:       fc.SSH.Target,
		SSHPort:         fc.SSH.Port,
		SSHKeyPath:      fc.SSH.KeyPath,
		SSHUseSudo:      fc.SSH.UseSudo,
		Serverless:      fc.Serverless,
	}
	return ec, nil
}

// BuildFromFlags construye un EvalContext directamente desde los flags pasados
// en la línea de comandos. Útil cuando no existe archivo de configuración.
func BuildFromFlags(name, stack, domain, ip string, ports []int, repo string, prodRefs []string) (*context.EvalContext, error) {
	fc := FileConfig{}
	fc.Environment.Name = name
	fc.Environment.Stack = stack
	fc.Environment.Type = "staging"
	fc.Target.Domain = domain
	fc.Target.IP = ip
	fc.ExpectedPorts = ports
	fc.Repository.Path = repo
	fc.Production.References = prodRefs
	return Build(fc)
}
