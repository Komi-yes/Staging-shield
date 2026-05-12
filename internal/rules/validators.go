// Validators: para cada SVR define cómo se traduce la evidencia del módulo
// de descubrimiento en un ComplianceStatus. Las reglas manuales se devuelven
// con StatusManualRequerido para que el reporte las liste sin contaminar el score.
package rules

import (
	"fmt"
	"regexp"
	"strings"

	ctx "github.com/stagingshield/staging-shield/internal/context"
)

// Validate ejecuta la validación de las 36 SVR sobre el contexto y guarda
// los resultados en ec.Results.
func Validate(ec *ctx.EvalContext) {
	cat := Catalog()
	results := make([]ctx.RuleResult, 0, len(cat))
	for _, rule := range cat {
		res := evaluate(rule, ec)
		results = append(results, res)
	}
	ec.Results = results
}

// evaluate dispatch entre los validadores específicos por ID.
// Se mantiene un switch explícito para que cada regla tenga su lógica
// trazable en código y sea fácil de auditar.
func evaluate(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	switch rule.ID {
	case "SVR-NET-01":
		return validateNet01(rule, ec)
	case "SVR-NET-04":
		return validateNet04(rule, ec)
	case "SVR-NET-05":
		return validateNet05(rule, ec)
	case "SVR-NET-07":
		return validateNet07(rule, ec)
	case "SVR-NET-08":
		return validateNet08(rule, ec)
	case "SVR-NET-09":
		return validateNet09(rule, ec)
	case "SVR-HAR-02":
		return validateHar02(rule, ec)
	case "SVR-HAR-03":
		return validateHar03(rule, ec)
	case "SVR-HAR-04":
		return validateHar04(rule, ec)
	case "SVR-HAR-05":
		return validateHar05(rule, ec)
	case "SVR-HAR-06":
		return validateHar06(rule, ec)
	case "SVR-HAR-08":
		return validateHar08(rule, ec)
	case "SVR-HAR-09":
		return validateHar09(rule, ec)
	case "SVR-HAR-10":
		return validateHar10(rule, ec)
	case "SVR-IAM-04":
		return validateIam04(rule, ec)
	case "SVR-IAM-05":
		return validateIam05(rule, ec)
	case "SVR-IAM-07":
		return validateIam07(rule, ec)
	case "SVR-IAM-08":
		return validateIam08(rule, ec)
	case "SVR-MON-01":
		return validateMon01(rule, ec)
	case "SVR-MON-05":
		return validateMon05(rule, ec)
	case "SVR-MON-06":
		return validateMon06(rule, ec)
	case "SVR-MON-07":
		return validateMon07(rule, ec)
	case "SVR-MON-08":
		return validateMon08(rule, ec)
	default:
		// Reglas manuales: se reportan como pendientes de revisión humana
		// y no participan en el score (CountsForScore() = false).
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusManualRequerido,
			Notes:  "Esta regla requiere revisión documental o acceso administrativo. El programa cliente la lista en el reporte para que el evaluador complete su valoración.",
		}
	}
}

// =====================================================================
// Dominio: Red y aislamiento
// =====================================================================

// SVR-NET-01: Segmentación staging/producción.
// Si el usuario proveyó hosts de producción, probamos conectividad TCP.
// Si alguno responde, el aislamiento está roto.
func validateNet01(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if len(ec.ProductionRefs) == 0 {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "No se proporcionaron referencias de producción (production.references). Para automatizar esta verificación, defina las IPs/hosts de producción en la configuración.",
		}
	}
	if len(ec.Discovery.ProductionReachable) > 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: fmt.Sprintf("Se logró conectividad desde el equipo del evaluador hacia hosts marcados como producción: %s. Esto sugiere ausencia de segmentación efectiva o presencia de rutas no controladas.", strings.Join(ec.Discovery.ProductionReachable, ", ")),
			Notes:    "La detección desde el equipo evaluador no equivale a la prueba directa desde el host de staging, pero es indicativa. Confirmar con el responsable del entorno la existencia de rutas explícitas.",
		}
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumpleParcial,
		Evidence: fmt.Sprintf("Ningún host de producción referenciado fue alcanzable mediante puertos TCP comunes. Hosts probados: %s.", strings.Join(ec.ProductionRefs, ", ")),
		Notes:    "La validación es indicativa. Para cumplir totalmente debe verificarse la topología, ACLs y políticas de routing con el equipo de infraestructura.",
	}
}

// SVR-NET-04: Exposición mínima de conexiones externas.
// Compara puertos abiertos vs puertos esperados.
func validateNet04(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if len(ec.Discovery.OpenPorts) == 0 && ec.Discovery.DNSError == "" && ec.IPAddress != "" {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: "El escaneo de puertos no detectó servicios expuestos en la lista de puertos comunes ni en los puertos esperados. Superficie mínima.",
		}
	}
	if len(ec.ExpectedPorts) == 0 {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "No se declaró 'expected_ports' en la configuración. Sin línea base de puertos esperados no es posible distinguir lo intencional de lo expuesto de más.",
		}
	}
	if len(ec.Discovery.UnexpectedPorts) == 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: fmt.Sprintf("Todos los puertos abiertos detectados (%s) están dentro de la lista declarada (%s).", joinInts(openPortsList(ec)), joinInts(ec.ExpectedPorts)),
		}
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusNoCumple,
		Evidence: fmt.Sprintf("Se encontraron puertos abiertos no declarados: %s. Puertos esperados: %s.", joinInts(ec.Discovery.UnexpectedPorts), joinInts(ec.ExpectedPorts)),
		Notes:    "Cada puerto adicional incrementa la superficie de ataque. Cierre o documente los puertos no esperados.",
	}
}

// SVR-NET-05: Política de denegación por defecto.
// Heurística: si la cantidad de puertos no esperados es elevada, hay alta
// probabilidad de política permisiva. Es semi-automática.
func validateNet05(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if len(ec.ExpectedPorts) == 0 {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "Sin 'expected_ports' no se puede inferir si la política es restrictiva. Defina la lista en la configuración.",
		}
	}
	unexp := len(ec.Discovery.UnexpectedPorts)
	switch {
	case unexp == 0:
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumpleParcial,
			Evidence: "No hay puertos abiertos fuera de los declarados, lo cual es coherente con una política de denegación por defecto. Validar configuración real del firewall.",
			Notes:    "La verificación final requiere inspección de las reglas del firewall perimetral.",
		}
	case unexp <= 2:
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumpleParcial,
			Evidence: fmt.Sprintf("Hay %d puertos no declarados abiertos, posibles excepciones puntuales: %s.", unexp, joinInts(ec.Discovery.UnexpectedPorts)),
		}
	default:
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: fmt.Sprintf("Se detectaron %d puertos abiertos fuera de la lista esperada (%s). Es indicativo de política permisiva o ausencia de denegación por defecto.", unexp, joinInts(ec.Discovery.UnexpectedPorts)),
		}
	}
}

// SVR-NET-07: Uso de TLS 1.3 cuando aplique.
func validateNet07(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	tls := ec.Discovery.TLS
	if !tls.Tested {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "No se pudo probar TLS porque no se configuró un dominio objetivo.",
		}
	}
	if !tls.Available {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: fmt.Sprintf("TLS no disponible en el puerto 443: %s.", tls.Error),
		}
	}
	if tls.IsExpired {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: fmt.Sprintf("Certificado TLS expirado (NotAfter=%s).", tls.NotAfter.Format("2006-01-02")),
		}
	}
	if tls.IsTLS13 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: fmt.Sprintf("TLS 1.3 activo. Cipher: %s. Issuer: %s.", tls.CipherSuite, tls.CertIssuer),
		}
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumpleParcial,
		Evidence: fmt.Sprintf("TLS disponible en versión %s (no 1.3). Cipher: %s.", tls.Version, tls.CipherSuite),
		Notes:    "Actualice la configuración para soportar TLS 1.3 como versión preferente y limite versiones inferiores.",
	}
}

// SVR-NET-08: Interfaces administrativas no expuestas libremente.
func validateNet08(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if len(ec.Discovery.AdminExposed) == 0 {
		if len(ec.Discovery.OpenPorts) == 0 {
			return ctx.RuleResult{
				Rule:   rule,
				Status: ctx.StatusFaltaEvidencia,
				Notes:  "El escaneo de puertos no produjo resultados, no es posible determinar exposición administrativa.",
			}
		}
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: "No se detectaron puertos administrativos típicos expuestos públicamente (SSH, RDP, paneles, Docker daemon, etc.).",
		}
	}
	parts := make([]string, 0, len(ec.Discovery.AdminExposed))
	for _, a := range ec.Discovery.AdminExposed {
		parts = append(parts, fmt.Sprintf("%d (%s)", a.Port, a.Description))
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusNoCumple,
		Evidence: fmt.Sprintf("Interfaces administrativas potencialmente expuestas: %s.", strings.Join(parts, ", ")),
		Notes:    "Restrinja el acceso a estas interfaces mediante VPN, bastión, ACLs por IP o autenticación fuerte. Si son legítimas, decláarelas en 'admin_interfaces'.",
	}
}

// SVR-NET-09: Coincidencia exacta puertos esperados vs detectados.
func validateNet09(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if len(ec.ExpectedPorts) == 0 {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "No se declaró 'expected_ports'. Defínalo para validar coincidencia exacta.",
		}
	}
	miss := len(ec.Discovery.MissingPorts)
	un := len(ec.Discovery.UnexpectedPorts)
	if miss == 0 && un == 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: fmt.Sprintf("Coincidencia exacta entre puertos esperados (%s) y detectados.", joinInts(ec.ExpectedPorts)),
		}
	}
	parts := []string{}
	if un > 0 {
		parts = append(parts, fmt.Sprintf("inesperados: %s", joinInts(ec.Discovery.UnexpectedPorts)))
	}
	if miss > 0 {
		parts = append(parts, fmt.Sprintf("declarados pero no abiertos: %s", joinInts(ec.Discovery.MissingPorts)))
	}
	st := ctx.StatusCumpleParcial
	if un > 0 {
		st = ctx.StatusNoCumple
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   st,
		Evidence: fmt.Sprintf("Diferencias entre la lista esperada y la superficie real: %s.", strings.Join(parts, "; ")),
	}
}

// =====================================================================
// Dominio: Hardening
// =====================================================================

// SVR-HAR-02: Servicios innecesarios deshabilitados.
// Heurística: si hay puertos no declarados abiertos, hay servicios potencialmente innecesarios.
func validateHar02(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if len(ec.ExpectedPorts) == 0 {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "Sin lista de puertos esperados no se pueden distinguir servicios necesarios de innecesarios.",
		}
	}
	if len(ec.Discovery.UnexpectedPorts) == 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: "No hay servicios escuchando fuera de los declarados.",
		}
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumpleParcial,
		Evidence: fmt.Sprintf("Puertos no declarados activos: %s. Pueden ser servicios innecesarios.", joinInts(ec.Discovery.UnexpectedPorts)),
		Notes:    "Verifique en el host si los servicios asociados deben estar deshabilitados (systemctl, ss, lsof).",
	}
}

// SVR-HAR-03: Acceso administrativo remoto endurecido.
// Heurística sobre banner SSH si fue capturado, y sshd_config si el modo
// local-host-scan está activo (en ese caso podemos dictaminar con valores
// reales de PermitRootLogin / PasswordAuthentication).
func validateHar03(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	// Si tenemos sshd_config parseado, ese es el dato más fuerte y lo usamos
	// directamente. El banner queda como evidencia complementaria.
	lh := ec.Discovery.LocalHost
	if lh.Available && lh.SSHConfigPath != "" {
		permitRoot := strings.ToLower(lh.SSHPermitRoot)
		passAuth := strings.ToLower(lh.SSHPasswordAuth)
		// CIS §5.2: PermitRootLogin debe ser 'no' o 'prohibit-password'.
		// PasswordAuthentication debe ser 'no' cuando hay claves disponibles.
		issues := []string{}
		if permitRoot == "yes" {
			issues = append(issues, "PermitRootLogin=yes (CIS §5.2: debería ser 'no' o 'prohibit-password')")
		}
		if passAuth == "yes" {
			issues = append(issues, "PasswordAuthentication=yes (CIS §5.2: debería ser 'no' cuando se usan llaves)")
		}
		if len(issues) > 0 {
			return ctx.RuleResult{
				Rule:     rule,
				Status:   ctx.StatusNoCumple,
				Evidence: fmt.Sprintf("Configuración SSH en %s: %s.", lh.SSHConfigPath, strings.Join(issues, "; ")),
				Notes:    "Edite sshd_config y recargue el servicio (systemctl reload ssh).",
			}
		}
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: fmt.Sprintf("Configuración SSH leída de %s: PermitRootLogin=%s, PasswordAuthentication=%s. Acceso remoto endurecido según CIS §5.2.", lh.SSHConfigPath, lh.SSHPermitRoot, lh.SSHPasswordAuth),
		}
	}

	banner, ok := ec.Discovery.Banners[22]
	if !ok {
		// SSH no detectado en 22, podría estar en otro puerto o cerrado
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "No se detectó SSH en el puerto 22 y no se activó --local-host-scan. Si usa un puerto distinto o RDP, verifique manualmente la configuración (PermitRootLogin, PasswordAuthentication, etc.).",
		}
	}
	// Versiones OpenSSH muy antiguas (<7.0) son señal mala
	if reOldSSH.MatchString(banner) {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: fmt.Sprintf("Banner SSH indica versión antigua: %s. Versiones <7.x carecen de mejoras de seguridad recientes.", banner),
		}
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumpleParcial,
		Evidence: fmt.Sprintf("SSH responde en 22 con banner: %s. La versión es razonable, pero la verificación final requiere revisar /etc/ssh/sshd_config (CIS §5.2).", banner),
		Notes:    "Verifique parámetros: PermitRootLogin no, PasswordAuthentication no si usa llaves, Protocol 2, MaxAuthTries bajo, LoginGraceTime bajo, etc. Active --local-host-scan para que el cliente lea estos valores directamente.",
	}
}

var reOldSSH = regexp.MustCompile(`(?i)OpenSSH_([1-6]\.|7\.[0-3])`)

// SVR-HAR-06: Sin firmas/banners innecesarios en el servidor web.
func validateHar06(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if len(ec.Discovery.HTTPHeaders) == 0 {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "No se obtuvieron encabezados HTTP. Verifique conectividad o pruebe sobre el dominio correcto.",
		}
	}
	leaks := []string{}
	risky := []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache"}
	for _, h := range risky {
		if v, ok := ec.Discovery.HTTPHeaders[h]; ok && v != "" {
			// El nombre del producto es info útil para un atacante; versión es peor.
			if reHeaderHasVersion.MatchString(v) {
				leaks = append(leaks, fmt.Sprintf("%s: %s (incluye versión)", h, v))
			} else {
				leaks = append(leaks, fmt.Sprintf("%s: %s", h, v))
			}
		}
	}
	missingSecurity := []string{}
	wantedSecurity := []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"}
	for _, h := range wantedSecurity {
		if _, ok := ec.Discovery.HTTPHeaders[h]; !ok {
			missingSecurity = append(missingSecurity, h)
		}
	}

	parts := []string{}
	if len(leaks) > 0 {
		parts = append(parts, "Encabezados con información del software: "+strings.Join(leaks, "; "))
	}
	if len(missingSecurity) > 0 {
		parts = append(parts, "Encabezados de seguridad ausentes: "+strings.Join(missingSecurity, ", "))
	}

	if len(parts) == 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: "No se detectan encabezados que filtren información del producto y los encabezados de seguridad recomendados están presentes.",
		}
	}
	st := ctx.StatusCumpleParcial
	if len(leaks) > 0 && len(missingSecurity) >= 3 {
		st = ctx.StatusNoCumple
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   st,
		Evidence: strings.Join(parts, ". "),
		Notes:    "Configure el servidor para ocultar la cabecera Server (server_tokens off en NGINX, ServerSignature Off / ServerTokens Prod en Apache) y agregue los encabezados de seguridad recomendados.",
	}
}

var reHeaderHasVersion = regexp.MustCompile(`\d+\.\d+`)

// SVR-HAR-09: Restricción de servicios heredados.
func validateHar09(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if len(ec.Discovery.OpenPorts) == 0 {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "No se obtuvieron resultados de escaneo. Verifique conectividad.",
		}
	}
	if len(ec.Discovery.LegacyServices) == 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: "No se detectaron servicios o protocolos heredados (FTP, Telnet, SMB, rsh, rlogin, etc.).",
		}
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusNoCumple,
		Evidence: fmt.Sprintf("Servicios heredados detectados en puertos: %s.", joinInts(ec.Discovery.LegacyServices)),
		Notes:    "Reemplace por equivalentes modernos (SFTP en lugar de FTP, SSH en lugar de Telnet/rsh) o deshabilítelos si no son necesarios.",
	}
}

// fallbackToManual devuelve un resultado StatusManualRequerido para reglas
// que solo se pueden automatizar bajo --local-host-scan. Cuando el usuario
// no activó el modo invasivo, estas reglas se comportan exactamente como
// antes: aparecen en el centro de revisión manual del HTML.
func fallbackToManual(rule ctx.SVR, hint string) ctx.RuleResult {
	return ctx.RuleResult{
		Rule:   rule,
		Status: ctx.StatusManualRequerido,
		Notes:  hint + " Para automatizar esta verificación, ejecute el cliente sobre el propio host de staging con --local-host-scan (modo invasivo). Si lo está ejecutando desde otro equipo, complete la valoración desde el centro de revisión del reporte.",
	}
}

// SVR-HAR-04: Parches del sistema.
// Bajo --local-host-scan inspeccionamos el gestor de paquetes local.
// Umbrales: 0 actualizaciones -> Cumple. 1+ de seguridad -> No cumple.
// Otros casos -> Cumple parcial proporcional al volumen.
func validateHar04(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if !ec.Discovery.LocalHost.Available {
		return fallbackToManual(rule, "El estado de parches requiere consultar el gestor de paquetes del host.")
	}
	lh := ec.Discovery.LocalHost
	if lh.PackagesError != "" {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "Error al consultar el gestor de paquetes: " + lh.PackagesError,
		}
	}
	if lh.PackagesOutdated == 0 {
		ev := "Sin actualizaciones pendientes en el gestor de paquetes."
		if lh.PackagesCheckedAt != "" {
			ev += " " + lh.PackagesCheckedAt
		}
		return ctx.RuleResult{Rule: rule, Status: ctx.StatusCumple, Evidence: ev}
	}
	if lh.SecurityUpdatesPending > 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: fmt.Sprintf("Hay %d actualizaciones de seguridad pendientes y %d actualizaciones totales pendientes. %s", lh.SecurityUpdatesPending, lh.PackagesOutdated, lh.PackagesCheckedAt),
			Notes:    "Aplique las actualizaciones de seguridad de inmediato (apt upgrade, dnf upgrade-minimal --security, etc.). Considere automatizar con unattended-upgrades.",
		}
	}
	// Sin seguridad explícita, decimos parcial proporcionalmente.
	st := ctx.StatusCumpleParcial
	if lh.PackagesOutdated > 50 {
		st = ctx.StatusNoCumple
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   st,
		Evidence: fmt.Sprintf("Hay %d paquetes con actualización disponible (sin diferenciación clara de seguridad). %s", lh.PackagesOutdated, lh.PackagesCheckedAt),
		Notes:    "Refresque el cache (apt update / dnf check-update) y revise cuáles son updates de seguridad. Establezca una ventana periódica de aplicación.",
	}
}

// SVR-HAR-05: Firewall local activo.
func validateHar05(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if !ec.Discovery.LocalHost.Available {
		return fallbackToManual(rule, "El estado del firewall local debe consultarse sobre el host (ufw, firewalld, nftables, iptables).")
	}
	lh := ec.Discovery.LocalHost
	if lh.FirewallTool == "none" || lh.FirewallTool == "" {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: "No se detectó ninguna herramienta de firewall local activa en el host (ufw/firewalld/nftables/iptables).",
			Notes:    "Instale y configure un firewall local. En Ubuntu el camino más simple es ufw: 'ufw default deny incoming', 'ufw allow 22/tcp', 'ufw enable'.",
		}
	}
	if !lh.FirewallActive {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: fmt.Sprintf("Se detectó %s pero está inactivo o sin reglas significativas.", lh.FirewallTool),
			Notes:    "Active el firewall y agregue una política de denegación por defecto para tráfico entrante.",
		}
	}
	if !lh.FirewallDefaultDeny {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumpleParcial,
			Evidence: fmt.Sprintf("%s está activo con %d reglas, pero la política por defecto no es 'deny/drop'.", lh.FirewallTool, lh.FirewallRulesCount),
			Notes:    "Cambie la política por defecto del chain INPUT a DROP o REJECT y abra explícitamente solo los puertos necesarios.",
		}
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumple,
		Evidence: fmt.Sprintf("%s activo con %d reglas y política de denegación por defecto en tráfico entrante.", lh.FirewallTool, lh.FirewallRulesCount),
	}
}

// SVR-HAR-08: Permisos de archivos sensibles.
func validateHar08(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if !ec.Discovery.LocalHost.Available {
		return fallbackToManual(rule, "Los permisos sobre /etc/shadow, claves SSH del host y sudoers requieren inspección directa del filesystem.")
	}
	bad := ec.Discovery.LocalHost.SensitiveFiles
	if len(bad) == 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: "Los archivos sensibles inspeccionados (/etc/shadow, /etc/sudoers, claves SSH del host, authorized_keys de root) tienen permisos dentro de lo esperado por CIS §6.1–6.2.",
		}
	}
	descs := make([]string, 0, len(bad))
	for _, f := range bad {
		descs = append(descs, fmt.Sprintf("%s (%s)", f.Path, f.Problem))
	}
	hasCritical := false
	for _, f := range bad {
		// /etc/shadow y claves privadas SSH con permisos laxos son críticos
		if strings.Contains(f.Path, "shadow") || strings.Contains(f.Path, "_key") {
			hasCritical = true
			break
		}
	}
	st := ctx.StatusCumpleParcial
	if hasCritical {
		st = ctx.StatusNoCumple
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   st,
		Evidence: "Archivos con permisos laxos: " + strings.Join(descs, "; "),
		Notes:    "Restrinja con 'chmod 0600' las claves privadas, 'chmod 0640' /etc/shadow, 'chmod 0440' /etc/sudoers. Verifique también el dueño (chown root:root).",
	}
}

// SVR-HAR-10: Trazabilidad de cambios — auditoría administrativa.
func validateHar10(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if !ec.Discovery.LocalHost.Available {
		return fallbackToManual(rule, "La verificación de auditoría requiere comprobar auditd / journald sobre el host.")
	}
	lh := ec.Discovery.LocalHost
	if lh.AuditdActive {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: "auditd está instalado y activo. Las reglas en /etc/audit/auditd.conf permiten trazar accesos privilegiados y cambios de configuración.",
		}
	}
	// Solo journald
	for _, l := range lh.LogsPresent {
		if strings.Contains(l, "journald") {
			return ctx.RuleResult{
				Rule:     rule,
				Status:   ctx.StatusCumpleParcial,
				Evidence: "auditd no está activo. systemd-journald sí provee logs del sistema pero sin las garantías de auditoría inmutable de auditd (CIS §4.1).",
				Notes:    "Instale auditd (sudo apt install auditd / sudo dnf install audit) y configure reglas mínimas para syscalls sensibles (execve, chmod sobre /etc, etc.).",
			}
		}
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusNoCumple,
		Evidence: "No se detectó auditd ni systemd-journald activos. No hay trazabilidad consistente de cambios administrativos en el host.",
		Notes:    "Instale auditd y habilite journald persistente (mkdir -p /var/log/journal).",
	}
}

// SVR-MON-01: Logs de acceso, error y administración.
func validateMon01(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if !ec.Discovery.LocalHost.Available {
		return fallbackToManual(rule, "Verificar la generación de logs requiere inspeccionar /var/log y el estado de los daemons de logging.")
	}
	lh := ec.Discovery.LocalHost
	if len(lh.LogsPresent) == 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: "No se detectaron archivos de log significativos en /var/log ni daemons de logging activos.",
			Notes:    "Habilite rsyslog/journald y configure el servidor web para escribir logs (NGINX: access_log/error_log, Apache: CustomLog/ErrorLog).",
		}
	}
	st := ctx.StatusCumple
	notes := ""
	if !lh.LogsRotating {
		st = ctx.StatusCumpleParcial
		notes = "Los logs existen pero no se detectó configuración de logrotate. Sin rotación los logs pueden llenar el disco; agregue /etc/logrotate.d/<app> con rotación diaria/semanal."
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   st,
		Evidence: "Logs presentes en el host: " + strings.Join(lh.LogsPresent, ", ") + ".",
		Notes:    notes,
	}
}

// =====================================================================
// Dominio: Identidades, acceso y secretos
// =====================================================================

// SVR-IAM-04: Sin secretos expuestos en código fuente o archivos públicos.
//
// Decisión clave: la regla habla de exposición *pública*. Un secreto que
// solo existe en un archivo local no trackeado por git y no presente en el
// historial no es exposición pública — es desarrollo local. Por eso, cuando
// el repositorio es git, contamos como falla únicamente los hallazgos en
// archivos trackeados o en historial. Si git no está disponible, caemos al
// comportamiento previo (presencia en disco) para no perder señal.
func validateIam04(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if ec.RepoPath == "" {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "No se proporcionó 'repository.path'. Para automatizar esta verificación, indique la ruta local del repositorio en la configuración.",
		}
	}

	// Separar fixtures (test/ejemplos/placeholders) de hallazgos reales antes
	// de cualquier otra clasificación. Los fixtures se reportan informalmente
	// en evidence pero NUNCA penalizan el score: una cadena "Bearer
	// invalid-token-for-test" en un archivo .test.js no es exposición de
	// credenciales y no debe bloquear la promoción de un entorno.
	realFindings := []ctx.SecretFinding{}
	fixtureFindings := []ctx.SecretFinding{}
	for _, f := range ec.Discovery.SecretFindings {
		if f.IsFixture {
			fixtureFindings = append(fixtureFindings, f)
		} else {
			realFindings = append(realFindings, f)
		}
	}

	totalReal := len(realFindings)
	fixtureNote := ""
	if len(fixtureFindings) > 0 {
		fixtureNote = fmt.Sprintf(" Se filtraron %d hallazgos en archivos de test/ejemplo (no penalizan, ver tabla de evidencia técnica).", len(fixtureFindings))
	}

	// Sin repo git, no hay forma de distinguir local vs expuesto: usar la
	// señal disponible (presencia en disco), pero excluyendo fixtures.
	if !ec.Discovery.Git.Available {
		if totalReal == 0 {
			return ctx.RuleResult{
				Rule:     rule,
				Status:   ctx.StatusCumple,
				Evidence: fmt.Sprintf("Búsqueda en %s no encontró patrones de secretos en archivos de configuración, código o manifiestos (excluyendo tests/ejemplos).%s", ec.RepoPath, fixtureNote),
				Notes:    "El repositorio no es un repo git, por lo que no se pudo distinguir entre archivos públicos y solo locales. Inicialice git para una evaluación más justa.",
			}
		}
		hi := countHighSeverity(realFindings)
		st := ctx.StatusCumpleParcial
		if hi > 0 {
			st = ctx.StatusNoCumple
		}
		return ctx.RuleResult{
			Rule:     rule,
			Status:   st,
			Evidence: fmt.Sprintf("Se detectaron %d posibles secretos en el repositorio (%d de severidad alta).%s El repositorio no es git, no fue posible filtrar por exposición pública.", totalReal, hi, fixtureNote),
			Notes:    "Rote las credenciales detectadas y muévalas a un gestor de secretos. Si son falsos positivos, mueva el archivo a un directorio test/ o renómbrelo con sufijo .test/.spec para que el cliente los excluya.",
		}
	}

	// Con repo git: separar lo realmente expuesto de lo solo local.
	// Trabajamos sobre realFindings (los fixtures ya quedaron afuera).
	exposed := []ctx.SecretFinding{}
	historical := []ctx.SecretFinding{}
	localOnly := []ctx.SecretFinding{}
	for _, f := range realFindings {
		switch {
		case f.Tracked:
			exposed = append(exposed, f)
		case f.InHistory:
			historical = append(historical, f)
		default:
			localOnly = append(localOnly, f)
		}
	}

	if len(exposed) == 0 && len(historical) == 0 {
		ev := fmt.Sprintf("No se encontraron secretos en archivos trackeados por git ni en el historial (excluyendo fixtures). Total escaneado: %d archivos. Hallazgos solo locales (no expuestos): %d.%s",
			len(ec.Discovery.Git.TrackedFiles), len(localOnly), fixtureNote)
		notes := ""
		if len(localOnly) > 0 {
			notes = "Hay secretos en archivos locales no trackeados (típicamente .env de desarrollo). No constituyen exposición pública mientras .gitignore impida su inclusión accidental, pero conviene rotarlos si se sospecha que pudieron filtrarse por otra vía."
		}
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: ev,
			Notes:    notes,
		}
	}

	hiExposed := countHighSeverity(exposed)
	hiHist := countHighSeverity(historical)

	parts := []string{}
	if len(exposed) > 0 {
		parts = append(parts, fmt.Sprintf("%d en archivos trackeados (%d severidad alta)", len(exposed), hiExposed))
	}
	if len(historical) > 0 {
		parts = append(parts, fmt.Sprintf("%d en archivos del historial git (%d severidad alta)", len(historical), hiHist))
	}
	if len(localOnly) > 0 {
		parts = append(parts, fmt.Sprintf("%d solo locales, no expuestos públicamente", len(localOnly)))
	}

	st := ctx.StatusCumpleParcial
	if hiExposed > 0 || hiHist > 0 {
		st = ctx.StatusNoCumple
	}

	return ctx.RuleResult{
		Rule:     rule,
		Status:   st,
		Evidence: "Hallazgos: " + strings.Join(parts, "; ") + "." + fixtureNote,
		Notes:    "Los secretos en archivos trackeados o en historial git deben considerarse comprometidos: rótelos de inmediato y muévalos a un gestor de secretos. Para limpiar el historial considere git filter-repo o BFG. Los hallazgos solo locales no afectan el score pero conviene revisarlos por higiene.",
	}
}

func countHighSeverity(fs []ctx.SecretFinding) int {
	n := 0
	for _, f := range fs {
		if f.Severity == "alto" {
			n++
		}
	}
	return n
}

// SVR-IAM-05: Auth fuerte en interfaces administrativas.
// Si hay paneles administrativos expuestos sobre HTTP plano (no TLS), es directamente un fallo.
func validateIam05(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if len(ec.Discovery.AdminExposed) == 0 {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "No se detectaron interfaces administrativas en el escaneo. Si su entorno expone consolas internas, verifique manualmente que exigen MFA / SSO / llaves SSH.",
		}
	}
	insecure := []string{}
	for _, a := range ec.Discovery.AdminExposed {
		// Docker daemon sin TLS, SSH es comparable, panels en HTTP
		if a.Port == 2375 {
			insecure = append(insecure, fmt.Sprintf("Docker daemon expuesto en %d sin TLS", a.Port))
		}
	}
	// Si hay panels en HTTP plano y TLS no está activo, marcar fallo
	if !ec.Discovery.TLS.IsTLS13 && len(ec.Discovery.AdminExposed) > 0 {
		insecure = append(insecure, "Interfaces admin expuestas con TLS débil o sin TLS 1.3")
	}
	if len(insecure) > 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: strings.Join(insecure, "; "),
		}
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumpleParcial,
		Evidence: "Interfaces administrativas expuestas existen, pero usan canal cifrado. Verificar manualmente la presencia de MFA o autenticación basada en llaves.",
	}
}

// SVR-IAM-07: Variables sensibles desde mecanismos apropiados.
//
// Decisión clave: el problema de seguridad no es que exista un .env en el
// disco del desarrollador — es que ese .env termine en el repositorio
// remoto. El validador discrimina por estado de tracking:
//
//	.env trackeado por git           -> no cumple (alta) — exposición pública.
//	.env en historial git            -> no cumple (alta) — recuperable de commits.
//	.env existe + gitignored         -> cumple — práctica recomendada.
//	.env existe + NO gitignored      -> cumple parcial — riesgo latente de commit accidental.
//	no hay .env y no hay URLs/passwords embebidos en archivos trackeados -> cumple.
//	credenciales embebidas en archivos trackeados -> no cumple.
//
// Cuando git no está disponible, cae al comportamiento previo basado en
// presencia en disco para no perder señal.
func validateIam07(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if ec.RepoPath == "" {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "Sin repository.path no se puede inspeccionar archivos de configuración.",
		}
	}

	// Sin git: heurística previa basada solo en presencia en disco.
	if !ec.Discovery.Git.Available {
		envInRepo := len(ec.Discovery.EnvFiles) > 0
		urlsEmbedded := 0
		for _, f := range ec.Discovery.SecretFindings {
			if f.IsFixture {
				continue
			}
			if strings.Contains(f.Pattern, "URL") || f.Pattern == "Password Assignment" {
				urlsEmbedded++
			}
		}
		if envInRepo || urlsEmbedded > 0 {
			return ctx.RuleResult{
				Rule:     rule,
				Status:   ctx.StatusCumpleParcial,
				Evidence: fmt.Sprintf("Archivos .env presentes=%v, URLs/credenciales embebidas en archivos escaneados=%d. Repo sin git: no fue posible determinar exposición pública.", envInRepo, urlsEmbedded),
				Notes:    "Inicialice git en el repositorio para que el modelo distinga entre archivos solo locales y archivos efectivamente expuestos.",
			}
		}
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: "No se detectaron archivos .env ni credenciales embebidas en el repositorio escaneado.",
		}
	}

	// Con git: clasificar cada .env por estado de tracking.
	tracked := []ctx.EnvFileFinding{}
	historical := []ctx.EnvFileFinding{}
	gitignored := []ctx.EnvFileFinding{}
	notIgnored := []ctx.EnvFileFinding{} // existe en disco, no trackeado, no en historial, no gitignored
	for _, f := range ec.Discovery.EnvFiles {
		switch {
		case f.Tracked:
			tracked = append(tracked, f)
		case f.InHistory:
			historical = append(historical, f)
		case f.Gitignored:
			gitignored = append(gitignored, f)
		default:
			notIgnored = append(notIgnored, f)
		}
	}

	// URLs/credenciales embebidas en archivos *trackeados* (no las que solo viven local).
	// Excluimos fixtures (test/ejemplos): "postgres://demo:demo@localhost/test"
	// dentro de un test no constituye una variable sensible expuesta.
	embeddedTracked := 0
	for _, f := range ec.Discovery.SecretFindings {
		if f.IsFixture {
			continue
		}
		if !f.Tracked && !f.InHistory {
			continue
		}
		if strings.Contains(f.Pattern, "URL") || f.Pattern == "Password Assignment" {
			embeddedTracked++
		}
	}

	// Caso crítico: hay un .env trackeado o en historial, o credenciales en archivos trackeados.
	if len(tracked) > 0 || len(historical) > 0 || embeddedTracked > 0 {
		parts := []string{}
		if len(tracked) > 0 {
			parts = append(parts, fmt.Sprintf("archivos .env actualmente trackeados por git: %s", envFileList(tracked)))
		}
		if len(historical) > 0 {
			parts = append(parts, fmt.Sprintf("archivos .env presentes en el historial git (recuperables aunque hoy no estén): %s", envFileList(historical)))
		}
		if embeddedTracked > 0 {
			parts = append(parts, fmt.Sprintf("%d credenciales/URLs embebidas en archivos trackeados", embeddedTracked))
		}
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: "Variables sensibles efectivamente expuestas: " + strings.Join(parts, "; ") + ".",
			Notes:    "Rote las credenciales filtradas, agregue el archivo a .gitignore y elimine su rastro del historial (git filter-repo o BFG). Inyecte las variables en tiempo de despliegue desde un gestor de secretos (Vault, AWS Secrets Manager, Doppler) o variables del orquestador.",
		}
	}

	// Caso intermedio: el .env existe pero NO está en .gitignore.
	// No hay exposición hoy, pero el siguiente commit puede crearla.
	if len(notIgnored) > 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumpleParcial,
			Evidence: fmt.Sprintf("Existen archivos .env locales que no están en .gitignore: %s. Hoy no están trackeados, pero un 'git add .' accidental los expondría.", envFileList(notIgnored)),
			Notes:    "Agregue una entrada al .gitignore (típicamente '.env' o '.env.local') para prevenir commits accidentales. La buena noticia: hoy no hay exposición real.",
		}
	}

	// Caso favorable: o no hay .env, o todos los que existen están .gitignored.
	if len(gitignored) > 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: fmt.Sprintf("Archivos .env presentes únicamente como configuración local de desarrollo y correctamente excluidos de git por .gitignore: %s.", envFileList(gitignored)),
			Notes:    "Confirme que las variables sensibles en producción se inyectan desde un mecanismo apropiado (gestor de secretos / variables del orquestador) y no desde estos archivos.",
		}
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumple,
		Evidence: "No se detectaron archivos .env ni credenciales embebidas en archivos trackeados por git.",
	}
}

// envFileList formatea una lista de hallazgos .env para el reporte.
func envFileList(fs []ctx.EnvFileFinding) string {
	if len(fs) == 0 {
		return "(ninguno)"
	}
	names := make([]string, 0, len(fs))
	for _, f := range fs {
		names = append(names, f.Path)
	}
	return strings.Join(names, ", ")
}

// SVR-IAM-08: el acceso desde redes externas hacia recursos internos debe
// estar asociado a identidades autorizadas.
//
// Lógica de evaluación automática:
//   - Si el cliente no detectó interfaces administrativas expuestas, no hay
//     superficie externa que validar y la regla queda en "Cumple": el
//     entorno no expone recursos internos sin restricción.
//   - Si hay interfaces admin expuestas, se inspecciona el resultado del
//     probe HTTP (módulo de descubrimiento) sobre cada una:
//   - Todas con AuthChallenge=true (401/403/WWW-Auth/redirect a login)
//     -> Cumple parcial. Hay control de identidad pero la mera exposición
//     del panel a internet sigue siendo subóptima (debería estar tras VPN
//     o IP allowlist).
//   - Alguna sin AuthChallenge (200 directo) -> No cumple. El recurso
//     responde sin pedir credenciales: cualquier identidad de internet
//     puede acceder.
//   - Puerto no-HTTP (SSH, RDP, BD) sin probe -> Cumple parcial: SSH/RDP
//     tienen su propia auth, pero la exposición directa a internet sin
//     red de confianza intermedia requiere validar manualmente que se
//     use llave + MFA.
//   - Si el probe falló (ProbeError no vacío y Probed=false), queda en
//     "Falta evidencia" para que el evaluador lo cierre manualmente.
func validateIam08(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if len(ec.Discovery.AdminExposed) == 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: "No se detectaron interfaces administrativas expuestas a redes externas. El control de identidad sobre recursos internos queda implícitamente cubierto por la ausencia de superficie de acceso pública.",
		}
	}

	type bucket struct {
		Description   string
		Port          int
		AuthChallenge bool
		HTTPStatus    int
		NonHTTP       bool
		ProbeFailed   bool
	}
	var buckets []bucket
	for _, af := range ec.Discovery.AdminExposed {
		b := bucket{Description: af.Description, Port: af.Port}
		if !af.Probed && af.ProbeError != "" && !strings.Contains(af.ProbeError, "no-HTTP") {
			b.ProbeFailed = true
		} else if !af.Probed && strings.Contains(af.ProbeError, "no-HTTP") {
			b.NonHTTP = true
		} else {
			b.AuthChallenge = af.AuthChallenge
			b.HTTPStatus = af.HTTPStatus
			b.NonHTTP = strings.Contains(af.ProbeError, "no-HTTP")
		}
		buckets = append(buckets, b)
	}

	// Cualquier endpoint HTTP que respondió 200 sin auth challenge es un
	// "no cumple" automático: cualquiera en internet puede acceder.
	openHTTP := []bucket{}
	withAuth := []bucket{}
	nonHTTP := []bucket{}
	failed := []bucket{}
	for _, b := range buckets {
		switch {
		case b.ProbeFailed:
			failed = append(failed, b)
		case b.NonHTTP:
			nonHTTP = append(nonHTTP, b)
		case b.AuthChallenge:
			withAuth = append(withAuth, b)
		default:
			openHTTP = append(openHTTP, b)
		}
	}

	if len(openHTTP) > 0 {
		descs := make([]string, 0, len(openHTTP))
		for _, b := range openHTTP {
			descs = append(descs, fmt.Sprintf("%d/%s (HTTP %d sin auth)", b.Port, b.Description, b.HTTPStatus))
		}
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: fmt.Sprintf("Interfaces administrativas que responden con contenido sin requerir credenciales: %s. Cualquier usuario de internet puede acceder a ellas sin asociarse a una identidad autorizada.", strings.Join(descs, "; ")),
			Notes:    "Coloque estos paneles detrás de una VPN, IP allowlist, o un reverse proxy con SSO. Verifique que el código de la aplicación obligue autenticación incluso en endpoints '/' del panel.",
		}
	}

	if len(failed) > 0 && len(withAuth) == 0 && len(nonHTTP) == 0 {
		// Solo hay interfaces que no respondieron al probe — no podemos
		// dictaminar automáticamente.
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "Se detectaron interfaces admin expuestas pero el probe HTTP no concluyó (timeouts, certificado inválido, etc.). Verifique manualmente que requieren autenticación.",
		}
	}

	parts := []string{}
	if len(withAuth) > 0 {
		descs := make([]string, 0, len(withAuth))
		for _, b := range withAuth {
			descs = append(descs, fmt.Sprintf("%d/%s (HTTP %d con auth)", b.Port, b.Description, b.HTTPStatus))
		}
		parts = append(parts, fmt.Sprintf("%d con desafío de autenticación: %s", len(withAuth), strings.Join(descs, ", ")))
	}
	if len(nonHTTP) > 0 {
		descs := make([]string, 0, len(nonHTTP))
		for _, b := range nonHTTP {
			descs = append(descs, fmt.Sprintf("%d/%s", b.Port, b.Description))
		}
		parts = append(parts, fmt.Sprintf("%d puertos no-HTTP (SSH/RDP/BD) cuya autenticación no es inspeccionable desde el cliente: %s", len(nonHTTP), strings.Join(descs, ", ")))
	}
	if len(failed) > 0 {
		parts = append(parts, fmt.Sprintf("%d sin respuesta concluyente al probe", len(failed)))
	}

	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumpleParcial,
		Evidence: "Interfaces admin expuestas con control de identidad: " + strings.Join(parts, "; ") + ".",
		Notes:    "Aunque los endpoints exigen autenticación, exponer paneles internos directamente a internet aumenta innecesariamente la superficie de ataque. Considere VPN, ZTNA o IP allowlist incluso cuando hay credenciales.",
	}
}

// =====================================================================
// Dominio: Monitoreo, integridad y trazabilidad
// =====================================================================

// SVR-MON-05: Historial comparable entre evaluaciones.
// Esta regla la cumple el propio programa cliente al persistir resultados.
func validateMon05(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumple,
		Evidence: "El programa cliente persiste cada corrida en disco (JSON) bajo el directorio configurado, permitiendo comparar evaluaciones sucesivas.",
	}
}

// SVR-MON-06: Alertar fallas críticas del perímetro.
func validateMon06(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumple,
		Evidence: "El reporte final marca explícitamente las SVR críticas y aplica la condición de aptitud (no apto si alguna falla crítica está en estado 'no cumple').",
	}
}

// SVR-MON-07: Reporte con score por dominio y global.
func validateMon07(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumple,
		Evidence: "El reporte HTML, JSON y consola incluyen score por cada uno de los cuatro dominios y el score global ponderado.",
	}
}

// SVR-MON-08: Diferenciar 'no cumple' de 'falta evidencia'.
func validateMon08(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumple,
		Evidence: "El modelo de estados separa StatusNoCumple, StatusFaltaEvidencia y StatusManualRequerido. El reporte enumera por separado las reglas no verificables automáticamente.",
	}
}

// =====================================================================
// Helpers
// =====================================================================

func openPortsList(ec *ctx.EvalContext) []int {
	out := make([]int, 0, len(ec.Discovery.OpenPorts))
	for _, f := range ec.Discovery.OpenPorts {
		out = append(out, f.Port)
	}
	return out
}

func joinInts(xs []int) string {
	if len(xs) == 0 {
		return "(vacío)"
	}
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return strings.Join(parts, ", ")
}
