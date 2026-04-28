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
	case "SVR-HAR-06":
		return validateHar06(rule, ec)
	case "SVR-HAR-09":
		return validateHar09(rule, ec)
	case "SVR-IAM-04":
		return validateIam04(rule, ec)
	case "SVR-IAM-05":
		return validateIam05(rule, ec)
	case "SVR-IAM-07":
		return validateIam07(rule, ec)
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
// Heurística sobre banner SSH si fue capturado.
func validateHar03(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	banner, ok := ec.Discovery.Banners[22]
	if !ok {
		// SSH no detectado en 22, podría estar en otro puerto o cerrado
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "No se detectó SSH en el puerto 22. Si usa un puerto distinto o RDP, verifique manualmente la configuración (PermitRootLogin, PasswordAuthentication, etc.).",
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
		Notes:    "Verifique parámetros: PermitRootLogin no, PasswordAuthentication no si usa llaves, Protocol 2, MaxAuthTries bajo, LoginGraceTime bajo, etc.",
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

// =====================================================================
// Dominio: Identidades, acceso y secretos
// =====================================================================

// SVR-IAM-04: Sin secretos expuestos en código.
func validateIam04(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if ec.RepoPath == "" {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "No se proporcionó 'repository.path'. Para automatizar esta verificación, indique la ruta local del repositorio en la configuración.",
		}
	}
	n := len(ec.Discovery.SecretFindings)
	if n == 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusCumple,
			Evidence: fmt.Sprintf("Búsqueda en %s no encontró patrones de secretos en archivos de configuración, código o manifiestos.", ec.RepoPath),
			Notes:    "La detección por patrones tiene limitaciones; complemente con herramientas como git-secrets, trufflehog o gitleaks para mayor cobertura histórica.",
		}
	}
	hi := 0
	for _, f := range ec.Discovery.SecretFindings {
		if f.Severity == "alto" {
			hi++
		}
	}
	st := ctx.StatusCumpleParcial
	if hi > 0 {
		st = ctx.StatusNoCumple
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   st,
		Evidence: fmt.Sprintf("Se detectaron %d posibles secretos en el repositorio (%d de severidad alta). Ver lista detallada en el reporte HTML/JSON.", n, hi),
		Notes:    "Rote las credenciales detectadas y muévalas a un gestor de secretos. Si son falsos positivos, márquelos en allowlist.",
	}
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
// Heurística: presencia de archivos .env en el repo y/o Postgres URL embebidas.
func validateIam07(rule ctx.SVR, ec *ctx.EvalContext) ctx.RuleResult {
	if ec.RepoPath == "" {
		return ctx.RuleResult{
			Rule:   rule,
			Status: ctx.StatusFaltaEvidencia,
			Notes:  "Sin repository.path no se puede inspeccionar archivos de configuración.",
		}
	}
	envInRepo := false
	urlsEmbedded := 0
	for _, f := range ec.Discovery.SecretFindings {
		if strings.HasSuffix(f.File, ".env") || f.File == ".env" {
			envInRepo = true
		}
		if strings.Contains(f.Pattern, "URL") || f.Pattern == "Password Assignment" {
			urlsEmbedded++
		}
	}
	if envInRepo || urlsEmbedded > 0 {
		return ctx.RuleResult{
			Rule:     rule,
			Status:   ctx.StatusNoCumple,
			Evidence: fmt.Sprintf("Archivos con variables sensibles embebidas: .env en repositorio=%v, URLs/credenciales embebidas=%d.", envInRepo, urlsEmbedded),
			Notes:    "Use un gestor de secretos (Vault, AWS Secrets Manager, Doppler) o variables de entorno inyectadas por el orquestador. Excluya .env del control de versiones.",
		}
	}
	return ctx.RuleResult{
		Rule:     rule,
		Status:   ctx.StatusCumpleParcial,
		Evidence: "No se detectaron archivos .env ni URLs con credenciales embebidas en el repositorio escaneado.",
		Notes:    "Confirme que las variables sensibles se inyectan en tiempo de despliegue desde un mecanismo apropiado.",
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
