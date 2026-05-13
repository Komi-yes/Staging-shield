package rules

import (
	"fmt"

	ctx "github.com/stagingshield/staging-shield/internal/context"
)

// serverlessNotApplicable lista las SVR que el modelo marca automáticamente
// como "No aplica" cuando el entorno declara serverless=true en config.yaml.
//
// La lista es deliberadamente CERRADA y vive en código: la decisión sobre
// qué reglas pierden sentido en serverless es parte del modelo, no de la
// configuración del usuario. Esto previene que un evaluador desactive
// reglas que sí debería evaluar usando el flag como pretexto.
//
// Solo entran reglas cuya verificación es OBJETIVAMENTE responsabilidad
// del proveedor en arquitectura serverless: parchado del SO subyacente,
// firewall local, permisos de filesystem persistente, auditd, /var/log.
// Reglas que SIGUEN siendo responsabilidad del usuario en serverless
// (secretos en código, headers HTTP, identidades, política de denegación
// a nivel de API Gateway/edge, etc.) NUNCA entran aquí.
var serverlessNotApplicable = map[string]string{
	"SVR-HAR-04": "El parchado del sistema operativo subyacente es responsabilidad del proveedor serverless (AWS Lambda, Vercel, Cloudflare Workers, etc.). El equipo de aplicación no gestiona el SO y no tiene acceso al gestor de paquetes del runtime.",
	"SVR-HAR-05": "Las funciones serverless no exponen un firewall local configurable por el usuario. El filtrado de tráfico se da en capas gestionadas por el proveedor (API Gateway, WAF del provider, edge networks).",
	"SVR-HAR-08": "Los entornos serverless no exponen un filesystem persistente cuyos permisos pueda configurar el equipo de aplicación. Archivos como /etc/shadow o claves SSH del host no existen en el modelo de ejecución.",
	"SVR-HAR-09": "Los servicios heredados (FTP, Telnet, SMB, rsh) no son configurables en serverless: el provider expone solo HTTPS y el handler de aplicación. No hay superficie para servicios legacy.",
	"SVR-HAR-10": "La auditoría a nivel de SO (auditd, logs administrativos del host) la gestiona el proveedor serverless. El equipo de aplicación consume los logs de invocación a través del servicio gestionado del provider (CloudWatch, Vercel Logs, etc.), no de auditd.",
	"SVR-MON-01": "La generación de logs de la plataforma es gestionada por el proveedor serverless. Los logs de aplicación se emiten a stdout/stderr y los recoge automáticamente el servicio de logging del provider; no existe /var/log al que apuntar.",
}

// IsNotApplicable decide si una regla debe omitirse del cálculo por
// declaración del modelo de ejecución. Retorna también la justificación
// que se renderiza como evidencia en el reporte.
//
// Esta función NO acepta overrides del usuario por diseño: la lista es
// cerrada y la única forma de evaluar las reglas afectadas es poner
// serverless=false en config.yaml.
func IsNotApplicable(ruleID string, ec *ctx.EvalContext) (bool, string) {
	if !ec.Serverless {
		return false, ""
	}
	reason, ok := serverlessNotApplicable[ruleID]
	if !ok {
		return false, ""
	}
	return true, fmt.Sprintf("[serverless] %s", reason)
}

// IsServerlessNA reporta si una regla está NA específicamente por la
// declaración serverless del entorno. La UI del HTML usa esta función
// para decidir NO renderizar los botones de veredicto (las NA por
// serverless son inmutables desde la UI).
func IsServerlessNA(ruleID string, ec *ctx.EvalContext) bool {
	if !ec.Serverless {
		return false
	}
	_, ok := serverlessNotApplicable[ruleID]
	return ok
}
