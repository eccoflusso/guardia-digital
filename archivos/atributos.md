**Atributo			Mercado Tradicional (SaaS Ley 20.393)		Guardia Digital Inteligente**

Naturaleza del Control		Pasivo/Administrativo (Matrices, Políticas).	Activo/Técnico (Bloqueo y re-autenticación).

Generación de Evidencia		Manual (Humanos suben documentos/logs).		Automatizada (Log Streams Auth0 → Datadog).

Prevención de Fraude		Depende del canal de denuncias.			Algorítmica (IA detecta viaje imposible/anomalías).

Adopción Mid-Market		Alta (Bajo costo, fácil de usar).		Alta (Arquitectura Serverless elimina costos de infraestructura IAM enterprise).



1\. Inmutabilidad de Logs (Estándar Probatorio)

Para que los eventos de acceso sirvan como evidencia en un juicio penal corporativo o ante la fiscalía, los logs no pueden ser alterables.

•Requisito: Asegúrate de que los logs enviados desde Auth0 vía tu API Gateway hacia CloudWatch y Datadog tengan políticas de retención tipo WORM (Write Once, Read Many). La trazabilidad de decisiones de acceso (ej. por qué el job de Modal forzó un MFA) debe ser criptográficamente segura o estrictamente inmutable.

2\. Mapeo Directo a la Ley 21.595 (Delitos Informáticos)

La actualización de la ley introdujo la Ley de Delitos Informáticos como delitos económicos base. Un acceso anómalo no es solo una alerta de seguridad; es la mitigación de un potencial delito penal.

•Requisito: El dashboard de compliance en Datadog debe hablar el idioma del Encargado de Prevención de Delitos (EPD), no solo del CISO. Las alertas de Vertex AI (fuera de turno, dispositivo nuevo) deben estar etiquetadas bajo categorías como: "Control Preventivo MPD: Mitigación de Fraude Informático / Acceso Ilícito".

3\. Trazabilidad de Revisiones de Acceso (IGA)

La Ley 20.393 exige demostrar que la empresa "supervisa y certifica" sus sistemas de prevención. El componente IGA (Identity Governance) es clave aquí. 

•Requisito: Tu plataforma debe poder emitir un reporte automatizado que demuestre quién tiene acceso a qué, y el historial de cuándo se otorgaron o revocaron esos privilegios (Offboarding automatizado). Si un ex-empleado comete un delito usando credenciales activas por negligencia de la empresa, la empresa es penalmente responsable. Tu sistema evita esto.

4\. SLA de Detección y Respuesta (Defensa Jurídica)

El job batch en Modal que consulta a Vertex AI cada 15 minutos es excelente para el Mid-Market.

•Requisito: Documenta este intervalo de 15 minutos como parte de la política de respuesta a incidentes del MPD del cliente. Ante un fiscal, demostrar que la empresa tiene un control algorítmico que aísla un acceso comprometido en un máximo de 15 minutos es una defensa probatoria altísima de que la empresa actuó con "debida diligencia".



