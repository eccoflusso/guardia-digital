/**
 * Auth0 Action (Trigger: post-login) — MFA Adaptativo Zero-Trust
 * Fuerza MFA cuando el login presenta señales de riesgo:
 *  - Score de riesgo alto (Auth0 Adaptive MFA / riskAssessment)
 *  - País distinto a Chile (fuera del perímetro habitual del Mid-Market local)
 *  - Horario fuera de turno laboral (07:00–22:00 CLT)
 *  - Dispositivo nuevo / IP no vista antes
 *  - Postura externa del dominio según SCAN-SIGHT I.A. (superficie de ataque):
 *    si el exterior del dominio está crítico (enforce), se fuerza MFA siempre.
 *  - [NUEVO] force_mfa_until en app_metadata: cierre del lazo de respuesta —
 *    ia_models/anomaly_detector.py escribe este campo vía Auth0 Management API
 *    cuando Vertex AI detecta un acceso anómalo (ver §4 Fase 4 del plan).
 *
 * Secret opcional: SCAN_SIGHT_API (URL base del scanner). Default: API pública de Wayweb.
 */
exports.onExecutePostLogin = async (event, api) => {
  const risk = event.authentication?.riskAssessment;
  const confidence = risk?.confidence;                       // 'low' | 'medium' | 'high'
  const country = event.request?.geoip?.countryCode || 'ZZ';

  // Hora local de Chile (America/Santiago)
  const hourCL = Number(
    new Intl.DateTimeFormat('es-CL', {
      hour: 'numeric', hour12: false, timeZone: 'America/Santiago',
    }).format(new Date())
  );
  const outOfShift = hourCL < 7 || hourCL >= 22;

  const newDevice = risk?.assessments?.NewDevice?.confidence === 'low';
  const untrustedIp = risk?.assessments?.UntrustedIP?.confidence === 'low';

  // ── Lazo de respuesta cerrado: anomaly_detector.py marca force_mfa_until cuando
  // Vertex AI detecta un acceso anómalo (anomaly_score >= 0.8) sobre este usuario ──
  const forceMfaUntil = event.user?.app_metadata?.force_mfa_until;
  const forcedByAnomaly = !!forceMfaUntil && new Date(forceMfaUntil) > new Date();

  // ── Señal externa SCAN-SIGHT I.A. (postura MFA según superficie de ataque del dominio) ──
  // Zero-Trust: si el EXTERIOR del dominio está crítico, endurecemos el acceso INTERNO.
  let externalPosture = 'unknown';   // enforce | step_up | standard | unknown
  try {
    const emailDomain = (event.user?.email || '').split('@')[1];
    if (emailDomain) {
      const base = event.secrets?.SCAN_SIGHT_API || 'https://api-pupzjflnwa-uc.a.run.app';
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 1500);   // no demorar el login
      const resp = await fetch(`${base}/risk-signal?domain=${encodeURIComponent(emailDomain)}`, { signal: ctrl.signal });
      clearTimeout(t);
      if (resp.ok) {
        const sig = await resp.json();
        externalPosture = sig.mfa_posture || 'unknown';
      } else {
        console.log(JSON.stringify({ service: 'guardia-auth0-action', scan_sight_error: `http_${resp.status}` }));
      }
    }
  } catch (e) {
    // Fail-open: si el scanner no responde, no bloqueamos el login (solo no aporta señal).
    // Se deja rastro en los logs de la Action para no perder visibilidad del fallo.
    console.log(JSON.stringify({ service: 'guardia-auth0-action', scan_sight_error: e?.name || 'unknown_error' }));
  }

  const externalEnforce = externalPosture === 'enforce';
  const externalStepUp = externalPosture === 'step_up';

  const suspicious =
    confidence === 'low' || confidence === 'medium' ||
    country !== 'CL' || outOfShift || newDevice || untrustedIp ||
    externalEnforce || externalStepUp || forcedByAnomaly;

  if (suspicious) {
    api.multifactor.enable('any', { allowRememberBrowser: false });
    // Trazabilidad para auditoría (Ley 20.393): queda en logs -> Datadog
    api.user.setAppMetadata('last_mfa_challenge', {
      reason: { confidence, country, outOfShift, newDevice, untrustedIp, externalPosture, forcedByAnomaly },
      at: new Date().toISOString(),
    });
  }
};
