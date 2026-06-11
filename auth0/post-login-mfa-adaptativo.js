/**
 * Auth0 Action (Trigger: post-login) — MFA Adaptativo Zero-Trust
 * Fuerza MFA cuando el login presenta señales de riesgo:
 *  - Score de riesgo alto (Auth0 Adaptive MFA / riskAssessment)
 *  - País distinto a Chile (fuera del perímetro habitual del Mid-Market local)
 *  - Horario fuera de turno laboral (07:00–22:00 CLT)
 *  - Dispositivo nuevo / IP no vista antes
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

  const suspicious =
    confidence === 'low' || confidence === 'medium' ||
    country !== 'CL' || outOfShift || newDevice || untrustedIp;

  if (suspicious) {
    api.multifactor.enable('any', { allowRememberBrowser: false });
    // Trazabilidad para auditoría (Ley 20.393): queda en logs -> Datadog
    api.user.setAppMetadata('last_mfa_challenge', {
      reason: { confidence, country, outOfShift, newDevice, untrustedIp },
      at: new Date().toISOString(),
    });
  }
};
