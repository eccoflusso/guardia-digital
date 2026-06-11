/**
 * Intercom — Bot de autoservicio embebido en Auth0 Universal Login.
 * Casos cubiertos sin intervención humana: desbloqueo de cuenta y setup de MFA.
 * Insertar este snippet en la plantilla de la página de login (Page Templates).
 */
(function () {
  var APP_ID = window.INTERCOM_APP_ID || 'REEMPLAZAR_APP_ID';

  window.intercomSettings = {
    api_base: 'https://api-iam.intercom.io',
    app_id: APP_ID,
    language_override: 'es',
    // Contexto para enrutar al bot correcto (flujos: bloqueo / MFA)
    custom_attributes: { origen: 'login_guardia_digital', mercado: 'cl' },
  };

  // Loader estándar de Intercom
  var w = window, ic = w.Intercom;
  if (typeof ic === 'function') {
    ic('reattach_activator'); ic('update', w.intercomSettings);
  } else {
    var i = function () { i.c(arguments); };
    i.q = []; i.c = function (args) { i.q.push(args); };
    w.Intercom = i;
    var s = document.createElement('script');
    s.type = 'text/javascript'; s.async = true;
    s.src = 'https://widget.intercom.io/widget/' + APP_ID;
    document.head.appendChild(s);
  }

  // Disparadores contextuales: abrir bot ante errores comunes de login
  document.addEventListener('DOMContentLoaded', function () {
    var errorBox = document.querySelector('.auth0-lock-error, [data-error-code]');
    if (!errorBox) return;
    var code = errorBox.getAttribute('data-error-code') || '';
    if (code === 'too_many_attempts') {
      window.Intercom('showNewMessage', 'Mi cuenta fue bloqueada por intentos fallidos.');
    } else if (code === 'mfa_required') {
      window.Intercom('showNewMessage', 'Necesito ayuda para configurar mi MFA.');
    }
  });
})();
