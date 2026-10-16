'use strict';
const $ = (id) => document.getElementById(id);
let mode = 'login', csrf = '', busy = false;
function message(text, error = false) { $('message').textContent = text; $('message').classList.toggle('error', error); }
function switchMode(next) {
  if (busy) return;
  mode = next;
  const register = next === 'register';
  $('name-field').hidden = !register; $('name').required = register;
  $('form-title').textContent = register ? 'Make it yours.' : 'Welcome back.';
  $('form-description').textContent = register ? 'Create an account in this local SQL database.' : 'Use an account you created in this local app.';
  $('password').autocomplete = register ? 'new-password' : 'current-password';
  $('submit').textContent = register ? 'Create account →' : 'Sign in →';
  $('step').textContent = register ? '02 / CREATE ACCOUNT' : '02 / SIGN IN';
  for (const value of ['login', 'register']) { $(value + '-tab').classList.toggle('selected', value === next); $(value + '-tab').setAttribute('aria-pressed', String(value === next)); }
  message('');
}
async function api(path, data) {
  const response = await fetch('/api/' + path, { method: data === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: data === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: data === undefined ? undefined : JSON.stringify(data) });
  const result = await response.json();
  if (!response.ok) { let text = result.detail || 'Request failed.'; if (response.status === 429) text += ' Wait ' + response.headers.get('Retry-After') + ' seconds.'; throw new Error(text); }
  return result;
}
async function account(user) {
  $('auth-view').hidden = !!user; $('account-view').hidden = !user;
  if (user) {
    // Verify authorization separately; a frontend-only flag is never the gate.
    const verified = await api('me');
    $('account-name').textContent = verified.name; $('account-email').textContent = verified.email;
    $('step').textContent = '02 / YOUR SESSION';
  } else switchMode('login');
}
async function bootstrap() {
  const result = await api('session'); csrf = result.csrf;
  await account(result.user); $('submit').disabled = false;
}
$('login-tab').onclick = () => switchMode('login');
$('register-tab').onclick = () => switchMode('register');
$('show-password').onclick = () => { const show = $('password').type === 'password'; $('password').type = show ? 'text' : 'password'; $('show-password').textContent = show ? 'Hide' : 'Show'; $('show-password').setAttribute('aria-pressed', String(show)); };
$('auth-form').onsubmit = async (event) => {
  event.preventDefault(); if (busy) return; busy = true; $('submit').disabled = true; message('Working…');
  const payload = { email: $('email').value, password: $('password').value };
  if (mode === 'register') payload.name = $('name').value;
  try {
    const result = await api(mode, payload);
    $('password').value = ''; $('password').type = 'password'; $('show-password').textContent = 'Show'; $('show-password').setAttribute('aria-pressed', 'false');
    if (mode === 'login') { csrf = result.csrf; await account(result.user); message('Session active. Your browser only holds an opaque cookie.'); }
    else { busy = false; switchMode('login'); message(result.message); $('password').focus(); }
  } catch (error) { message(error.message, true); }
  finally { busy = false; $('submit').disabled = false; }
};
$('logout').onclick = async () => {
  $('logout').disabled = true;
  try { await api('logout', {}); await bootstrap(); message('Signed out. Server session revoked.'); }
  catch (error) { message(error.message, true); }
  finally { $('logout').disabled = false; }
};
bootstrap().catch((error) => message(error.message + ' Reload this page to reconnect.', true));
