'use strict';

const PBKDF2_ITERATIONS = 200000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const VERSION = 1;
const PREFIX = 'DC1.';
const MIN_PAYLOAD_LENGTH = 1 + SALT_LENGTH + IV_LENGTH + 16;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

const ui = {
  tabs: Array.from(document.querySelectorAll('.segment')),
  panels: {
    encrypt: document.getElementById('panel-encrypt'),
    decrypt: document.getElementById('panel-decrypt')
  },
  encryptPassword: document.getElementById('encrypt-password'),
  decryptPassword: document.getElementById('decrypt-password'),
  plainText: document.getElementById('plain-text'),
  protectedOutput: document.getElementById('protected-output'),
  protectedInput: document.getElementById('protected-input'),
  decryptedOutput: document.getElementById('decrypted-output'),
  encryptButton: document.getElementById('encrypt-button'),
  decryptButton: document.getElementById('decrypt-button'),
  copyNotionButton: document.getElementById('copy-notion-button'),
  clearEncryptButton: document.getElementById('clear-encrypt-button'),
  clearDecryptButton: document.getElementById('clear-decrypt-button'),
  encryptStatus: document.getElementById('encrypt-status'),
  decryptStatus: document.getElementById('decrypt-status'),
  encryptResult: document.getElementById('encrypt-result'),
  decryptResult: document.getElementById('decrypt-result')
};

let activeMode = 'encrypt';
let copyFeedbackTimer = null;

function setStatus(element, message = '', type = '') {
  element.textContent = message;
  element.classList.remove('is-success', 'is-error');
  if (type) element.classList.add(`is-${type}`);
}

function setMode(mode) {
  if (!ui.panels[mode]) return;
  activeMode = mode;

  for (const tab of ui.tabs) {
    const isActive = tab.dataset.mode === mode;
    tab.classList.toggle('is-active', isActive);
    tab.setAttribute('aria-selected', String(isActive));
    tab.tabIndex = isActive ? 0 : -1;
  }

  for (const [name, panel] of Object.entries(ui.panels)) {
    const isActive = name === mode;
    panel.hidden = !isActive;
    panel.classList.toggle('is-active', isActive);
  }
}

async function deriveAesKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function bytesToBase64(bytes) {
  const chunkSize = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toBase64Url(bytes) {
  return bytesToBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromBase64Url(value) {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('INVALID_BASE64URL');
  }

  const remainder = value.length % 4;
  if (remainder === 1) {
    throw new Error('INVALID_BASE64URL');
  }

  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - remainder) % 4);
  try {
    return base64ToBytes(padded);
  } catch {
    throw new Error('INVALID_BASE64URL');
  }
}

function normalizeProtectedText(raw) {
  let value = raw.trim();

  if (value.startsWith('```') && value.endsWith('```')) {
    value = value.slice(3, -3);
  }

  return value
    .replace(/[\u200B\u200C\u200D\u2060\uFEFF]/g, '')
    .replace(/[\u2010\u2011\u2012\u2013\u2014\u2212]/g, '-')
    .replace(/\s+/g, '');
}

async function encryptEntry(password, text) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveAesKey(password, salt);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(text))
  );

  const payload = new Uint8Array(1 + SALT_LENGTH + IV_LENGTH + ciphertext.length);
  payload[0] = VERSION;
  payload.set(salt, 1);
  payload.set(iv, 1 + SALT_LENGTH);
  payload.set(ciphertext, 1 + SALT_LENGTH + IV_LENGTH);

  return PREFIX + toBase64Url(payload);
}

async function decryptEntry(password, protectedText) {
  const normalized = normalizeProtectedText(protectedText);
  if (!normalized.startsWith(PREFIX)) {
    throw new Error('INVALID_PREFIX');
  }

  const payload = fromBase64Url(normalized.slice(PREFIX.length));
  if (payload.length < MIN_PAYLOAD_LENGTH) {
    throw new Error('PAYLOAD_TOO_SHORT');
  }
  if (payload[0] !== VERSION) {
    throw new Error('UNSUPPORTED_VERSION');
  }

  const salt = payload.slice(1, 1 + SALT_LENGTH);
  const iv = payload.slice(1 + SALT_LENGTH, 1 + SALT_LENGTH + IV_LENGTH);
  const ciphertext = payload.slice(1 + SALT_LENGTH + IV_LENGTH);
  const key = await deriveAesKey(password, salt);

  try {
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return decoder.decode(plaintext);
  } catch {
    throw new Error('DECRYPT_FAILED');
  }
}

async function handleEncrypt() {
  const password = ui.encryptPassword.value;
  const text = ui.plainText.value;

  setStatus(ui.encryptStatus);

  if (!password) {
    setStatus(ui.encryptStatus, 'Введите пароль.', 'error');
    ui.encryptPassword.focus();
    return;
  }
  if (!text) {
    setStatus(ui.encryptStatus, 'Введите текст записи.', 'error');
    ui.plainText.focus();
    return;
  }

  ui.encryptButton.disabled = true;
  try {
    const protectedText = await encryptEntry(password, text);
    ui.protectedOutput.value = protectedText;
    ui.encryptResult.hidden = false;
    setStatus(ui.encryptStatus, '✓ Запись защищена', 'success');

    requestAnimationFrame(() => {
      ui.protectedOutput.focus({ preventScroll: true });
      ui.protectedOutput.select();
      ui.protectedOutput.setSelectionRange(0, ui.protectedOutput.value.length);
      ui.encryptResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  } catch {
    setStatus(ui.encryptStatus, 'Не удалось зашифровать запись.', 'error');
  } finally {
    ui.encryptButton.disabled = false;
  }
}

function getDecryptErrorMessage(error) {
  switch (error?.message) {
    case 'INVALID_PREFIX':
      return 'Запись должна начинаться с DC1.';
    case 'INVALID_BASE64URL':
      return 'Повреждённый формат защищённой записи.';
    case 'PAYLOAD_TOO_SHORT':
      return 'Защищённая запись слишком короткая или повреждена.';
    case 'UNSUPPORTED_VERSION':
      return 'Эта версия защищённой записи пока не поддерживается.';
    default:
      return 'Неверный пароль или повреждённая запись.';
  }
}

async function handleDecrypt() {
  const password = ui.decryptPassword.value;
  const protectedText = ui.protectedInput.value;

  setStatus(ui.decryptStatus);

  if (!password) {
    setStatus(ui.decryptStatus, 'Введите пароль.', 'error');
    ui.decryptPassword.focus();
    return;
  }
  if (!protectedText.trim()) {
    setStatus(ui.decryptStatus, 'Вставьте защищённую запись.', 'error');
    ui.protectedInput.focus();
    return;
  }

  ui.decryptButton.disabled = true;
  try {
    const text = await decryptEntry(password, protectedText);
    ui.decryptedOutput.value = text;
    ui.decryptResult.hidden = false;
    setStatus(ui.decryptStatus, '✓ Запись расшифрована', 'success');

    requestAnimationFrame(() => {
      ui.decryptedOutput.focus({ preventScroll: true });
      ui.decryptedOutput.setSelectionRange(0, 0);
      ui.decryptedOutput.scrollTop = 0;
      ui.decryptResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  } catch (error) {
    ui.decryptedOutput.value = '';
    ui.decryptResult.hidden = true;
    setStatus(ui.decryptStatus, getDecryptErrorMessage(error), 'error');
  } finally {
    ui.decryptButton.disabled = false;
  }
}

async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Continue to fallback while still inside the original click handler chain.
    }
  }

  const temp = document.createElement('textarea');
  temp.value = text;
  temp.setAttribute('readonly', '');
  temp.setAttribute('aria-hidden', 'true');
  temp.style.position = 'fixed';
  temp.style.top = '0';
  temp.style.left = '-9999px';
  temp.style.opacity = '0';
  document.body.appendChild(temp);
  temp.focus();
  temp.select();
  temp.setSelectionRange(0, temp.value.length);

  let copied = false;
  try {
    copied = document.execCommand('copy');
  } catch {
    copied = false;
  } finally {
    temp.remove();
  }
  return copied;
}

async function handleCopyForNotion() {
  const protectedText = ui.protectedOutput.value;
  if (!protectedText) {
    setStatus(ui.encryptStatus, 'Сначала зашифруйте запись.', 'error');
    return;
  }

  const notionText = `\`\`\`\n${protectedText}\n\`\`\``;
  const originalLabel = '📝 Скопировать для Notion';
  const copied = await copyText(notionText);

  if (!copied) {
    setStatus(ui.encryptStatus, 'Не удалось скопировать. Защищённая запись осталась на экране.', 'error');
    return;
  }

  setStatus(ui.encryptStatus, '✓ Запись защищена', 'success');
  ui.copyNotionButton.textContent = '✓ Скопировано для Notion';
  clearTimeout(copyFeedbackTimer);
  copyFeedbackTimer = setTimeout(() => {
    ui.copyNotionButton.textContent = originalLabel;
  }, 1500);
}

function clearEncrypt() {
  ui.encryptPassword.value = '';
  ui.plainText.value = '';
  ui.protectedOutput.value = '';
  ui.encryptResult.hidden = true;
  setStatus(ui.encryptStatus);
  clearTimeout(copyFeedbackTimer);
  ui.copyNotionButton.textContent = '📝 Скопировать для Notion';
  ui.plainText.focus();
}

function clearDecrypt() {
  ui.decryptPassword.value = '';
  ui.protectedInput.value = '';
  ui.decryptedOutput.value = '';
  ui.decryptResult.hidden = true;
  setStatus(ui.decryptStatus);
  ui.protectedInput.focus();
}

function togglePassword(button) {
  const target = document.getElementById(button.dataset.target);
  if (!target) return;
  const show = target.type === 'password';
  target.type = show ? 'text' : 'password';
  button.setAttribute('aria-pressed', String(show));
  button.setAttribute('aria-label', show ? 'Скрыть пароль' : 'Показать пароль');
  button.textContent = show ? '🙈' : '👁';
  target.focus({ preventScroll: true });
}

for (const tab of ui.tabs) {
  tab.addEventListener('click', () => setMode(tab.dataset.mode));
  tab.addEventListener('keydown', (event) => {
    if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
    event.preventDefault();
    const nextMode = activeMode === 'encrypt' ? 'decrypt' : 'encrypt';
    setMode(nextMode);
    document.querySelector(`.segment[data-mode="${nextMode}"]`)?.focus();
  });
}

document.querySelectorAll('.password-toggle').forEach((button) => {
  button.addEventListener('click', () => togglePassword(button));
});

ui.encryptButton.addEventListener('click', handleEncrypt);
ui.decryptButton.addEventListener('click', handleDecrypt);
ui.copyNotionButton.addEventListener('click', handleCopyForNotion);
ui.clearEncryptButton.addEventListener('click', clearEncrypt);
ui.clearDecryptButton.addEventListener('click', clearDecrypt);

document.addEventListener('keydown', (event) => {
  if (!(event.ctrlKey || event.metaKey) || event.key !== 'Enter' || event.isComposing) return;
  event.preventDefault();
  if (activeMode === 'encrypt') {
    handleEncrypt();
  } else {
    handleDecrypt();
  }
});

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./service-worker.js').catch(() => {
      // The app still works online; no user data is involved in registration.
    });
  });
}

setMode('encrypt');
