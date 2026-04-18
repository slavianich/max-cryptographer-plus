const VERSION = 'v1';
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const DEFAULT_ITERATIONS = 250000;
const FAST_ITERATIONS = 10000;
const PASS_LENGTH = 20;

const inputText = document.getElementById('inputText');
const resultText = document.getElementById('resultText');
const passwordInput = document.getElementById('password');
const iterationsInput = document.getElementById('iterations');
const kdfMode = document.getElementById('kdfMode');
const statusEl = document.getElementById('status');
const resultLengthEl = document.getElementById('resultLength');
const strengthIndicator = document.getElementById('strengthIndicator');
const emojiMode = document.getElementById('emojiMode');
const themeToggle = document.getElementById('themeToggle');

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const setStatus = (message, type = 'info') => {
  statusEl.textContent = message;
  statusEl.className = type === 'error' ? 'error' : type === 'success' ? 'success' : '';
};

const updateResultLength = (value = '') => {
  resultLengthEl.textContent = `Encrypted length: ${value.length}`;
};

const encode = (bytes) => {
  let binary = '';
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
};

const decode = (base64) => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

const normalizePayload = (value) => value.replace(/\s+/g, '').replace(/[🔹✨🧩]/g, '').replace(/\|/g, ':');

const addEmojiSeparators = (payload) => {
  const [v, salt, nonce, ciphertext] = payload.split(':');
  if (!v || !salt || !nonce || !ciphertext) return payload;
  return `${v}✨${salt}🔹${nonce}🧩${ciphertext}`;
};

const removeEmojiSeparators = (payload) => normalizePayload(payload);

const evaluatePasswordStrength = (password) => {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;

  if (score <= 2) return 'weak';
  if (score <= 4) return 'medium';
  return 'strong';
};

const updateStrengthUI = () => {
  const strength = evaluatePasswordStrength(passwordInput.value);
  strengthIndicator.textContent = `Strength: ${strength}`;
  strengthIndicator.className = `strength ${strength}`;
};

async function deriveKey(password, salt, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encrypt(plainText, password, iterations) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  const key = await deriveKey(password, salt, iterations);

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    encoder.encode(plainText)
  );

  return {
    salt,
    nonce,
    ciphertext: new Uint8Array(cipherBuffer)
  };
}

async function decrypt(payload, password, iterations) {
  const normalized = removeEmojiSeparators(payload);
  const parts = normalized.split(':');

  if (parts.length !== 4) {
    throw new Error('Invalid payload format. Expected v1:salt:nonce:ciphertext');
  }

  const [version, saltB64, nonceB64, ciphertextB64] = parts;
  if (version !== VERSION) {
    throw new Error(`Unsupported version: ${version}`);
  }

  const salt = decode(saltB64);
  const nonce = decode(nonceB64);
  const ciphertext = decode(ciphertextB64);
  const key = await deriveKey(password, salt, iterations);

  const plainBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    ciphertext
  );

  return decoder.decode(plainBuffer);
}

const getIterations = () => {
  const parsed = Number.parseInt(iterationsInput.value, 10);
  if (Number.isNaN(parsed) || parsed < 1000) {
    throw new Error('Iterations must be a number >= 1000');
  }
  return parsed;
};

const buildPayload = ({ salt, nonce, ciphertext }) => `${VERSION}:${encode(salt)}:${encode(nonce)}:${encode(ciphertext)}`;

const clearSensitiveState = () => {
  passwordInput.value = '';
  updateStrengthUI();
};

const handleEncrypt = async () => {
  let password = passwordInput.value;
  try {
    const plain = inputText.value;
    if (!plain) throw new Error('Input text is empty');
    if (!password) throw new Error('Password is required');

    const iterations = getIterations();
    const encrypted = await encrypt(plain, password, iterations);
    const payload = buildPayload(encrypted);
    const displayed = emojiMode.checked ? addEmojiSeparators(payload) : payload;

    resultText.value = displayed;
    updateResultLength(payload);
    setStatus('Encryption complete', 'success');
  } catch (error) {
    setStatus(error.message || 'Encryption failed', 'error');
  } finally {
    password = '';
    clearSensitiveState();
  }
};

const handleDecrypt = async () => {
  let password = passwordInput.value;
  try {
    const payload = inputText.value.trim();
    if (!payload) throw new Error('Input payload is empty');
    if (!password) throw new Error('Password is required');

    const iterations = getIterations();
    const plain = await decrypt(payload, password, iterations);

    resultText.value = plain;
    updateResultLength(removeEmojiSeparators(payload));
    setStatus('Decryption complete', 'success');
  } catch (error) {
    setStatus(error.message || 'Decryption failed', 'error');
  } finally {
    password = '';
    clearSensitiveState();
  }
};

const handleCopy = async () => {
  try {
    if (!resultText.value) throw new Error('Nothing to copy');
    await navigator.clipboard.writeText(resultText.value);
    setStatus('Result copied to clipboard', 'success');
  } catch {
    setStatus('Clipboard write failed', 'error');
  }
};

const handlePaste = async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (!text) throw new Error('Clipboard is empty');
    inputText.value = text;
    setStatus('Pasted from clipboard', 'success');
  } catch {
    setStatus('Clipboard read failed', 'error');
  }
};

const clearFields = () => {
  inputText.value = '';
  resultText.value = '';
  passwordInput.value = '';
  updateResultLength('');
  updateStrengthUI();
  setStatus('Fields cleared', 'success');
};

const makeStrongPassword = () => {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*()-_=+[]{}';
  const random = crypto.getRandomValues(new Uint8Array(PASS_LENGTH));
  let generated = '';
  random.forEach((val) => {
    generated += alphabet[val % alphabet.length];
  });
  passwordInput.value = generated;
  updateStrengthUI();
  setStatus('Strong password generated locally', 'success');
};

const syncIterationsWithMode = () => {
  if (kdfMode.value === 'fast' && iterationsInput.value === String(DEFAULT_ITERATIONS)) {
    iterationsInput.value = String(FAST_ITERATIONS);
  }
  if (kdfMode.value === 'pbkdf2' && iterationsInput.value === String(FAST_ITERATIONS)) {
    iterationsInput.value = String(DEFAULT_ITERATIONS);
  }
};

const toggleTheme = () => {
  const body = document.body;
  const current = body.dataset.theme || 'light';
  const next = current === 'light' ? 'dark' : 'light';
  body.dataset.theme = next;
  themeToggle.textContent = next === 'dark' ? 'Light theme' : 'Dark theme';
};

document.getElementById('encryptBtn').addEventListener('click', handleEncrypt);
document.getElementById('decryptBtn').addEventListener('click', handleDecrypt);
document.getElementById('copyBtn').addEventListener('click', handleCopy);
document.getElementById('pasteBtn').addEventListener('click', handlePaste);
document.getElementById('clearBtn').addEventListener('click', clearFields);
document.getElementById('generatePasswordBtn').addEventListener('click', makeStrongPassword);
themeToggle.addEventListener('click', toggleTheme);
kdfMode.addEventListener('change', syncIterationsWithMode);
passwordInput.addEventListener('input', updateStrengthUI);
emojiMode.addEventListener('change', () => {
  if (!resultText.value) return;
  if (resultText.value.startsWith(`${VERSION}:`) || /[✨🔹🧩]/.test(resultText.value)) {
    const normalized = removeEmojiSeparators(resultText.value);
    resultText.value = emojiMode.checked ? addEmojiSeparators(normalized) : normalized;
  }
});

updateStrengthUI();
updateResultLength('');
setStatus('Ready: fully local encryption/decryption');
