/* XSafety — клиентская логика.
 *
 * Никакой пользовательский текст не вставляется через innerHTML: все
 * данные приходят из API и выводятся через textContent, поэтому XSS в
 * интерфейсе невозможен даже при подмене ответа (см. SECURITY.md, V-14).
 */
'use strict';

const API = '/api';
const CSRF_COOKIE = 'xsafety_xsrf';
const MAX_UPLOAD_BYTES = 64 * 1024 * 1024;

const SEVERITY = {
  critical: { label: 'Критично', color: '#ff4d6d' },
  high: { label: 'Высокая', color: '#ff8a3d' },
  medium: { label: 'Средняя', color: '#ffd166' },
  low: { label: 'Низкая', color: '#7cc7ff' },
  info: { label: 'Инфо', color: '#9aa7c7' },
};

const VERDICT = {
  clean: { label: 'Чисто', color: '#4ade80', icon: '✓' },
  suspicious: { label: 'Подозрительно', color: '#ffbe5c', icon: '!' },
  malicious: { label: 'Опасно', color: '#ff5d7a', icon: '×' },
};

const FALLBACK_MODELS = [
  { id: 'm1', name: 'XSafety 1', tagline: 'Скрипты Windows и Python', extensions: ['bat', 'py'] },
  { id: 'm2', name: 'XSafety 2', tagline: 'Плюс JavaScript и PowerShell', extensions: ['bat', 'py', 'js', 'ps1'] },
  { id: 'm3_lite', name: 'XSafety 3 Lite', tagline: 'Плюс VBS, HTA, DLL и ZIP', extensions: ['bat', 'py', 'js', 'ps1', 'vbs', 'hta', 'dll', 'zip'] },
  { id: 'm3_pro', name: 'XSafety 3 Pro', tagline: 'Плюс EXE и JAR', extensions: ['bat', 'py', 'js', 'ps1', 'vbs', 'hta', 'dll', 'zip', 'exe', 'jar'] },
];

const state = {
  me: null,
  quota: null,
  plans: null,
  models: FALLBACK_MODELS.slice(),
  selectedModel: null,
  selectedOffers: {},
  file: null,
  authMode: 'login',
  pendingPurchase: null,
  view: 'scanner',
  historyLoaded: false,
  lastFocus: null,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

/* ------------------------------- утилиты ------------------------------- */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function getCookie(name) {
  const match = document.cookie.split(';').map((part) => part.trim()).find((part) => part.startsWith(name + '='));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : '';
}

function fmtSize(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} Б`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} КБ`;
  return `${(value / (1024 * 1024)).toFixed(2)} МБ`;
}

function fmtNum(value) {
  return new Intl.NumberFormat('ru-RU').format(Number(value) || 0);
}

function fmtDate(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('ru-RU', {
    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
  }).format(date);
}

function timeLeft(iso) {
  if (!iso) return '—';
  const target = new Date(iso).getTime();
  if (!Number.isFinite(target)) return '—';
  let ms = target - Date.now();
  if (ms <= 0) return 'сейчас';
  const totalMinutes = Math.ceil(ms / 60000);
  const days = Math.floor(totalMinutes / 1440);
  const hours = Math.floor((totalMinutes % 1440) / 60);
  const minutes = totalMinutes % 60;
  if (days > 0) return `${days} д ${hours} ч`;
  if (hours > 0) return `${hours} ч ${String(minutes).padStart(2, '0')} мин`;
  return `${minutes} мин`;
}

function modelName(id) {
  const model = state.models.find((item) => item.id === id);
  return model ? model.name : id;
}

function planName(id) {
  const plans = state.plans?.plans || [];
  const plan = plans.find((item) => item.id === id);
  return plan ? plan.name : (id === 'default' ? 'Default' : id);
}

function toast(message, type = 'info', ttl = 5200) {
  const box = $('#toasts');
  if (!box) return;
  const node = el('div', `toast toast-${type}`, message);
  box.appendChild(node);
  while (box.children.length > 4) box.removeChild(box.firstChild);
  window.setTimeout(() => {
    node.classList.add('is-out');
    window.setTimeout(() => node.remove(), 200);
  }, ttl);
}

async function ensureCsrf() {
  if (getCookie(CSRF_COOKIE)) return;
  try {
    await fetch(`${API}/health`, { credentials: 'same-origin' });
  } catch (_) { /* сервер недоступен — ошибку покажет основной запрос */ }
}

class ApiError extends Error {
  constructor(message, status, code, details) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details || {};
  }
}

async function api(path, options = {}) {
  const init = { method: options.method || 'GET', credentials: 'same-origin', headers: { ...(options.headers || {}) } };
  if (options.json !== undefined) {
    init.method = options.method || 'POST';
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(options.json);
  } else if (options.body !== undefined) {
    init.body = options.body;
  }
  if (init.method !== 'GET' && init.method !== 'HEAD') {
    await ensureCsrf();
    const csrf = getCookie(CSRF_COOKIE);
    if (csrf) init.headers['X-CSRF-Token'] = csrf;
  }
  let response;
  try {
    response = await fetch(`${API}${path}`, init);
  } catch (_) {
    throw new ApiError('Сервер недоступен. Проверьте подключение.', 0, 'network');
  }
  let data = null;
  try { data = await response.json(); } catch (_) { data = null; }
  if (!response.ok) {
    const error = data && data.error ? data.error : {};
    throw new ApiError(error.message || `Ошибка ${response.status}`, response.status, error.code || 'error', error.details);
  }
  return data;
}

/* ------------------------------ навигация ------------------------------ */

function showView(name, { updateHash = true } = {}) {
  if (!['scanner', 'pricing', 'history'].includes(name)) name = 'scanner';
  state.view = name;
  $$('.view').forEach((view) => { view.hidden = view.id !== `view-${name}`; });
  $$('.tab').forEach((tab) => tab.classList.toggle('is-active', tab.dataset.nav === name));
  if (updateHash && window.location.hash !== `#${name}`) {
    history.replaceState(null, '', `#${name}`);
  }
  window.scrollTo({ top: 0, behavior: 'smooth' });
  if (name === 'history') loadHistory();
  if (name === 'pricing') renderPricing();
}

function routeFromHash() {
  const name = (window.location.hash || '#scanner').slice(1);
  showView(name, { updateHash: false });
}

/* -------------------------------- аккаунт ------------------------------- */

function currentPlanLabel() {
  if (!state.quota) return 'Default';
  const until = state.quota.plan_until;
  if (state.quota.plan === 'premium' || state.quota.plan === 'pro') {
    return `${planName(state.quota.plan)}${until ? ` до ${fmtDate(until)}` : ' · навсегда'}`;
  }
  return 'Default';
}

function renderAccount() {
  const chip = $('#userChip');
  const loginBtn = $('#loginBtn');
  if (state.me) {
    chip.hidden = false;
    loginBtn.hidden = true;
    $('#userEmail').textContent = state.me.email;
    $('#userAvatar').textContent = (state.me.email[0] || '?');
    $('#userPlan').textContent = currentPlanLabel();
    $('#planBadge').textContent = planName(state.quota?.plan || state.me.plan);
  } else {
    chip.hidden = true;
    loginBtn.hidden = false;
    $('#planBadge').textContent = 'Гость';
  }
  const pill = $('#refillPill');
  pill.hidden = !state.quota;
  if (state.quota) {
    $('#refillTime').textContent = timeLeft(state.quota.resets_at);
  }
}

function toggleUserMenu() {
  if (!state.me) return;
  const existing = document.querySelector('.user-menu');
  if (existing) { existing.remove(); return; }
  const menu = el('div', 'user-menu');
  const head = el('div', 'user-menu-head');
  head.appendChild(el('b', '', state.me.email));
  head.appendChild(el('span', '', currentPlanLabel()));
  menu.appendChild(head);
  const historyBtn = el('button', 'user-menu-item', 'История проверок');
  historyBtn.type = 'button';
  historyBtn.addEventListener('click', () => { menu.remove(); showView('history'); });
  const plansBtn = el('button', 'user-menu-item', 'Тарифы и лимиты');
  plansBtn.type = 'button';
  plansBtn.addEventListener('click', () => { menu.remove(); showView('pricing'); });
  const logoutBtn = el('button', 'user-menu-item is-danger', 'Выйти');
  logoutBtn.type = 'button';
  logoutBtn.addEventListener('click', () => { menu.remove(); logout(); });
  menu.append(historyBtn, plansBtn, logoutBtn);
  $('.top-actions').appendChild(menu);
  setTimeout(() => {
    const close = (event) => {
      if (!menu.contains(event.target) && event.target !== $('#userChip')) {
        menu.remove();
        document.removeEventListener('click', close);
      }
    };
    document.addEventListener('click', close);
  }, 0);
}

async function logout() {
  try {
    await api('/auth/logout', { method: 'POST' });
  } catch (_) { /* выходим локально в любом случае */ }
  state.me = null;
  state.quota = null;
  state.historyLoaded = false;
  state.file = null;
  $('#resultSection').hidden = true;
  resetFile();
  renderAll();
  toast('Вы вышли из аккаунта.', 'info');
}

function openAuth(mode = 'login') {
  state.lastFocus = document.activeElement;
  setAuthMode(mode);
  $('#authError').hidden = true;
  const modal = $('#authModal');
  modal.hidden = false;
  document.body.style.overflow = 'hidden';
  setTimeout(() => $('#authEmail').focus(), 30);
}

function closeModal(name) {
  const modal = document.getElementById(`${name}Modal`);
  if (!modal) return;
  modal.hidden = true;
  document.body.style.overflow = '';
  if (state.lastFocus && document.contains(state.lastFocus)) {
    state.lastFocus.focus();
  }
  state.lastFocus = null;
}

function setAuthMode(mode) {
  state.authMode = mode;
  $$('[data-auth-tab]').forEach((tab) => tab.classList.toggle('is-active', tab.dataset.authTab === mode));
  const isLogin = mode === 'login';
  $('#authTitle').textContent = isLogin ? 'Вход в XSafety' : 'Регистрация в XSafety';
  $('#authSubmit').textContent = isLogin ? 'Войти' : 'Создать аккаунт';
  $('#authPassword').autocomplete = isLogin ? 'current-password' : 'new-password';
  $('#authNote').textContent = isLogin
    ? 'Нет аккаунта? Переключитесь на регистрацию — это займёт несколько секунд.'
    : 'Пароль от 8 символов. Демо-аккаунт хранится в локальной базе SQLite.';
  $('#authError').hidden = true;
}

async function submitAuth(event) {
  event.preventDefault();
  const email = $('#authEmail').value.trim();
  const password = $('#authPassword').value;
  const errorNode = $('#authError');
  const button = $('#authSubmit');
  errorNode.hidden = true;
  if (!email || !password) {
    errorNode.textContent = 'Заполните e-mail и пароль.';
    errorNode.hidden = false;
    return;
  }
  if (state.authMode === 'register' && password.length < 8) {
    errorNode.textContent = 'Пароль должен быть не короче 8 символов.';
    errorNode.hidden = false;
    return;
  }
  button.disabled = true;
  const original = button.textContent;
  button.textContent = 'Подождите…';
  try {
    const data = await api(`/auth/${state.authMode}`, { json: { email, password } });
    state.me = data.user;
    state.quota = data.quota;
    state.historyLoaded = false;
    closeModal('auth');
    $('#authForm').reset();
    renderAll();
    toast(state.authMode === 'register' ? 'Аккаунт создан. Добро пожаловать!' : 'С возвращением!', 'success');
    if (state.authMode === 'register') showView('pricing');
  } catch (error) {
    errorNode.textContent = error.message;
    errorNode.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

/* --------------------------------- модели -------------------------------- */

function renderModels() {
  const grid = $('#modelGrid');
  clear(grid);
  const quotaModels = new Map((state.quota?.models || []).map((item) => [item.model_id, item]));
  const models = state.models;
  let firstAvailable = null;

  models.forEach((model) => {
    const quota = quotaModels.get(model.id);
    const available = state.me ? Boolean(quota && quota.available) : false;
    const exhausted = Boolean(quota && quota.exhausted);
    const blocked = state.me ? Boolean(quota && quota.blocked) : false;
    if (!firstAvailable && available && !exhausted) firstAvailable = model.id;

    const button = el('button', 'model-card');
    button.type = 'button';
    button.setAttribute('role', 'radio');
    button.dataset.model = model.id;
    button.setAttribute('aria-checked', String(state.selectedModel === model.id));

    const head = el('div', 'model-head');
    head.appendChild(el('span', 'model-name', model.name));
    if (state.me && quota && quota.blocked) head.appendChild(el('span', 'model-lock', '🔒'));
    button.appendChild(head);

    const exts = el('div', 'model-exts');
    model.extensions.forEach((ext) => exts.appendChild(el('span', 'ext', `.${ext}`)));
    button.appendChild(exts);

    const quotaLine = el('div', 'model-quota');
    if (!state.me) {
      quotaLine.textContent = 'Войдите, чтобы проверить файлы';
    } else if (blocked) {
      quotaLine.textContent = 'Нет в тарифе — лимиты не начисляются';
    } else if (quota) {
      const mb = quota.mb_limit === null ? 'без лимита объёма' : `до ${quota.mb_limit} МБ`;
      quotaLine.append(document.createTextNode('Осталось '));
      quotaLine.appendChild(el('b', '', `${quota.requests_left} из ${quota.requests_limit}`));
      quotaLine.append(document.createTextNode(` · ${mb}`));
    } else {
      quotaLine.textContent = 'Загрузка лимитов…';
    }
    button.appendChild(quotaLine);

    const status = el('div', 'model-status');
    status.appendChild(el('span', 'dot'));
    if (!state.me) {
      status.appendChild(el('span', '', 'требуется вход'));
    } else if (blocked) {
      status.appendChild(el('span', '', 'недоступно · без начисления'));
    } else if (exhausted) {
      const span = el('span');
      span.append(document.createTextNode('лимит исчерпан · сброс через '));
      const timer = el('b', '', timeLeft(quota.resets_at));
      timer.dataset.reset = quota.resets_at;
      span.appendChild(timer);
      status.appendChild(span);
    } else {
      status.appendChild(el('span', '', 'готово к проверке'));
    }
    button.appendChild(status);

    if (state.me && blocked) button.classList.add('is-blocked');
    if (state.me && exhausted) button.classList.add('is-exhausted');
    if (state.selectedModel === model.id) button.classList.add('is-selected');

    button.addEventListener('click', () => selectModel(model.id));
    grid.appendChild(button);
  });

  if (!state.selectedModel || !models.some((model) => model.id === state.selectedModel)) {
    state.selectedModel = firstAvailable || models[0]?.id || null;
  } else if (state.me) {
    const current = quotaModels.get(state.selectedModel);
    if (current && (current.blocked || current.exhausted)) {
      state.selectedModel = firstAvailable || state.selectedModel;
    }
  }
  syncSelectedModel();
}

function syncSelectedModel() {
  $$('.model-card').forEach((card) => {
    const selected = card.dataset.model === state.selectedModel;
    card.classList.toggle('is-selected', selected);
    card.setAttribute('aria-checked', String(selected));
  });
  const input = $('#fileInput');
  const model = state.models.find((item) => item.id === state.selectedModel);
  if (input && model) input.accept = model.extensions.map((ext) => `.${ext}`).join(',');
  const quota = (state.quota?.models || []).find((item) => item.model_id === state.selectedModel);
  const hint = $('#quotaHint');
  if (!state.me) {
    hint.textContent = 'Войдите, чтобы использовать лимиты';
  } else if (quota && quota.blocked) {
    hint.textContent = 'Модель вне тарифа — выберите другую';
  } else if (quota) {
    hint.textContent = `${quota.name} · осталось ${quota.requests_left} запросов`;
  } else {
    hint.textContent = 'Выберите модель и файл';
  }
  updateDropAccept();
}

function selectModel(modelId) {
  const quota = (state.quota?.models || []).find((item) => item.model_id === modelId);
  if (state.me && quota) {
    if (quota.blocked) {
      toast('Этой модели нет в тарифе: новые лимиты на неё не начисляются. Смените тариф.', 'error');
      return;
    }
    if (quota.exhausted) {
      toast(`Лимит исчерпан. Сброс через ${timeLeft(quota.resets_at)}.`, 'error');
      return;
    }
  }
  state.selectedModel = modelId;
  syncSelectedModel();
}

function updateDropAccept() {
  const sub = $('#dropSub');
  const model = state.models.find((item) => item.id === state.selectedModel);
  if (!sub || !model) return;
  const exts = model.extensions.map((ext) => `.${ext}`).join(', ');
  sub.textContent = `Форматы модели: ${exts} · до 64 МБ`;
}

/* --------------------------------- файл --------------------------------- */

function resetFile() {
  state.file = null;
  const info = $('#fileInfo');
  if (info) info.textContent = 'Файл не выбран';
  const dropFile = $('#dropFile');
  if (dropFile) { dropFile.hidden = true; dropFile.textContent = ''; }
  const input = $('#fileInput');
  if (input) input.value = '';
  const button = $('#scanBtn');
  if (button) button.disabled = true;
}

function extensionOf(name) {
  const parts = String(name || '').toLowerCase().split('.');
  return parts.length > 1 ? parts.pop() : '';
}

function setFile(file) {
  if (!file) return;
  if (file.size > MAX_UPLOAD_BYTES) {
    toast('Файл больше 64 МБ — технический лимит сервиса.', 'error');
    return;
  }
  if (file.size === 0) {
    toast('Файл пустой.', 'error');
    return;
  }
  state.file = file;
  const model = state.models.find((item) => item.id === state.selectedModel);
  const ext = extensionOf(file.name);
  $('#fileInfo').textContent = `${file.name} · ${fmtSize(file.size)}`;
  const dropFile = $('#dropFile');
  dropFile.textContent = `${file.name} · ${fmtSize(file.size)}`;
  dropFile.hidden = false;
  $('#scanBtn').disabled = false;
  if (model && !model.extensions.includes(ext)) {
    toast(`Модель ${model.name} не проверяет .${ext || '?'} — выберите подходящую модель.`, 'error');
  }
}

async function startScan() {
  if (!state.me) {
    openAuth('login');
    toast('Войдите, чтобы использовать лимиты проверок.', 'info');
    return;
  }
  if (!state.file) {
    toast('Сначала выберите файл.', 'error');
    return;
  }
  const model = state.selectedModel;
  if (!model) {
    toast('Выберите модель проверки.', 'error');
    return;
  }
  const modelInfo = state.models.find((item) => item.id === model);
  const ext = extensionOf(state.file.name);
  if (modelInfo && !modelInfo.extensions.includes(ext)) {
    toast(`Модель ${modelInfo.name} не проверяет .${ext}. Выберите другую модель.`, 'error');
    return;
  }
  const button = $('#scanBtn');
  const label = button.querySelector('.btn-label');
  const spinner = button.querySelector('.spinner');
  button.disabled = true;
  label.textContent = 'Проверяем…';
  spinner.hidden = false;
  $('#scanProgress').hidden = false;

  const form = new FormData();
  form.append('file', state.file, state.file.name);
  form.append('model', model);

  try {
    const data = await api('/scan', { method: 'POST', body: form });
    if (data.quota) state.quota = data.quota;
    renderAccount();
    renderModels();
    renderResult(data.result, data.scan_id);
    state.historyLoaded = false;
    toast('Проверка завершена.', 'success');
  } catch (error) {
    if (error.status === 401) {
      state.me = null;
      state.quota = null;
      renderAll();
      openAuth('login');
    }
    if (error.status === 429 || error.status === 413 || error.code === 'daily_limit') {
      refreshMe();
    }
    toast(error.message, 'error');
  } finally {
    button.disabled = !state.file;
    label.textContent = 'Проверить';
    spinner.hidden = true;
    $('#scanProgress').hidden = true;
  }
}

/* -------------------------------- результат ------------------------------ */

function renderResult(result, scanId) {
  const section = $('#resultSection');
  clear(section);
  const verdict = VERDICT[result.verdict] || VERDICT.suspicious;
  section.style.setProperty('--v', verdict.color);

  const head = el('div', 'result-head');
  const icon = el('div', 'verdict-icon', verdict.icon);
  head.appendChild(icon);
  const headText = el('div');
  headText.appendChild(el('div', 'verdict-title', verdict.label));
  headText.appendChild(el('div', 'verdict-file', `${result.filename} · модель ${modelName(result.model)}`));
  head.appendChild(headText);

  const actions = el('div', 'result-actions');
  if (scanId) {
    const view = el('a', 'btn btn-soft btn-sm', 'Открыть отчёт');
    view.href = `${API}/scans/${encodeURIComponent(scanId)}/report.html`;
    view.target = '_blank';
    view.rel = 'noopener noreferrer';
    const download = el('a', 'btn btn-ghost btn-sm', 'Скачать HTML');
    download.href = `${API}/scans/${encodeURIComponent(scanId)}/report.html?download=1`;
    download.rel = 'noopener noreferrer';
    actions.append(view, download);
  }
  const again = el('button', 'btn btn-ghost btn-sm', 'Новая проверка');
  again.type = 'button';
  again.addEventListener('click', () => {
    resetFile();
    $('#dropZone').scrollIntoView({ behavior: 'smooth', block: 'center' });
    setTimeout(() => $('#fileInput').click(), 250);
  });
  actions.appendChild(again);
  head.appendChild(actions);
  section.appendChild(head);

  const body = el('div', 'result-body');

  const chips = el('div', 'chips');
  const counts = result.counts || {};
  ['critical', 'high', 'medium', 'low', 'info'].forEach((sev) => {
    if (!counts[sev]) return;
    const chip = el('span', 'chip', `${SEVERITY[sev].label}: ${counts[sev]}`);
    chip.style.setProperty('--c', SEVERITY[sev].color);
    chips.appendChild(chip);
  });
  if (!chips.children.length) {
    const chip = el('span', 'chip', 'Находок нет');
    chip.style.setProperty('--c', '#4ade80');
    chips.appendChild(chip);
  }
  body.appendChild(chips);

  const meta = el('div', 'meta-grid');
  const metaItems = [
    ['Размер', fmtSize(result.size)],
    ['Расширение', `.${result.extension}`],
    ['Проверено файлов', fmtNum(result.scanned_entries)],
    ['Время анализа', `${fmtNum(result.elapsed_ms)} мс`],
    ['SHA-256', result.sha256],
  ];
  metaItems.forEach(([label, value]) => {
    const item = el('div', 'meta-item');
    item.appendChild(el('span', '', label));
    const bold = el('b', '', value);
    if (label === 'SHA-256') bold.title = value;
    item.appendChild(bold);
    meta.appendChild(item);
  });
  body.appendChild(meta);

  const findings = el('div', 'findings');
  const findingsHead = el('div', 'findings-head');
  findingsHead.appendChild(el('h3', '', `Находки — ${result.findings.length}`));
  findingsHead.appendChild(el('span', '', 'каждая строка — отдельная сигнатура'));
  findings.appendChild(findingsHead);

  if (!result.findings.length) {
    const clean = el('div', 'clean-state');
    const mark = el('span', 'tick', '✓');
    mark.style.color = '#4ade80';
    mark.style.fontSize = '20px';
    clean.append(mark, el('span', '', 'Сигнатуры не сработали. Запускайте файл только если доверяете источнику.'));
    findings.appendChild(clean);
  }

  result.findings.forEach((finding, index) => {
    const severity = SEVERITY[finding.severity] || SEVERITY.info;
    const card = el('article', 'finding');
    card.style.setProperty('--v', severity.color);
    const cardHead = el('div', 'finding-head');
    cardHead.appendChild(el('span', 'sev-pill', severity.label));
    cardHead.appendChild(el('h4', '', `${index + 1}. ${finding.title}`));
    cardHead.appendChild(el('code', 'sig-id', finding.sig_id));
    card.appendChild(cardHead);
    card.appendChild(el('p', '', finding.description));
    if (finding.entry) card.appendChild(el('div', 'where', `Вложение: ${finding.entry}`));
    if (finding.offset) card.appendChild(el('div', 'where', `Строка: ${finding.offset}`));
    if (finding.evidence) card.appendChild(el('pre', 'evidence', finding.evidence));
    findings.appendChild(card);
  });
  body.appendChild(findings);

  if (Array.isArray(result.notes) && result.notes.length) {
    const notes = el('div');
    notes.appendChild(el('h3', '', 'Примечания'));
    const list = el('ul', 'notes-list');
    result.notes.forEach((note) => list.appendChild(el('li', '', note)));
    notes.appendChild(list);
    body.appendChild(notes);
  }

  section.appendChild(body);
  section.hidden = false;
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* -------------------------------- тарифы -------------------------------- */

function defaultOffer(plan) {
  if (state.selectedOffers[plan.id]) return state.selectedOffers[plan.id];
  const offers = plan.offers || [];
  const month = offers.find((offer) => offer.id === '1m');
  return month ? month.id : (offers[0]?.id || null);
}

function renderPricing() {
  const grid = $('#planGrid');
  if (!grid) return;
  clear(grid);
  const plans = state.plans?.plans || [];
  if (!plans.length) {
    const empty = el('div', 'empty-state');
    empty.appendChild(el('b', '', 'Не удалось загрузить тарифы'));
    empty.appendChild(el('span', '', 'Обновите страницу или проверьте соединение.'));
    grid.appendChild(empty);
    return;
  }
  const current = state.quota?.plan || state.me?.plan || null;

  plans.forEach((plan) => {
    const card = el('article', 'plan card');
    if (plan.highlighted) card.classList.add('is-featured');
    if (current === plan.id) card.classList.add('is-current');
    if (plan.highlighted) card.appendChild(el('span', 'plan-flag', 'Популярный'));

    const top = el('div', 'plan-top');
    const names = el('div');
    names.appendChild(el('h2', 'plan-name', plan.name));
    names.appendChild(el('div', 'plan-tagline', plan.tagline));
    top.appendChild(names);
    if (current === plan.id) top.appendChild(el('span', 'badge badge-ok', 'Ваш тариф'));
    card.appendChild(top);

    if (plan.is_free) {
      const price = el('div', 'plan-price');
      price.appendChild(el('b', '', '0 грн'));
      price.appendChild(el('span', '', 'бесплатно навсегда'));
      card.appendChild(price);
    } else {
      const offers = el('div', 'offer-list');
      const selected = defaultOffer(plan);
      plan.offers.forEach((offer) => {
        const row = el('button', 'offer');
        row.type = 'button';
        if (offer.id === selected) row.classList.add('is-active');
        row.appendChild(el('span', 'offer-term', offer.label));
        row.appendChild(el('span', 'offer-price', `${fmtNum(offer.price)} грн`));
        if (offer.has_discount) {
          row.appendChild(el('span', 'offer-old', `${fmtNum(offer.old_price)}`));
          row.appendChild(el('span', 'discount', `−${offer.discount_label}%`));
        }
        row.addEventListener('click', () => {
          state.selectedOffers[plan.id] = offer.id;
          Array.from(card.querySelectorAll('.offer')).forEach((item) => item.classList.remove('is-active'));
          row.classList.add('is-active');
          openPurchase(plan, offer);
        });
        offers.appendChild(row);
      });
      card.appendChild(offers);
    }

    const limits = el('div', 'plan-limits');
    (plan.allowances || []).forEach((allowance) => {
      const row = el('div', 'limit-row');
      row.appendChild(el('span', 'limit-dot'));
      row.appendChild(el('span', 'limit-model', allowance.model_name.replace('XSafety ', 'Модель ')));
      if (allowance.available) {
        const mb = allowance.mb === null ? 'без лимита' : `${allowance.mb} МБ`;
        row.appendChild(el('span', 'limit-value', `${allowance.requests} запр. · ${mb}`));
      } else {
        row.classList.add('is-off');
        row.appendChild(el('span', 'limit-value is-off', 'не входит в тариф'));
      }
      limits.appendChild(row);
    });
    card.appendChild(limits);

    const features = el('ul', 'plan-features');
    (plan.features || []).forEach((feature) => features.appendChild(el('li', '', feature)));
    card.appendChild(features);

    const cta = el('div', 'plan-cta');
    if (plan.is_free) {
      const button = el('button', 'btn btn-ghost btn-block', current === plan.id ? 'Текущий тариф' : 'Базовый доступ');
      button.type = 'button';
      button.disabled = true;
      cta.appendChild(button);
    } else {
      const selectedOfferId = defaultOffer(plan);
      const offer = (plan.offers || []).find((item) => item.id === selectedOfferId);
      const button = el('button', 'btn btn-primary btn-block', current === plan.id ? 'Продлить тариф' : 'Подключить');
      button.type = 'button';
      button.addEventListener('click', () => {
        const actualOffer = (plan.offers || []).find((item) => item.id === state.selectedOffers[plan.id]) || offer;
        openPurchase(plan, actualOffer);
      });
      cta.appendChild(button);
      cta.appendChild(el('div', 'plan-note', 'Демо-режим · оплата не списывается'));
    }
    card.appendChild(cta);
    grid.appendChild(card);
  });
}

function openPurchase(plan, offer) {
  if (!plan || !offer) return;
  if (!state.me) {
    toast('Войдите или создайте аккаунт, чтобы подключить тариф.', 'info');
    openAuth('register');
    return;
  }
  state.pendingPurchase = { plan, offer };
  state.lastFocus = document.activeElement;
  const summary = $('#purchaseSummary');
  clear(summary);

  const addRow = (label, value, className = 'row') => {
    const row = el('div', className);
    row.appendChild(el('span', '', label));
    row.appendChild(el('b', '', value));
    summary.appendChild(row);
  };
  addRow('Тариф', `${plan.name} · ${offer.label}`);
  if (offer.has_discount) {
    addRow('Обычная цена', `${fmtNum(offer.old_price)} грн`);
    addRow('Скидка', `−${offer.discount_label}% (${fmtNum(offer.saving)} грн)`);
  }
  const total = el('div', 'row total');
  const left = el('span', '', 'К оплате');
  const right = el('div');
  right.appendChild(el('b', '', `${fmtNum(offer.price)} грн`));
  if (offer.has_discount) right.appendChild(el('span', 'old', `${fmtNum(offer.old_price)}`));
  total.append(left, right);
  summary.appendChild(total);

  $('#purchaseError').hidden = true;
  $('#purchaseModal').hidden = false;
  document.body.style.overflow = 'hidden';
  setTimeout(() => $('#purchaseConfirm').focus(), 30);
}

async function confirmPurchase() {
  if (!state.pendingPurchase) return;
  const button = $('#purchaseConfirm');
  const errorNode = $('#purchaseError');
  const { plan, offer } = state.pendingPurchase;
  button.disabled = true;
  errorNode.hidden = true;
  try {
    const data = await api('/billing/purchase', { json: { plan: plan.id, offer: offer.id } });
    state.me = data.user;
    state.quota = data.quota;
    closeModal('purchase');
    renderAll();
    toast(`Тариф ${plan.name} активирован (демо).`, 'success');
  } catch (error) {
    if (error.status === 401) {
      closeModal('purchase');
      openAuth('login');
      toast('Сессия истекла — войдите снова.', 'error');
    } else {
      errorNode.textContent = error.message;
      errorNode.hidden = false;
    }
  } finally {
    button.disabled = false;
  }
}

/* -------------------------------- история -------------------------------- */

async function loadHistory(force = false) {
  const list = $('#historyList');
  if (!list) return;
  if (!state.me) {
    clear(list);
    const empty = el('div', 'empty-state');
    empty.appendChild(el('b', '', 'История доступна после входа'));
    empty.appendChild(el('span', '', 'Войдите, чтобы сохранять отчёты и возвращаться к ним.'));
    const button = el('button', 'btn btn-soft', 'Войти');
    button.type = 'button';
    button.addEventListener('click', () => openAuth('login'));
    empty.appendChild(button);
    list.appendChild(empty);
    return;
  }
  if (state.historyLoaded && !force) return;
  clear(list);
  for (let index = 0; index < 3; index += 1) list.appendChild(el('div', 'skeleton'));
  try {
    const data = await api('/scans');
    state.historyLoaded = true;
    clear(list);
    const scans = data.scans || [];
    if (!scans.length) {
      const empty = el('div', 'empty-state');
      empty.appendChild(el('b', '', 'Проверок пока нет'));
      empty.appendChild(el('span', '', 'Загрузите первый файл — отчёт появится здесь.'));
      const button = el('button', 'btn btn-soft', 'К сканеру');
      button.type = 'button';
      button.addEventListener('click', () => showView('scanner'));
      empty.appendChild(button);
      list.appendChild(empty);
      return;
    }
    scans.forEach((scan) => list.appendChild(historyItem(scan)));
  } catch (error) {
    clear(list);
    const empty = el('div', 'empty-state');
    empty.appendChild(el('b', '', 'Не удалось загрузить историю'));
    empty.appendChild(el('span', '', error.message));
    list.appendChild(empty);
  }
}

function historyItem(scan) {
  const verdict = VERDICT[scan.verdict] || VERDICT.suspicious;
  const item = el('div', 'history-item');
  const badge = el('span', `badge ${scan.verdict === 'malicious' ? 'badge-danger' : scan.verdict === 'suspicious' ? 'badge-warn' : 'badge-ok'}`, verdict.label);
  item.appendChild(badge);

  const main = el('div', 'history-main');
  main.appendChild(el('div', 'history-name', scan.filename));
  const meta = el('div', 'history-meta');
  meta.appendChild(el('span', '', modelName(scan.model)));
  meta.appendChild(el('span', '', fmtDate(scan.created_at)));
  meta.appendChild(el('span', '', fmtSize(scan.size)));
  meta.appendChild(el('span', '', `находок: ${fmtNum(scan.findings)}`));
  main.appendChild(meta);
  item.appendChild(main);

  const actions = el('div', 'history-actions');
  const open = el('a', 'btn btn-ghost btn-sm', 'Открыть');
  open.href = `${API}/scans/${encodeURIComponent(scan.id)}/report.html`;
  open.target = '_blank';
  open.rel = 'noopener noreferrer';
  const download = el('a', 'btn btn-ghost btn-sm', 'Скачать');
  download.href = `${API}/scans/${encodeURIComponent(scan.id)}/report.html?download=1`;
  download.rel = 'noopener noreferrer';
  const remove = el('button', 'btn btn-danger btn-sm', 'Удалить');
  remove.type = 'button';
  remove.addEventListener('click', async () => {
    if (!window.confirm(`Удалить отчёт «${scan.filename}»?`)) return;
    try {
      await api(`/scans/${encodeURIComponent(scan.id)}`, { method: 'DELETE' });
      item.remove();
      toast('Отчёт удалён.', 'info');
      if (!$('#historyList').children.length) state.historyLoaded = false;
    } catch (error) {
      toast(error.message, 'error');
    }
  });
  actions.append(open, download, remove);
  item.appendChild(actions);
  return item;
}

/* ------------------------------- сброс лимитов --------------------------- */

function tickClock() {
  $$('[data-reset]').forEach((node) => {
    node.textContent = timeLeft(node.dataset.reset);
  });
  if (state.quota) {
    const time = $('#refillTime');
    if (time) time.textContent = timeLeft(state.quota.resets_at);
    const diff = new Date(state.quota.resets_at).getTime() - Date.now();
    if (Number.isFinite(diff) && diff <= 0) {
      const now = Date.now();
      if (!state.lastRefillRefresh || now - state.lastRefillRefresh > 15000) {
        state.lastRefillRefresh = now;
        refreshMe();
      }
    }
  }
}

let refreshInFlight = false;
async function refreshMe() {
  if (refreshInFlight) return;
  refreshInFlight = true;
  try {
    const data = await api('/me');
    if (data.user) {
      const planChanged = !state.quota || state.quota.plan !== data.quota.plan;
      state.me = data.user;
      state.quota = data.quota;
      renderAccount();
      renderModels();
      if (planChanged) renderPricing();
    } else {
      state.me = null;
      state.quota = null;
      renderAccount();
      renderModels();
    }
  } catch (_) { /* тихо: индикаторы останутся прежними */ }
  finally {
    refreshInFlight = false;
  }
}

/* --------------------------------- события ------------------------------- */

function bindEvents() {
  $$('[data-nav]').forEach((node) => {
    node.addEventListener('click', (event) => {
      event.preventDefault();
      showView(node.dataset.nav);
    });
  });

  $('#loginBtn').addEventListener('click', () => openAuth('login'));
  $('#userChip').addEventListener('click', toggleUserMenu);
  $$('[data-close]').forEach((node) => {
    node.addEventListener('click', () => closeModal(node.dataset.close));
  });
  $$('[data-auth-tab]').forEach((tab) => {
    tab.addEventListener('click', () => setAuthMode(tab.dataset.authTab));
  });
  $('#authForm').addEventListener('submit', submitAuth);
  $('#purchaseConfirm').addEventListener('click', confirmPurchase);

  const drop = $('#dropZone');
  const input = $('#fileInput');
  drop.addEventListener('click', () => input.click());
  drop.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      input.click();
    }
  });
  ['dragenter', 'dragover'].forEach((name) => {
    drop.addEventListener(name, (event) => {
      event.preventDefault();
      drop.classList.add('is-over');
    });
  });
  ['dragleave', 'dragend'].forEach((name) => {
    drop.addEventListener(name, () => drop.classList.remove('is-over'));
  });
  drop.addEventListener('drop', (event) => {
    event.preventDefault();
    drop.classList.remove('is-over');
    const file = event.dataTransfer?.files?.[0];
    if (file) setFile(file);
  });
  input.addEventListener('change', () => {
    const file = input.files?.[0];
    if (file) setFile(file);
  });
  $('#scanBtn').addEventListener('click', startScan);

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    ['auth', 'purchase'].forEach((name) => {
      const modal = document.getElementById(`${name}Modal`);
      if (modal && !modal.hidden) closeModal(name);
    });
    document.querySelector('.user-menu')?.remove();
  });

  window.addEventListener('hashchange', routeFromHash);

  document.addEventListener('click', (event) => {
    const anchor = event.target.closest('a[data-nav]');
    if (anchor) {
      event.preventDefault();
      showView(anchor.dataset.nav);
    }
  });
}

/* --------------------------------- запуск -------------------------------- */

async function loadPlans() {
  try {
    const data = await api('/plans');
    state.plans = data;
    if (Array.isArray(data.models) && data.models.length) state.models = data.models;
    const maxRules = Math.max(0, ...state.models.map((model) => Number(model.signatures) || 0));
    $('#statRules').textContent = maxRules ? fmtNum(maxRules) : '120+';
    if (Number(data.max_upload_mb)) {
      $('#dropSub').textContent = `Форматы модели: ${state.models[0].extensions.map((ext) => `.${ext}`).join(', ')} · до ${data.max_upload_mb} МБ`;
    }
  } catch (error) {
    $('#statRules').textContent = '120+';
    toast(error.message || 'Не удалось загрузить каталог тарифов.', 'error');
  }
}

async function loadMe() {
  try {
    const data = await api('/me');
    state.me = data.user;
    state.quota = data.quota;
  } catch (error) {
    state.me = null;
    state.quota = null;
  }
}

function renderAll() {
  renderAccount();
  renderModels();
  renderPricing();
  if (state.view === 'history') loadHistory(true);
}

async function init() {
  bindEvents();
  $('#statRules').textContent = '…';
  await Promise.all([loadPlans(), loadMe()]);
  renderAll();
  routeFromHash();
  window.setInterval(tickClock, 1000);
  tickClock();
  if (state.me && state.quota) {
    setTimeout(() => {
      const blocked = (state.quota.models || []).filter((model) => model.blocked).length;
      if (blocked && state.quota.plan === 'default') {
        toast('На тарифе Default доступна только модель 1. Модели 2, 3 Lite и 3 Pro можно открыть в «Тарифах».', 'info', 8000);
      }
    }, 1200);
  }
}

document.addEventListener('DOMContentLoaded', init);
