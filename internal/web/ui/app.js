'use strict';

const $ = (s) => document.querySelector(s);
const el = (tag, props = {}, ...kids) => {
  const n = Object.assign(document.createElement(tag), props);
  n.append(...kids);
  return n;
};

const EXT = {
  image: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'avif', 'svg', 'ico', 'heic', 'heif'],
  pdf: ['pdf'],
  video: ['mp4', 'm4v', 'webm', 'mov', 'mkv', 'ogv'],
  audio: ['mp3', 'm4a', 'aac', 'wav', 'ogg', 'oga', 'opus', 'flac'],
  text: ['txt', 'md', 'markdown', 'log', 'csv', 'tsv', 'json', 'yaml', 'yml', 'toml', 'ini', 'conf',
    'cfg', 'env', 'xml', 'html', 'htm', 'css', 'js', 'ts', 'go', 'py', 'sh', 'rb', 'java', 'kt',
    'swift', 'c', 'h', 'cpp', 'rs', 'sql', 'srt', 'vtt'],
};
const ICON = { dir: '📁', image: '🖼️', pdf: '📕', video: '🎬', audio: '🎵', text: '📄', other: '📦' };
const TEXT_LIMIT = 1 << 20;

function kind(entry) {
  if (entry.dir) return 'dir';
  const ext = entry.name.includes('.') ? entry.name.split('.').pop().toLowerCase() : '';
  for (const [k, list] of Object.entries(EXT)) if (list.includes(ext)) return k;
  return 'other';
}

const state = { dir: '', entries: [], path: [], expanded: new Set(['']), closed: false };

// ---------- API ----------

async function api(url, opts) {
  let r;
  try {
    r = await fetch(url, opts);
  } catch (e) {
    showClosed();
    throw e;
  }
  if (r.status === 401 || r.status === 410) {
    showClosed();
    throw new Error('сейф закрыт');
  }
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  return r.json();
}

const post = (url, body) =>
  api(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

const fileURL = (e, dl) => `/api/file/${encodeURIComponent(e.id)}${dl ? '?dl=1' : ''}`;

// ---------- UI helpers ----------

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 5000);
}

function size(n) {
  if (n < 1024) return `${n} Б`;
  const u = ['КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return `${n.toFixed(n < 10 ? 1 : 0)} ${u[i]}`;
}

const dateFmt = new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'short' });

function showClosed() {
  if (state.closed) return;
  state.closed = true;
  closeViewer();
  $('#closed').hidden = false;
}

// ---------- Navigation ----------

async function open(dir) {
  const data = await api(`/api/list?dir=${encodeURIComponent(dir)}`);
  state.dir = dir;
  state.entries = data.entries;
  state.path = data.path;
  state.expanded.add('');
  for (const p of data.path) state.expanded.add(p.id);
  if (location.hash.slice(1) !== dir) history.replaceState(null, '', '#' + dir);
  renderCrumbs();
  renderRows();
  renderTree();
}

const refresh = () => open(state.dir).catch((e) => toast(e.message));

function go(dir) {
  if (dir === state.dir) return refresh();
  history.pushState(null, '', '#' + dir);
  open(dir).catch((e) => toast(e.message));
}

window.addEventListener('popstate', () => open(location.hash.slice(1)).catch(() => open('')));

function renderCrumbs() {
  const items = [{ id: '', name: 'Сейф' }, ...state.path];
  $('#crumbs').replaceChildren(...items.map((p) => {
    const a = el('a', { href: '#' + p.id, textContent: p.name });
    a.onclick = (ev) => { ev.preventDefault(); go(p.id); };
    return el('li', {}, a);
  }));
  document.title = (state.path.length ? state.path.at(-1).name + ' — ' : '') + 'Сейф';
}

function renderRows() {
  $('#empty').hidden = state.entries.length > 0;
  $('#rows').replaceChildren(...state.entries.map((e) => {
    const k = kind(e);
    const link = el('a', { href: e.dir ? '#' + e.id : fileURL(e) },
      el('span', { className: 'icon', textContent: ICON[k] }), el('span', { textContent: e.name }));
    link.onclick = (ev) => { ev.preventDefault(); e.dir ? go(e.id) : openViewer(e); };

    const ops = el('td', { className: 'ops' });
    if (!e.dir) ops.append(el('a', { className: 'button', href: fileURL(e, true), textContent: 'Скачать' }), ' ');
    const ren = el('button', { type: 'button', textContent: 'Переименовать' });
    ren.onclick = () => rename(e);
    const del = el('button', { type: 'button', className: 'danger', textContent: 'Удалить' });
    del.onclick = () => remove(e);
    ops.append(ren, ' ', del);

    return el('tr', {},
      el('td', { className: 'name' }, link),
      el('td', { className: 'num', textContent: e.dir ? '' : size(e.size) }),
      el('td', { className: 'date', textContent: dateFmt.format(new Date(e.modified)) }),
      ops);
  }));
}

// ---------- Folder tree ----------

async function renderTree() {
  const build = async (id, name) => {
    const open = state.expanded.has(id);
    let kids = [];
    if (open) {
      const data = id === state.dir ? { entries: state.entries } : await api(`/api/list?dir=${encodeURIComponent(id)}`);
      kids = data.entries.filter((e) => e.dir);
    }
    const twist = el('button', { type: 'button', className: 'twist', textContent: open ? '▾' : '▸',
      ariaLabel: open ? 'Свернуть' : 'Развернуть' });
    if (open && !kids.length && id !== '') twist.classList.add('leaf');
    twist.onclick = () => {
      state.expanded.has(id) ? state.expanded.delete(id) : state.expanded.add(id);
      renderTree();
    };
    const a = el('a', { href: '#' + id, textContent: (id === '' ? '🔒 ' : '📁 ') + name });
    a.onclick = (ev) => { ev.preventDefault(); go(id); };
    const node = el('div', { className: 'node' + (id === state.dir ? ' current' : '') }, twist, a);
    const li = el('li', {}, node);
    if (kids.length) li.append(el('ul', {}, ...(await Promise.all(kids.map((k) => build(k.id, k.name))))));
    return li;
  };
  try {
    $('#tree').replaceChildren(el('ul', {}, await build('', 'Сейф')));
  } catch { /* a folder vanished mid-render; the next refresh redraws */ }
}

// ---------- Actions ----------

async function mkdir() {
  const name = prompt('Название новой папки:');
  if (!name || !name.trim()) return;
  try {
    await post('/api/mkdir', { dir: state.dir, name });
    refresh();
  } catch (e) { toast(e.message); }
}

async function rename(e) {
  const name = prompt('Новое имя:', e.name);
  if (!name || name === e.name) return;
  try {
    await post('/api/rename', { id: e.id, name });
    refresh();
  } catch (err) { toast(err.message); }
}

async function remove(e) {
  const what = e.dir ? `папку «${e.name}» со всем содержимым` : `файл «${e.name}»`;
  if (!confirm(`Удалить ${what}? Это необратимо.`)) return;
  try {
    await post('/api/delete', { id: e.id });
    state.expanded.delete(e.id);
    refresh();
  } catch (err) { toast(err.message); }
}

async function closeVault() {
  if (!confirm('Закрыть сейф? Программа завершится, файлы снова будут доступны только по паролю.')) return;
  try { await post('/api/close', {}); } catch { /* already gone */ }
  showClosed();
}

// ---------- Upload ----------

const queue = [];
let uploading = false;

function enqueue(items) {
  // items: [{file, path}] where path is relative to the current folder.
  const dir = state.dir;
  for (const it of items) queue.push({ ...it, dir });
  if (!uploading) runQueue();
}

function sendOne(item, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `/api/upload?dir=${encodeURIComponent(item.dir)}&path=${encodeURIComponent(item.path)}`);
    xhr.upload.onprogress = (ev) => ev.lengthComputable && onProgress(ev.loaded);
    xhr.onload = () => (xhr.status < 300 ? resolve() : reject(new Error(xhr.responseText.trim() || xhr.statusText)));
    xhr.onerror = () => reject(new Error('связь с программой потеряна'));
    xhr.send(item.file);
  });
}

async function runQueue() {
  uploading = true;
  const box = $('#uploads');
  box.hidden = false;
  let done = 0, failed = 0;
  while (queue.length) {
    const item = queue.shift();
    const total = done + failed + queue.length + 1;
    const setText = (pct) =>
      ($('#uploads-text').textContent = `Шифрую ${done + failed + 1} из ${total}: ${item.path}${pct != null ? ` — ${pct}%` : ''}`);
    setText();
    $('#uploads-bar').style.width = '0';
    try {
      await sendOne(item, (loaded) => {
        const pct = item.file.size ? Math.round((loaded / item.file.size) * 100) : 100;
        $('#uploads-bar').style.width = pct + '%';
        setText(pct);
      });
      done++;
    } catch (e) {
      failed++;
      toast(`${item.path}: ${e.message}`);
      if (state.closed) break;
    }
    if (item.dir === state.dir) refresh();
  }
  uploading = false;
  box.hidden = true;
  refresh();
  if (failed) toast(`Не загружено файлов: ${failed}`);
}

$('#btn-upload').onclick = () => $('#pick-files').click();
$('#btn-upload-dir').onclick = () => $('#pick-dir').click();
$('#pick-files').onchange = (ev) => {
  enqueue([...ev.target.files].map((f) => ({ file: f, path: f.name })));
  ev.target.value = '';
};
$('#pick-dir').onchange = (ev) => {
  enqueue([...ev.target.files].map((f) => ({ file: f, path: f.webkitRelativePath || f.name })));
  ev.target.value = '';
};

// Drag and drop, folders included.
async function collect(entry, prefix, out) {
  if (entry.isFile) {
    const file = await new Promise((res, rej) => entry.file(res, rej));
    out.push({ file, path: prefix + file.name });
  } else if (entry.isDirectory) {
    const reader = entry.createReader();
    let batch;
    do {
      batch = await new Promise((res, rej) => reader.readEntries(res, rej));
      for (const child of batch) await collect(child, prefix + entry.name + '/', out);
    } while (batch.length);
  }
}

let dragDepth = 0;
document.addEventListener('dragenter', (ev) => {
  if (!ev.dataTransfer?.types.includes('Files')) return;
  dragDepth++;
  $('#drop').hidden = false;
});
document.addEventListener('dragleave', () => {
  if (--dragDepth <= 0) { dragDepth = 0; $('#drop').hidden = true; }
});
document.addEventListener('dragover', (ev) => ev.preventDefault());
document.addEventListener('drop', async (ev) => {
  ev.preventDefault();
  dragDepth = 0;
  $('#drop').hidden = true;
  const entries = [...ev.dataTransfer.items].map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  const out = [];
  if (entries.length) {
    for (const en of entries) await collect(en, '', out);
  } else {
    for (const f of ev.dataTransfer.files) out.push({ file: f, path: f.name });
  }
  if (out.length) enqueue(out);
});

// ---------- Viewer ----------

let viewing = null;

async function openViewer(e) {
  viewing = e;
  const k = kind(e);
  $('#viewer-name').textContent = e.name;
  $('#viewer-dl').href = fileURL(e, true);
  const body = $('#viewer-body');
  body.replaceChildren();
  $('#viewer').hidden = false;
  const url = fileURL(e);
  const cantShow = (why) => body.replaceChildren(el('div', { className: 'note' },
    el('p', { textContent: why }),
    el('p', { textContent: '«Скачать» сохранит расшифрованную копию на этот компьютер — после работы её стоит удалить.' })));

  if (k === 'image') {
    const img = el('img', { src: url, alt: e.name });
    img.onerror = () => cantShow('Браузер не умеет показывать этот формат изображений.');
    body.append(img);
  } else if (k === 'pdf') {
    body.append(el('iframe', { src: url, title: e.name }));
  } else if (k === 'video' || k === 'audio') {
    const m = el(k, { src: url, controls: true, autoplay: true, preload: 'metadata' });
    m.onerror = () => cantShow('Браузер не умеет воспроизводить этот формат.');
    body.append(m);
  } else if (k === 'text') {
    try {
      const r = await fetch(url, { headers: { Range: `bytes=0-${TEXT_LIMIT - 1}` } });
      if (!r.ok) throw new Error((await r.text()).trim());
      const text = new TextDecoder('utf-8').decode(await r.arrayBuffer());
      if (viewing !== e) return;
      const pre = el('pre', { textContent: text });
      if (e.size > TEXT_LIMIT) pre.append(`\n\n… показан первый 1 МБ из ${size(e.size)}`);
      body.replaceChildren(pre);
    } catch (err) { cantShow(`Не удалось открыть: ${err.message}`); }
  } else {
    cantShow('Этот тип файла браузер показать не может.');
  }
}

function closeViewer() {
  viewing = null;
  $('#viewer').hidden = true;
  $('#viewer-body').replaceChildren(); // stops media playback
}

function step(delta) {
  if (!viewing) return;
  const files = state.entries.filter((e) => !e.dir);
  const i = files.findIndex((e) => e.id === viewing.id);
  const next = files[(i + delta + files.length) % files.length];
  if (next) openViewer(next);
}

$('#viewer-close').onclick = closeViewer;
$('#viewer-prev').onclick = () => step(-1);
$('#viewer-next').onclick = () => step(1);
document.addEventListener('keydown', (ev) => {
  if ($('#viewer').hidden) return;
  if (ev.key === 'Escape') closeViewer();
  else if (ev.key === 'ArrowLeft' && !(ev.target instanceof HTMLMediaElement)) step(-1);
  else if (ev.key === 'ArrowRight' && !(ev.target instanceof HTMLMediaElement)) step(1);
});

// ---------- Start ----------

$('#btn-mkdir').onclick = mkdir;
$('#btn-close').onclick = closeVault;

// Notice when the program is stopped from the terminal (Ctrl+C).
setInterval(() => {
  if (!state.closed && !uploading) fetch('/api/list?dir=').then((r) => r.status === 401 && showClosed(), showClosed);
}, 4000);

open(location.hash.slice(1)).catch(() => open('').catch((e) => toast(e.message)));
