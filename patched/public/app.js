let token = localStorage.getItem('token_patched');
let currentUser = JSON.parse(localStorage.getItem('user_patched') || 'null');

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showTab(tab) {
  document.getElementById('login-tab').style.display = tab === 'login' ? 'block' : 'none';
  document.getElementById('register-tab').style.display = tab === 'register' ? 'block' : 'none';
  document.getElementById('btn-tab-login').classList.toggle('active', tab === 'login');
  document.getElementById('btn-tab-register').classList.toggle('active', tab === 'register');
}

function setMsg(id, text, type) {
  const el = document.getElementById(id);
  el.className = `msg ${type}`;
  el.textContent = text;
}

async function doLogin() {
  const username = document.getElementById('login-user').value;
  const password = document.getElementById('login-pass').value;
  const res = await fetch('/api/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  const data = await res.json();
  if (!res.ok) { setMsg('login-msg', data.error, 'error'); return; }
  token = data.token;
  currentUser = data.user;
  localStorage.setItem('token_patched', token);
  localStorage.setItem('user_patched', JSON.stringify(currentUser));
  location.reload();
}

async function doRegister() {
  const username = document.getElementById('reg-user').value;
  const password = document.getElementById('reg-pass').value;
  const res = await fetch('/api/register', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  const data = await res.json();
  setMsg('reg-msg', res.ok ? 'Registered! Please login.' : data.error, res.ok ? 'success' : 'error');
}

async function loadTasks() {
  const res = await fetch('/api/tasks', { headers: { Authorization: `Bearer ${token}` } });
  const tasks = await res.json();
  const list = document.getElementById('task-list');
  if (!tasks.length) { list.innerHTML = '<p style="color:#888;font-size:0.85rem">No tasks yet.</p>'; return; }
  // FIX: escapeHTML on all user data; data-task-id used for event delegation (no onclick)
  list.innerHTML = tasks.map(t => `
    <div class="task-item">
      <div class="task-body">
        <div class="task-id">ID: ${t.id}</div>
        <div class="task-title">${escapeHTML(t.title)}</div>
        <div class="task-desc">${escapeHTML(t.description || '')}</div>
      </div>
      <button class="danger" data-task-id="${t.id}" style="margin-left:12px;padding:5px 12px;font-size:0.8rem">Delete</button>
    </div>
  `).join('');
}

async function createTask() {
  const title = document.getElementById('task-title').value;
  const description = document.getElementById('task-desc').value;
  const res = await fetch('/api/tasks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ title, description })
  });
  const data = await res.json();
  if (!res.ok) { setMsg('task-msg', data.error, 'error'); return; }
  document.getElementById('task-title').value = '';
  document.getElementById('task-desc').value = '';
  loadTasks();
}

async function deleteTask(id) {
  await fetch(`/api/tasks/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });
  loadTasks();
}

async function fetchById() {
  const id = document.getElementById('idor-id').value;
  const res = await fetch(`/api/tasks/${id}`, { headers: { Authorization: `Bearer ${token}` } });
  const data = await res.json();
  const el = document.getElementById('idor-result');
  el.textContent = JSON.stringify(data, null, 2);
  el.style.cssText = `background:${res.ok ? '#e8f5e9' : '#fdecea'};padding:10px;border-radius:6px`;
}

async function uploadFile() {
  const fileInput = document.getElementById('file-input');
  if (!fileInput.files[0]) { setMsg('upload-msg', 'Select a file first', 'error'); return; }
  const form = new FormData();
  form.append('file', fileInput.files[0]);
  const res = await fetch('/api/upload', {
    method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: form
  });
  const data = await res.json();
  setMsg('upload-msg', res.ok ? `Uploaded: ${escapeHTML(data.originalName)}` : data.error, res.ok ? 'success' : 'error');
}

function init() {
  if (token) {
    document.getElementById('app-section').style.display = 'block';
    document.getElementById('user-info').textContent = `Logged in as: ${currentUser?.username}`;
    loadTasks();

    document.getElementById('btn-add-task').addEventListener('click', createTask);
    document.getElementById('btn-fetch').addEventListener('click', fetchById);
    document.getElementById('btn-upload').addEventListener('click', uploadFile);
    document.getElementById('btn-logout').addEventListener('click', () => {
      localStorage.removeItem('token_patched');
      localStorage.removeItem('user_patched');
      location.reload();
    });
    // Event delegation for dynamically generated delete buttons
    document.getElementById('task-list').addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-task-id]');
      if (btn) deleteTask(Number(btn.dataset.taskId));
    });
  } else {
    document.getElementById('auth-section').style.display = 'block';

    document.getElementById('btn-tab-login').addEventListener('click', () => showTab('login'));
    document.getElementById('btn-tab-register').addEventListener('click', () => showTab('register'));
    document.getElementById('btn-login').addEventListener('click', doLogin);
    document.getElementById('btn-register').addEventListener('click', doRegister);
  }
}

init();
