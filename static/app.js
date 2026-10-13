var $ = function(s){ return document.querySelector(s); };
var $$ = function(s){ return document.querySelectorAll(s); };
var esc = function(s){ return (s||'').replace(/[&<>"']/g, function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
}); };
var fmtTime = function(t){ return new Date(t*1000).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'}); };
var fmtDay = function(t){
  var d = new Date(t*1000), n = new Date();
  if (d.toDateString()===n.toDateString()) return fmtTime(t);
  var y = new Date(n); y.setDate(y.getDate()-1);
  if (d.toDateString()===y.toDateString()) return 'вчера';
  return d.toLocaleDateString('ru-RU',{day:'2-digit',month:'2-digit'});
};
var fmtSize = function(n){ return n<1024?n+' Б':n<1048576?(n/1024).toFixed(1)+' КБ':(n/1048576).toFixed(1)+' МБ'; };
var initial = function(s){ return ((s||'?').trim()[0]||'?').toUpperCase(); };
var fmtDur = function(s){ s=Math.round(s||0); return (s/60|0)+':'+('0'+(s%60)).slice(-2); };
var fmtStatus = function(st, lastSeen){
  if (st === 'online') return 'в сети';
  if (st === 'dnd') return 'не беспокоить';
  if (!lastSeen) return 'был(а) недавно';
  var d = new Date(lastSeen*1000), n = new Date();
  if (d.toDateString() === n.toDateString()) return 'был(а) в ' + fmtTime(lastSeen);
  return 'был(а) ' + d.toLocaleDateString('ru-RU',{day:'2-digit',month:'2-digit'});
};
var EMOJIS = ['👍','❤️','😂','🔥','😢','😮'];
var APP_VERSION = '2.3';

/* ---------- E2E для секретных чатов (ECDH P-256 + AES-GCM) ---------- */
var SECRET_KEYS = {};
var SECRET_PENDING = {};

function b64FromBuf(buf){
  var s = '';
  var u = new Uint8Array(buf);
  for (var i=0; i<u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}
function bufFromB64(b64){
  var bin = atob(b64);
  var u = new Uint8Array(bin.length);
  for (var i=0; i<bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

function ensureSecretKey(chatId){
  if (SECRET_KEYS[chatId]) return Promise.resolve(SECRET_KEYS[chatId]);
  if (SECRET_PENDING[chatId]) return SECRET_PENDING[chatId];
  SECRET_PENDING[chatId] = (function(){
    var priv = null, pub = null;
    var myPrivJwk = null, myPubJwk = null;
    try {
      myPrivJwk = localStorage.getItem('sk_priv_' + chatId);
      myPubJwk = localStorage.getItem('sk_pub_' + chatId);
    } catch(e){}
    var p = Promise.resolve();
    if (myPrivJwk && myPubJwk){
      p = Promise.all([
        crypto.subtle.importKey('jwk', JSON.parse(myPrivJwk),
          {name:'ECDH', namedCurve:'P-256'}, true, ['deriveKey','deriveBits']),
        crypto.subtle.importKey('jwk', JSON.parse(myPubJwk),
          {name:'ECDH', namedCurve:'P-256'}, true, [])
      ]).then(function(r){ priv = r[0]; pub = r[1]; })
        .catch(function(){ priv = null; pub = null; });
    }
    return p.then(function(){
      if (priv && pub) return;
      return crypto.subtle.generateKey(
        {name:'ECDH', namedCurve:'P-256'}, true, ['deriveKey','deriveBits']
      ).then(function(pair){
        priv = pair.privateKey; pub = pair.publicKey;
        return Promise.all([
          crypto.subtle.exportKey('jwk', priv),
          crypto.subtle.exportKey('jwk', pub)
        ]);
      }).then(function(jwks){
        try {
          localStorage.setItem('sk_priv_' + chatId, JSON.stringify(jwks[0]));
          localStorage.setItem('sk_pub_' + chatId, JSON.stringify(jwks[1]));
        } catch(e){}
      });
    }).then(function(){
      return crypto.subtle.exportKey('jwk', pub);
    }).then(function(pubJwk){
      return api('/api/chats/' + chatId + '/secret_key',
        {method:'POST', body:{wrapped: JSON.stringify(pubJwk)}});
    }).then(function(){
      return api('/api/chats/' + chatId + '/secret_key');
    }).then(function(r){
      if (!r || !r.wrapped){
        SECRET_PENDING[chatId] = null;
        return null;
      }
      var peerJwk = JSON.parse(r.wrapped);
      return crypto.subtle.importKey('jwk', peerJwk,
        {name:'ECDH', namedCurve:'P-256'}, true, []);
    }).then(function(peerPub){
      if (!peerPub) return null;
      return crypto.subtle.deriveBits({name:'ECDH', public: peerPub}, priv, 256);
    }).then(function(bits){
      if (!bits) return null;
      return crypto.subtle.importKey('raw', bits, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
    }).then(function(aesKey){
      if (aesKey) SECRET_KEYS[chatId] = aesKey;
      SECRET_PENDING[chatId] = null;
      return aesKey;
    }).catch(function(e){
      SECRET_PENDING[chatId] = null;
      throw e;
    });
  })();
  return SECRET_PENDING[chatId];
}

function encryptSecret(chatId, text){
  return ensureSecretKey(chatId).then(function(key){
    if (!key) throw new Error('Собеседник ещё не открыл секретный чат');
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt(
      {name:'AES-GCM', iv: iv}, key, new TextEncoder().encode(text)
    ).then(function(ct){
      var ctArr = new Uint8Array(ct);
      var buf = new Uint8Array(iv.length + ctArr.length);
      buf.set(iv, 0); buf.set(ctArr, iv.length);
      return b64FromBuf(buf.buffer);
    });
  });
}

function decryptSecret(chatId, b64){
  return ensureSecretKey(chatId).then(function(key){
    if (!key) return '[нет ключа — собеседник ещё не подключился]';
    try {
      var raw = bufFromB64(b64);
      var iv = raw.slice(0, 12);
      var data = raw.slice(12);
      return crypto.subtle.decrypt({name:'AES-GCM', iv: iv}, key, data)
        .then(function(pt){ return new TextDecoder().decode(pt); })
        .catch(function(){ return '[не удалось расшифровать]'; });
    } catch(e){
      return '[не удалось расшифровать]';
    }
  });
}

/* ---------- Утилиты ---------- */
function onceTap(el, fn){
  if (!el) return;
  var fired = 0;
  function run(e){
    var now = Date.now();
    if (now - fired < 350){ if (e && e.cancelable) e.preventDefault(); return; }
    fired = now; fn.call(el, e);
  }
  el.addEventListener('touchend', function(e){
    if (e.cancelable && e.preventDefault) e.preventDefault(); run(e);
  }, {passive:false});
  el.addEventListener('click', run);
}

function devCheck(){ return ''; }
function officialCheck(){ return '<span class="official-check">✔</span>'; }

function api(url, opts){
  opts = opts || {};
  var o = Object.assign({credentials:'same-origin', cache:'no-store'}, opts);
  if (o.body && !(o.body instanceof FormData) && typeof o.body !== 'string'){
    o.body = JSON.stringify(o.body);
  }
  if (o.body && !(o.body instanceof FormData)) {
    o.headers = Object.assign({'Content-Type':'application/json'}, o.headers||{});
  }
  return fetch(url, o).then(function(r){
    var ct = r.headers.get('content-type')||'';
    return (ct.indexOf('json')>=0 ? r.json() : Promise.resolve(null)).then(function(d){
      if (!r.ok){
        var err = new Error((d && d.error) || ('HTTP '+r.status));
        err.status = r.status; throw err;
      }
      return d;
    });
  });
}

function applyTheme(t){
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('theme', t); } catch(e){}
}
try { applyTheme(localStorage.getItem('theme') || 'dark'); } catch(e){ applyTheme('dark'); }

var ME = null, CHATS = [], FOLDERS = [], ACTIVE = null, ACTIVE_FOLDER = 0;
var LAST_ID = 0, POLL = null, SCREEN = 'chats';
var WALLPAPER = 'default', STICKERS_OPEN = false, ACTIVE_PACK_ID = null;
var REC = null, REC_CHUNKS = [], REC_START = 0, REC_TIMER = null;
var REPLY_TO = null, LAST_TYPING_SENT = 0;
var CURRENT_PEER = null, LAST_TYPING_NAMES = [];
var SLOW_COOLDOWN = 0, SLOW_TIMER = null;
var INVITE_HASH = null;

var PC = null, LOCAL_STREAM = null, CALL_ID = null, CALL_POLL = null;
var CALL_ROLE = null;

var WALLPAPERS = {
  'default': '',
  'dark':    '#0e1621',
  'blue':    'linear-gradient(135deg,#182a42 0%,#0e1621 100%)',
  'green':   'linear-gradient(135deg,#1e2e21 0%,#0e1621 100%)',
  'purple':  'linear-gradient(135deg,#2a1e3a 0%,#0e1621 100%)',
  'warm':    'linear-gradient(135deg,#2a1e1e 0%,#0e1621 100%)'
};

function showScreen(name){
  SCREEN = name;
  var arr = $$('.screen');
  for (var i=0; i<arr.length; i++)
    arr[i].classList.toggle('active', arr[i].getAttribute('data-screen') === name);
}
function bindBacks(){
  var arr = $$('[data-back]');
  for (var i=0; i<arr.length; i++){
    (function(el){ onceTap(el, function(){ showScreen('chats'); }); })(arr[i]);
  }
}
function openDrawer(){ $('#drawer').classList.add('open'); $('#backdrop').classList.add('show'); }
function closeDrawer(){ $('#drawer').classList.remove('open'); $('#backdrop').classList.remove('show'); }

/* ---------- AUTH ---------- */
function showAuth(){
  $('#app').classList.add('hidden');
  var a = $('#auth'); a.classList.remove('hidden');
  a.innerHTML = '<div class="auth-card">'
    + '<img src="/static/icon.svg" class="auth-logo" alt="">'
    + '<h1>Голубь</h1>'
    + '<p class="auth-sub">Локальный мессенджер с шифрованием</p>'
    + '<div class="tabs">'
    + '<button class="tab active" data-mode="login">Вход</button>'
    + '<button class="tab" data-mode="register">Регистрация</button>'
    + '</div>'
    + '<form id="auth-form">'
    + '<div class="field hidden" data-name><input name="name" placeholder="Имя"></div>'
    + '<div class="field"><input name="username" placeholder="Юзернейм" required></div>'
    + '<div class="username-hint" id="un-hint-reg"></div>'
    + '<div class="field"><input name="password" type="password" placeholder="Пароль" required></div>'
    + '<div class="err" id="auth-err"></div>'
    + '<button class="primary-btn" type="submit">Войти</button>'
    + '</form></div>';
  var mode = 'login';
  var tabs = a.querySelectorAll('.tab');
  for (var i=0; i<tabs.length; i++){
    (function(tab){
      onceTap(tab, function(){
        mode = tab.getAttribute('data-mode');
        var tt = a.querySelectorAll('.tab');
        for (var j=0; j<tt.length; j++) tt[j].classList.toggle('active', tt[j]===tab);
        a.querySelector('[data-name]').classList.toggle('hidden', mode !== 'register');
        a.querySelector('.primary-btn').textContent = mode==='register' ? 'Создать аккаунт' : 'Войти';
      });
    })(tabs[i]);
  }
  var unInput = a.querySelector('[name=username]');
  var unTimer = null;
  unInput.addEventListener('input', function(){
    if (mode !== 'register') return;
    clearTimeout(unTimer);
    var v = unInput.value.trim().replace(/^@/,'');
    var hint = a.querySelector('#un-hint-reg');
    if (v.length < 3){ hint.textContent = ''; return; }
    unTimer = setTimeout(function(){
      api('/api/check_username?u=' + encodeURIComponent(v)).then(function(r){
        hint.className = 'username-hint ' + (r.available ? 'ok' : 'bad');
        hint.textContent = (r.available ? '✓ ' : '✗ ') + r.reason;
      }).catch(function(){ hint.textContent = ''; });
    }, 400);
  });
  a.querySelector('#auth-form').onsubmit = function(ev){
    ev.preventDefault();
    var f = ev.target;
    var body = {username: f.username.value, password: f.password.value};
    if (mode === 'register') body.name = f.name.value;
    api('/api/'+mode, {method:'POST', body: body})
      .then(function(){ return api('/api/me'); })
      .then(function(u){ ME = u; start(); })
      .catch(function(e){ $('#auth-err').textContent = e.message; });
  };
}

function boot(){
  INVITE_HASH = (location.pathname.match(/^\/j\/([^\/]+)/) || [])[1] || null;

  // Защита: если уже перезагружались из-за версии в этой сессии — не повторяем
  var reloaded = false;
  try { reloaded = sessionStorage.getItem('ver_reloaded') === '1'; } catch(e){}

  api('/api/version').then(function(v){
    if (v && v.version && v.version !== APP_VERSION && !reloaded){
      try { sessionStorage.setItem('ver_reloaded', '1'); } catch(e){}
      try {
        if (window.caches && caches.keys) caches.keys().then(function(ks){ ks.forEach(function(k){ caches.delete(k); }); });
        if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations)
          navigator.serviceWorker.getRegistrations().then(function(rs){ rs.forEach(function(r){ r.unregister(); }); });
      } catch(e){}
      location.replace(location.pathname + '?v=' + Date.now());
      return;
    }
    // Версия совпала или уже перезагружались — просто продолжаем
    try { sessionStorage.removeItem('ver_reloaded'); } catch(e){}
    api('/api/me').then(function(u){ ME = u; start(); }).catch(function(){ showAuth(); });
  }).catch(function(){
    // Если /api/version не отвечает — не зацикливаемся, просто запускаем
    api('/api/me').then(function(u){ ME = u; start(); }).catch(function(){ showAuth(); });
  });
}

function start(){
  $('#auth').classList.add('hidden');
  $('#app').classList.remove('hidden');
  showScreen('chats');
  fillDrawerUser();
  Promise.all([loadChats(), loadFolders()]).then(function(){
    renderChatList(); renderFolderTabs();
  });
  if (INVITE_HASH) joinInvite(INVITE_HASH);
  if (POLL) clearInterval(POLL);
  POLL = setInterval(tick, 2000);
  startIncomingCallPoll();
  setInterval(checkNotifications, 5000);
}

function fillDrawerUser(){
  var av = ME.avatar ? '<img src="/api/avatars/'+ME.avatar+'">' : initial(ME.name);
  $('#du-avatar').innerHTML = av;
  $('#du-name').textContent = ME.name;
  $('#du-user').textContent = '@' + ME.username;
}

function tick(){
  loadChats().then(function(){ if (SCREEN === 'chats') renderChatList(); }).catch(function(){});
  if (SCREEN === 'chat' && ACTIVE) pollMessages().catch(function(){});
}

document.addEventListener('visibilitychange', function(){
  if (!document.hidden && ME){
    loadChats().then(function(){ if (SCREEN === 'chats') renderChatList(); }).catch(function(){});
    if (SCREEN === 'chat' && ACTIVE) pollMessages().catch(function(){});
  }
});

function onDrawerClick(btn){
  var act = btn.getAttribute('data-act');
  closeDrawer();
  if (act === 'profile'){ renderProfileEdit(); showScreen('profile'); }
  else if (act === 'about'){ renderAbout(); showScreen('about'); }
  else if (act === 'settings'){ renderSettings(); showScreen('settings'); }
  else if (act === 'folders'){ renderFoldersScreen(); showScreen('folders'); }
  else if (act === 'logout'){
    api('/api/logout', {method:'POST'}).catch(function(){}).then(function(){ location.reload(); });
  }
}

function loadChats(){ return api('/api/chats').then(function(r){ CHATS = r; }); }
function loadFolders(){ return api('/api/folders').then(function(r){ FOLDERS = r; }); }

function renderFolderTabs(){
  var box = $('#folders-tabs');
  var html = '<button class="folder-tab'+(ACTIVE_FOLDER===0?' on':'')+'" data-fid="0">Все</button>';
  FOLDERS.forEach(function(f){
    html += '<button class="folder-tab'+(ACTIVE_FOLDER===f.id?' on':'')+'" data-fid="'+f.id+'">'+esc(f.name)+'</button>';
  });
  box.innerHTML = html;
  var ts = box.querySelectorAll('.folder-tab');
  for (var i=0; i<ts.length; i++){
    (function(t){
      onceTap(t, function(){
        ACTIVE_FOLDER = parseInt(t.getAttribute('data-fid'),10) || 0;
        renderFolderTabs(); renderChatList();
      });
    })(ts[i]);
  }
}

function renderChatList(){
  var list = $('#chat-list');
  var q = ($('#q').value || '').toLowerCase().trim();
  var items = CHATS.slice();
  if (ACTIVE_FOLDER){
    var f = null;
    for (var k=0; k<FOLDERS.length; k++) if (FOLDERS[k].id === ACTIVE_FOLDER) f = FOLDERS[k];
    if (f) items = items.filter(function(c){ return f.chat_ids.indexOf(c.id) >= 0; });
  }
  if (q) items = items.filter(function(c){ return (c.title||'').toLowerCase().indexOf(q)>=0; });
  if (!items.length){
    list.innerHTML = '<div class="empty-list">'+(q ? 'Ничего не найдено' : 'Нет чатов.<br>Нажмите ✎ чтобы создать.')+'</div>';
    return;
  }
  list.innerHTML = '';
  items.forEach(function(c){
    var el = document.createElement('div');
    el.className = 'chat-item';
    var av = c.avatar ? '<img src="/api/avatars/'+c.avatar+'">' : initial(c.title);
    var chip = c.type !== 'dm' ? '<span class="ci-chip">'+(c.type==='group'?'группа':(c.type==='channel'?'канал':'секрет'))+'</span>' : '';
    if (c.is_secret) chip = '<span class="ci-chip">🔒 секрет</span>';
    var statusDot = '';
    if (c.type === 'dm' && c.peer_status){
      statusDot = '<span class="status-inline '+c.peer_status+'"><span class="dot"></span></span>';
    }
    var preview = '<i>нет сообщений</i>', time = '';
    if (c.last){
      if (c.last.is_secret) preview = '<b>'+esc(c.last.sender)+':</b> 🔒';
      else if (c.last.is_sticker) preview = '<b>'+esc(c.last.sender)+':</b> стикер';
      else if (c.last.is_voice) preview = '<b>'+esc(c.last.sender)+':</b> голосовое';
      else if (c.last.text) preview = '<b>'+esc(c.last.sender)+':</b> '+esc(c.last.text);
      else if (c.last.file) preview = '<b>'+esc(c.last.sender)+':</b> файл';
      time = fmtDay(c.last.created);
    }
    if (c.typing && c.typing.length){
      preview = '<span class="typing-inline">'+esc(c.typing.join(', '))+' печата'+(c.typing.length>1?'ют':'ет')+'...</span>';
    }
    el.innerHTML = '<div class="ci-av">'+av+'</div>'
      + '<div class="ci-meta">'
      + '<div class="ci-row1"><span class="ci-name">'+esc(c.title)+statusDot+'</span><span class="ci-time">'+time+'</span></div>'
      + '<div class="ci-row2"><span class="ci-preview">'+preview+'</span>'+chip+'</div></div>';
    onceTap(el, function(){ openChat(c.id); });
    list.appendChild(el);
  });
}

function applyWallpaper(){ $('#messages').style.background = WALLPAPERS[WALLPAPER] || ''; }

function updateChatHeaderStatus(){
  var sub = $('#chat-sub'); if (!sub) return;
  if (LAST_TYPING_NAMES.length){
    sub.className = 'chat-sub typing-active';
    sub.textContent = LAST_TYPING_NAMES.join(', ')+' печата'+(LAST_TYPING_NAMES.length>1?'ют':'ет')+'...';
    return;
  }
  sub.className = 'chat-sub';
  var c = null; for (var i=0; i<CHATS.length; i++) if (CHATS[i].id === ACTIVE) c = CHATS[i];
  if (c && c.type === 'secret'){
    sub.textContent = SECRET_KEYS[ACTIVE] ? '🔒 секретный чат · E2E' : '🔒 ожидание ключа собеседника…';
    return;
  }
  if (CURRENT_PEER) sub.textContent = fmtStatus(CURRENT_PEER.status, CURRENT_PEER.last_seen);
  else sub.textContent = c ? (c.type==='dm'?'был(а) недавно':(c.type==='group'?'группа':(c.type==='channel'?'канал':''))) : '';
}

function openChat(id){
  ACTIVE = id; LAST_ID = 0; closeStickers(); clearReply();
  LAST_TYPING_NAMES = []; CURRENT_PEER = null;
  var c = null; for (var i=0; i<CHATS.length; i++) if (CHATS[i].id === id) c = CHATS[i];
  if (!c) c = {title:'Чат'};
  $('#chat-avatar').innerHTML = c.avatar ? '<img src="/api/avatars/'+c.avatar+'">' : initial(c.title);
  $('#chat-name').textContent = c.title;
  $('#pinned-bar').classList.add('hidden');
  showScreen('chat');
  updateChatHeaderStatus();

  // 🔐 Секретный чат — инициализация E2E
  if (c.type === 'secret'){
    ensureSecretKey(id).then(function(k){
      updateChatHeaderStatus();
      if (k) pollMessages(true);
      else {
        // собеседник ещё не заходил — повторяем попытку каждые 3 сек
        var retry = setInterval(function(){
          if (ACTIVE !== id || SECRET_KEYS[id]){ clearInterval(retry); return; }
          ensureSecretKey(id).then(function(kk){
            if (kk){ clearInterval(retry); updateChatHeaderStatus(); pollMessages(true); }
          }).catch(function(){});
        }, 3000);
      }
    }).catch(function(e){ console.warn('E2E:', e); });
  }

  return api('/api/chats/'+id+'/wallpaper').then(function(wp){
    WALLPAPER = (wp && wp.value) || 'default';
  }).catch(function(){ WALLPAPER = 'default'; }).then(function(){
    applyWallpaper();
    return pollMessages(true);
  });
}

function showWallpaperPicker(){
  var keys = Object.keys(WALLPAPERS);
  var html = keys.map(function(k){
    var bg = WALLPAPERS[k] || 'var(--tg-chat-bg)';
    return '<div class="wp-item'+(WALLPAPER===k?' on':'')+'" data-k="'+k+'" style="background:'+bg+'"><span>'+k+'</span></div>';
  }).join('');
  var m = modal('<div class="modal-title">Обои чата</div><div class="wp-grid">'+html+'</div>');
  var its = m.querySelectorAll('.wp-item');
  for (var i=0; i<its.length; i++){
    (function(el){ onceTap(el, function(){
      WALLPAPER = el.getAttribute('data-k'); applyWallpaper();
      api('/api/chats/'+ACTIVE+'/wallpaper', {method:'POST', body:{value:WALLPAPER}}).catch(function(){});
      m.remove();
    }); })(its[i]);
  }
}

function showChatMenu(btn){
  var ex = document.querySelector('.popover'); if (ex){ ex.remove(); return; }
  var rect = btn.getBoundingClientRect();
  var c = null; for (var i=0; i<CHATS.length; i++) if (CHATS[i].id === ACTIVE) c = CHATS[i];
  if (!c) return;
  var items = [];
  if (c.type === 'dm') items.push({id:'block', label:'Заблокировать'});
  items.push({id:'wallpaper', label:'Сменить обои'});
  items.push({id:'info', label:'Информация'});
  items.push({id:'hide', label: c.type==='dm' ? 'Удалить чат' : 'Покинуть', danger:true});
  var pop = document.createElement('div');
  pop.className = 'popover';
  pop.style.top = (rect.bottom + 6) + 'px'; pop.style.right = '8px';
  pop.innerHTML = items.map(function(i){
    return '<button data-id="'+i.id+'"'+(i.danger?' class="danger"':'')+'>'+i.label+'</button>';
  }).join('');
  document.body.appendChild(pop);
  setTimeout(function(){
    document.addEventListener('click', function cl(){ pop.remove(); document.removeEventListener('click', cl); });
  }, 0);
  onceTap(pop, function(ev){
    var b = ev.target.closest ? ev.target.closest('button') : null; if (!b) return;
    pop.remove();
    var id = b.getAttribute('data-id');
    if (id === 'block'){
      if (!confirm('Заблокировать?')) return;
      api('/api/blocks/'+c.peer_id, {method:'POST'}).then(function(){ openChat(ACTIVE); }).catch(function(e){ alert(e.message); });
    } else if (id === 'wallpaper') showWallpaperPicker();
    else if (id === 'info') showInfo(ACTIVE);
    else if (id === 'hide'){
      if (!confirm('Убрать из списка?')) return;
      api('/api/chats/'+ACTIVE+'/hide', {method:'POST'}).then(function(){
        ACTIVE = null; showScreen('chats'); return loadChats();
      }).then(renderChatList).catch(function(e){ alert(e.message); });
    }
  });
}

function setReply(msg){
  REPLY_TO = {id: msg.id, sender: (msg.sender && msg.sender.name) || '?',
              text: msg.text || (msg.file ? 'файл' : (msg.poll ? 'опрос' : ''))};
  $('#reply-bar').classList.remove('hidden');
  $('#reply-name').textContent = REPLY_TO.sender;
  $('#reply-text').textContent = (REPLY_TO.text || '').slice(0, 100);
  $('#msg').focus();
}
function clearReply(){ REPLY_TO = null; var b = $('#reply-bar'); if (b) b.classList.add('hidden'); }

function sendText(text){
  if (!text || !ACTIVE) return Promise.resolve();
  if (SLOW_COOLDOWN > 0) return Promise.resolve();
  closeStickers();
  var c = null; for (var i=0; i<CHATS.length; i++) if (CHATS[i].id === ACTIVE) c = CHATS[i];

  // 🔐 Секретный чат — шифруем на клиенте
  if (c && c.type === 'secret'){
    return encryptSecret(ACTIVE, text).then(function(b64){
      var body = {text: b64, encrypted: true};
      if (REPLY_TO) body.reply_to = REPLY_TO.id;
      clearReply();
      return api('/api/chats/'+ACTIVE+'/messages', {method:'POST', body: body});
    }).then(function(){ return pollMessages(); })
      .catch(function(err){ alert('Не удалось зашифровать: ' + err.message); });
  }

  var body = {text: text};
  if (REPLY_TO) body.reply_to = REPLY_TO.id;
  clearReply();
  return api('/api/chats/'+ACTIVE+'/messages', {method:'POST', body: body})
    .then(function(){ return pollMessages(); })
    .catch(function(err){ alert(err.message); });
}

function uploadAndSendFiles(files){
  var list = Array.prototype.slice.call(files);
  if (!list.length) return Promise.resolve();
  var fd = new FormData();
  for (var i=0; i<list.length; i++) fd.append('files', list[i]);
  return api('/api/upload_multi', {method:'POST', body: fd}).then(function(ups){
    var p = Promise.resolve();
    ups.forEach(function(up){
      p = p.then(function(){
        var body = {file_id: up.id};
        if (REPLY_TO) body.reply_to = REPLY_TO.id;
        return api('/api/chats/'+ACTIVE+'/messages', {method:'POST', body: body});
      });
    });
    return p.then(function(){ clearReply(); return pollMessages(); });
  });
}

function stopRec(){ if (REC && REC.state !== 'inactive') REC.stop(); }
function startVoiceRec(){
  if (REC){ stopRec(); return; }
  navigator.mediaDevices.getUserMedia({audio:true}).then(function(stream){
    var mime = '';
    var choices = ['audio/webm;codecs=opus','audio/webm','audio/mp4','audio/ogg'];
    for (var i=0; i<choices.length; i++){
      if (window.MediaRecorder && MediaRecorder.isTypeSupported(choices[i])){ mime = choices[i]; break; }
    }
    var mr = mime ? new MediaRecorder(stream, {mimeType: mime}) : new MediaRecorder(stream);
    REC_CHUNKS = []; REC_START = Date.now();
    mr.ondataavailable = function(ev){ if (ev.data && ev.data.size) REC_CHUNKS.push(ev.data); };
    mr.onstop = function(){
      stream.getTracks().forEach(function(t){ t.stop(); });
      clearInterval(REC_TIMER);
      var bar = document.querySelector('.rec-bar'); if (bar) bar.remove();
      var vb = $('#btn-voice'); if (vb) vb.classList.remove('recording');
      var dur = (Date.now() - REC_START)/1000;
      REC = null;
      if (dur < 0.7) return;
      var blob = new Blob(REC_CHUNKS, {type: mr.mimeType || 'audio/webm'});
      var f = new File([blob], 'voice.webm', {type: blob.type});
      var fd = new FormData(); fd.append('file', f);
      api('/api/upload', {method:'POST', body: fd}).then(function(up){
        var body = {file_id: up.id, is_voice: true, duration: dur};
        if (REPLY_TO) body.reply_to = REPLY_TO.id;
        return api('/api/chats/'+ACTIVE+'/messages', {method:'POST', body: body});
      }).then(function(){ clearReply(); return pollMessages(); })
      .catch(function(e){ alert(e.message); });
    };
    mr.start(); REC = mr;
    $('#btn-voice').classList.add('recording');
    var bar = document.createElement('div');
    bar.className = 'rec-bar';
    bar.innerHTML = '<span class="rec-dot"></span><span id="rec-t">0:00</span>';
    document.body.appendChild(bar);
    REC_TIMER = setInterval(function(){
      var t = (Date.now() - REC_START)/1000;
      var el = document.getElementById('rec-t'); if (el) el.textContent = fmtDur(t);
      if (t > 180) stopRec();
    }, 200);
  }).catch(function(e){ alert('Микрофон: ' + e.message); });
}

/* ---------- STICKERS ---------- */
function getChatScreen(){ return document.querySelector('[data-screen="chat"]'); }
function removeStickersDOM(){ var p = $('#stickers-panel'); if (p && p.parentNode) p.parentNode.removeChild(p); }
function closeStickers(){ removeStickersDOM(); STICKERS_OPEN = false; ACTIVE_PACK_ID = null; }
function reloadStickers(){ STICKERS_OPEN = false; removeStickersDOM(); openStickers(); }
function openStickers(){
  if (STICKERS_OPEN) return;
  removeStickersDOM(); STICKERS_OPEN = true; ACTIVE_PACK_ID = null;
  var screen = getChatScreen(); var composer = $('#composer');
  if (!screen || !composer) return;
  var panel = document.createElement('div');
  panel.className = 'stickers-panel'; panel.id = 'stickers-panel';
  panel.innerHTML = '<div class="sp-tabs" id="sp-tabs">'
    + '<button class="sp-tab sp-new-tab" id="sp-new-tab">＋</button></div>'
    + '<div class="sp-body" id="sp-body"><div class="sp-empty">Загрузка…</div></div>';
  screen.insertBefore(panel, composer);
  onceTap(panel.querySelector('#sp-new-tab'), createPackDialog);
  api('/api/packs').catch(function(){ return []; }).then(function(packs){
    if (!STICKERS_OPEN) return;
    var tabs = $('#sp-tabs'); if (!tabs) return;
    var html = '';
    packs.forEach(function(p){
      html += '<button class="sp-tab" data-pid="'+p.id+'"><span>'+esc(p.name)+'</span>'
        + (p.is_official?officialCheck():'') + '</button>';
    });
    tabs.innerHTML = '<button class="sp-tab sp-new-tab" id="sp-new-tab">＋</button>' + html;
    onceTap(tabs.querySelector('#sp-new-tab'), createPackDialog);
    var tbs = tabs.querySelectorAll('.sp-tab[data-pid]');
    for (var i=0; i<tbs.length; i++){
      (function(b){ onceTap(b, function(){ setActivePack(parseInt(b.getAttribute('data-pid'),10)); }); })(tbs[i]);
    }
    if (packs.length) setActivePack(packs[0].id);
    else $('#sp-body').innerHTML = '<div class="sp-empty">Нет паков. Нажмите ＋.</div>';
  });
}

function setActivePack(pid){
  ACTIVE_PACK_ID = pid;
  var panel = $('#stickers-panel'); if (!panel) return;
  var tabs = panel.querySelectorAll('.sp-tab');
  for (var i=0; i<tabs.length; i++){
    tabs[i].classList.toggle('on', tabs[i].getAttribute('data-pid') === String(pid));
  }
  var body = $('#sp-body'); if (!body) return;
  body.innerHTML = '<div class="sp-empty">Загрузка…</div>';
  api('/api/packs/'+pid).then(function(p){
    if (ACTIVE_PACK_ID !== pid) return;
    renderPackContent(p);
  }).catch(function(e){
    if (e && (e.status === 404)){ if (STICKERS_OPEN) reloadStickers(); return; }
    $('#sp-body').innerHTML = '<div class="sp-empty">Ошибка: '+esc(e.message)+'</div>';
  });
}

function renderPackContent(p){
  var body = $('#sp-body'); if (!body) return;
  var header = '<div class="sp-pack-head"><div class="sp-pack-name">'+esc(p.name)+(p.is_official?officialCheck():'')+'</div>'
    + '<div class="sp-pack-actions">';
  if (p.mine) header += '<button class="sp-act" id="sp-add-sticker">＋ Стикер</button>'
    + '<button class="sp-act danger" id="sp-del-pack">🗑</button>';
  header += '</div></div>';
  var grid = '<div class="sp-grid">';
  if (p.stickers.length){
    p.stickers.forEach(function(s){
      grid += '<div class="sp-item" data-sid="'+s.id+'"><img src="/api/files/'+s.file.id+'">'
        + (p.mine ? '<div class="sp-del" data-del="'+s.id+'">✕</div>' : '') + '</div>';
    });
  } else grid += '<div class="sp-empty">Пусто.</div>';
  grid += '</div>';
  body.innerHTML = header + grid;
  var ab = $('#sp-add-sticker'); if (ab) onceTap(ab, function(){ addStickerToPack(p.id); });
  var db = $('#sp-del-pack'); if (db) onceTap(db, function(){
    if (!confirm('Удалить пак?')) return;
    api('/api/packs/'+p.id, {method:'DELETE'}).then(reloadStickers).catch(function(e){ alert(e.message); });
  });
  var its = body.querySelectorAll('.sp-item');
  for (var i=0; i<its.length; i++){
    (function(it){
      onceTap(it, function(ev){
        var delId = ev.target.getAttribute && ev.target.getAttribute('data-del');
        if (delId){
          if (!confirm('Удалить стикер?')) return;
          api('/api/packs/'+p.id+'/stickers/'+delId, {method:'DELETE'}).then(function(){ setActivePack(p.id); }).catch(function(e){ alert(e.message); });
          return;
        }
        var sid = parseInt(it.getAttribute('data-sid'),10);
        var body2 = {sticker_id: sid};
        if (REPLY_TO) body2.reply_to = REPLY_TO.id;
        api('/api/chats/'+ACTIVE+'/messages', {method:'POST', body: body2})
          .then(function(){ clearReply(); closeStickers(); return pollMessages(); })
          .catch(function(e){ alert(e.message); });
      });
    })(its[i]);
  }
}

function addStickerToPack(pid){
  var inp = document.createElement('input'); inp.type='file'; inp.accept='image/*';
  inp.onchange = function(){
    var f = inp.files[0]; if (!f) return;
    var fd = new FormData(); fd.append('file', f);
    api('/api/packs/'+pid+'/stickers', {method:'POST', body: fd})
      .then(function(){ setActivePack(pid); }).catch(function(e){ alert(e.message); });
  };
  inp.click();
}

function createPackDialog(){
  var canOffic = !!(ME && ME.is_dev_local);
  var m = modal('<div class="modal-title">Новый пак</div>'
    + '<input class="modal-input" id="pack-name" placeholder="Название">'
    + (canOffic ? '<label class="check-row"><input type="checkbox" id="pack-off"><span>Официальный</span></label>' : '')
    + '<button class="primary-btn" id="pack-create">Создать</button>');
  onceTap(m.querySelector('#pack-create'), function(){
    var name = m.querySelector('#pack-name').value.trim(); if (!name) return;
    var body = {name: name};
    var cb = m.querySelector('#pack-off'); if (cb && cb.checked) body.is_official = true;
    api('/api/packs', {method:'POST', body: body}).then(function(){ m.remove(); reloadStickers(); })
      .catch(function(e){ alert(e.message); });
  });
}

/* ---------- MESSAGES ---------- */
function pollMessages(clear){
  if (!ACTIVE) return Promise.resolve();
  var url = '/api/chats/'+ACTIVE+'/messages?after='+(clear?0:LAST_ID);
  return api(url).then(function(res){
    var msgs = res.messages || [];
    var deletedIds = res.deleted_ids || [];
    var typingNames = res.typing || [];
    var peerStatus = res.peer_status || null;
    var pinned = res.pinned || [];

    LAST_TYPING_NAMES = typingNames;
    if (peerStatus){ if (!CURRENT_PEER) CURRENT_PEER = {}; CURRENT_PEER.status = peerStatus; }
    updateChatHeaderStatus();
    renderPinned(pinned);

    var box = $('#messages'); if (!box) return;
    if (clear){
      box.innerHTML = '';
      if (WALLPAPER === 'default') box.style.background = ''; else applyWallpaper();
    }
    deletedIds.forEach(function(id){
      var el = box.querySelector('[data-mid="'+id+'"]'); if (el && el.parentNode) el.parentNode.removeChild(el);
    });
    if (!msgs.length && clear){
      box.innerHTML = '<div class="chat-empty">Нет сообщений.<br>Напишите первым 👋</div>'; return;
    }
    if (clear && box.firstChild && box.firstChild.className === 'chat-empty') box.innerHTML = '';
    var atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 100;
    msgs.forEach(function(m){
      if (m.id > LAST_ID) LAST_ID = m.id;
      var old = box.querySelector('[data-mid="'+m.id+'"]');
      var newEl = renderMsg(m);
      if (old) old.parentNode.replaceChild(newEl, old); else box.appendChild(newEl);
    });
    if (msgs.length && (atBottom || clear)) box.scrollTop = box.scrollHeight;
    applySlowCooldown();
  });
}

function applySlowCooldown(){
  var c = null; for (var i=0; i<CHATS.length; i++) if (CHATS[i].id === ACTIVE) c = CHATS[i];
  if (!c || !c.slow_mode) return;
  var box = $('#messages'); if (!box) return;
  var mine = box.querySelectorAll('.msg-row.me');
  if (!mine.length) return;
  var last = mine[mine.length-1]._msg;
  if (!last) return;
  var secSince = (Date.now()/1000) - last.created;
  if (secSince >= c.slow_mode) return;
  SLOW_COOLDOWN = Math.ceil(c.slow_mode - secSince);
  var inp = $('#msg'); if (!inp) return;
  inp.disabled = true; inp.placeholder = 'Подождите ' + SLOW_COOLDOWN + ' сек';
  clearInterval(SLOW_TIMER);
  SLOW_TIMER = setInterval(function(){
    SLOW_COOLDOWN--;
    if (SLOW_COOLDOWN <= 0){
      clearInterval(SLOW_TIMER); SLOW_COOLDOWN = 0;
      inp.disabled = false; inp.placeholder = 'Сообщение';
      return;
    }
    inp.placeholder = 'Подождите ' + SLOW_COOLDOWN + ' сек';
  }, 1000);
}

function renderPinned(pinned){
  var bar = $('#pinned-bar'); if (!bar) return;
  if (!pinned || !pinned.length){ bar.classList.add('hidden'); bar.innerHTML = ''; return; }
  var p = pinned[0]; bar.classList.remove('hidden');
  var text = p.text || (p.is_sticker ? 'стикер' : (p.is_voice ? 'голосовое' : (p.file ? 'файл' : (p.poll ? 'опрос' : ''))));
  bar.innerHTML = '<div class="pb-ic">📌</div>'
    + '<div class="pb-body"><div class="pb-title">Закреплённое'+(pinned.length>1?' ('+pinned.length+')':'')+'</div>'
    + '<div class="pb-text">'+esc((p.sender&&p.sender.name)||'')+': '+esc(text.slice(0,80))+'</div></div>'
    + '<button class="pb-close" id="pb-close">✕</button>';
  onceTap(bar, function(ev){
    if (ev.target.id === 'pb-close'){
      ev.stopPropagation();
      api('/api/chats/'+ACTIVE+'/pin/'+p.id, {method:'DELETE'}).then(function(){ renderPinned([]); }).catch(function(){});
      return;
    }
    scrollToMsg(p.id);
  });
}

function scrollToMsg(id){
  var box = $('#messages'); if (!box) return;
  var el = box.querySelector('[data-mid="'+id+'"]'); if (!el) return;
  el.scrollIntoView({behavior:'smooth', block:'center'});
  el.classList.add('highlight');
  setTimeout(function(){ el.classList.remove('highlight'); }, 1400);
}

function renderReplyQuote(m){
  if (!m.reply_to) return '';
  var r = m.reply_to;
  var text = r.deleted ? '<span class="rq-del">Сообщение удалено</span>'
    : (r.text ? esc(r.text) : (r.is_sticker ? 'стикер' : (r.is_voice ? 'голосовое' : (r.file ? 'файл' : ''))));
  return '<div class="reply-quote" data-reply="'+r.id+'"><div class="rq-name">'+esc(r.sender)+'</div>'
    + '<div class="rq-text">'+text+'</div></div>';
}

function renderReactions(m){
  if (!m.reactions || !m.reactions.length) return '';
  return '<div class="msg-reactions">' + m.reactions.map(function(r){
    var mine = r.user_ids.indexOf(ME.id) >= 0;
    return '<span class="react-chip'+(mine?' mine':'')+'" data-emoji="'+r.emoji+'">'
      + r.emoji + '<span class="rc-count">'+r.count+'</span></span>';
  }).join('') + '</div>';
}

function renderPoll(m){
  var p = m.poll; if (!p) return '';
  var html = '<div class="poll-card"><div class="poll-q">'+esc(p.question)+'</div>';
  p.options.forEach(function(opt, idx){
    var cnt = p.counts[idx] || 0;
    var pct = p.total ? Math.round(cnt * 100 / p.total) : 0;
    var mine = p.my_votes.indexOf(idx) >= 0;
    html += '<div class="poll-opt'+(mine?' mine':'')+'" data-idx="'+idx+'">'
      + '<div class="poll-opt-bar" style="width:'+pct+'%"></div>'
      + '<div class="poll-opt-txt"><span>'+esc(opt)+'</span><span>'+pct+'% ('+cnt+')</span></div>'
      + '</div>';
  });
  html += '<div class="poll-meta">Всего: '+p.total
    + (p.multiple ? ' · несколько' : '') + (p.anonymous ? ' · анонимно' : '')
    + (p.closed ? ' · закрыт' : '') + '</div></div>';
  return html;
}

function renderMsg(m){
  var isMe = m.sender && ME && m.sender.id === ME.id;
  var el = document.createElement('div');
  el.className = 'msg-row' + (isMe ? ' me' : '');
  el.setAttribute('data-mid', String(m.id));
  el._msg = m;
  var av = (m.sender && m.sender.avatar) ? '<img src="/api/avatars/'+m.sender.avatar+'">' : initial(m.sender ? m.sender.name : '?');

  if (m.deleted){
    el.innerHTML = '<div class="m-av">'+av+'</div><div class="bubble">'
      + '<div class="m-text" style="color:var(--tg-text-muted);font-style:italic">Сообщение удалено</div>'
      + '<span class="m-time">'+fmtTime(m.created)+'</span></div>';
    return el;
  }

  if (m.poll){
    el.innerHTML = '<div class="m-av">'+av+'</div><div class="bubble">'
      + '<div class="m-sender">'+esc((m.sender&&m.sender.name)||'')+'</div>'
      + renderPoll(m)
      + '<span class="m-time">'+fmtTime(m.created)+'</span></div>'
      + renderReactions(m);
    var opts = el.querySelectorAll('.poll-opt');
    for (var k=0; k<opts.length; k++){
      (function(o){
        onceTap(o, function(){
          var idx = parseInt(o.getAttribute('data-idx'),10);
          api('/api/polls/'+m.poll.id+'/vote', {method:'POST', body:{option: idx}})
            .then(function(){ return pollMessages(); }).catch(function(e){ alert(e.message); });
        });
      })(opts[k]);
    }
    bindQuoteClick(el); bindReactionClick(el, m); bindMsgLongPress(el, m);
    return el;
  }

  if (m.is_sticker && m.file){
    el.className += ' sticker-row';
    el.innerHTML = '<div class="m-av">'+av+'</div><div class="bubble sticker-only">'
      + renderReplyQuote(m) + '<img class="m-sticker" src="/api/files/'+m.file.id+'"></div>'
      + renderReactions(m);
    onceTap(el.querySelector('.m-sticker'), function(){ window.open('/api/files/'+m.file.id,'_blank'); });
    bindQuoteClick(el); bindReactionClick(el, m); bindMsgLongPress(el, m);
    return el;
  }

  if (m.is_voice && m.file){
    el.innerHTML = '<div class="m-av">'+av+'</div><div class="bubble">'
      + '<div class="m-sender">'+esc((m.sender&&m.sender.name)||'')+'</div>'
      + renderReplyQuote(m)
      + '<div class="m-voice" data-fid="'+m.file.id+'" data-dur="'+(m.duration||0)+'">'
      + '<div class="vplay">▶</div><div class="vbar"><div class="vbar-fill"></div></div>'
      + '<div class="vt">'+fmtDur(m.duration||0)+'</div>'
      + '<audio preload="metadata" src="/api/files/'+m.file.id+'"></audio></div>'
      + '<span class="m-time">'+fmtTime(m.created)+'</span></div>'
      + renderReactions(m);
    bindVoice(el.querySelector('.m-voice'));
    bindQuoteClick(el); bindReactionClick(el, m); bindMsgLongPress(el, m);
    return el;
  }

  var fileHtml = '';
  if (m.file){
    var mime = m.file.mime || '';
    var url = '/api/files/'+m.file.id, dl = url+'?download=1';
    if (mime.indexOf('image/') === 0){
      fileHtml = '<div class="m-media-wrap"><img class="m-attach-img" src="'+url+'">'
        + '<a class="m-media-dl" href="'+dl+'" download>⬇</a></div>';
    } else if (mime.indexOf('video/') === 0){
      fileHtml = '<div class="m-media-wrap"><video controls preload="metadata" style="max-width:100%;max-height:20rem;border-radius:.5rem" src="'+url+'"></video>'
        + '<a class="m-media-dl" href="'+dl+'" download>⬇</a></div>';
    } else if (mime.indexOf('audio/') === 0){
      fileHtml = '<div class="m-media-wrap"><audio controls src="'+url+'"></audio>'
        + '<a class="m-media-dl" href="'+dl+'" download>⬇</a></div>';
    } else {
      fileHtml = '<a class="m-file-link" href="'+dl+'" download><span class="fic">📎</span>'
        + '<span>'+esc(m.file.name)+'<br><span style="font-size:.78rem;color:var(--tg-text-muted)">'
        + fmtSize(m.file.size)+' · скачать</span></span></a>';
    }
  }

  /* Текстовое тело: с E2E или без */
  var textHtml = '';
  if (m.text){
    if (m.enc){
      textHtml = '<div class="m-text m-enc-pending">🔒 расшифровка…</div>';
    } else {
      textHtml = '<div class="m-text">'+esc(m.text)+'</div>';
    }
  }

  el.innerHTML = '<div class="m-av">'+av+'</div><div class="bubble">'
    + '<div class="m-sender">'+esc((m.sender&&m.sender.name)||'')+'</div>'
    + renderReplyQuote(m) + fileHtml
    + textHtml
    + (m.edited ? '<span class="edited-mark">изм.</span>' : '')
    + '<span class="m-time">'+fmtTime(m.created)+'</span></div>'
    + renderReactions(m);

  /* Асинхронная расшифровка E2E */
  if (m.enc && m.text){
    (function(elRef, mRef){
      decryptSecret(ACTIVE, mRef.text).then(function(plain){
        var t = elRef.querySelector('.m-enc-pending');
        if (t){ t.classList.remove('m-enc-pending'); t.textContent = '🔒 ' + plain; }
      }).catch(function(){});
    })(el, m);
  }

  var img = el.querySelector('.m-attach-img');
  if (img) onceTap(img, function(){ window.open(url,'_blank'); });
  bindQuoteClick(el); bindReactionClick(el, m); bindMsgLongPress(el, m);
  return el;
}

function bindQuoteClick(el){
  var q = el.querySelector('.reply-quote'); if (!q) return;
  onceTap(q, function(){ scrollToMsg(parseInt(q.getAttribute('data-reply'),10)); });
}
function bindReactionClick(el, m){
  var chips = el.querySelectorAll('.react-chip');
  for (var i=0; i<chips.length; i++){
    (function(chip){
      onceTap(chip, function(ev){
        ev.stopPropagation();
        var emoji = chip.getAttribute('data-emoji');
        api('/api/messages/'+m.id+'/reactions', {method:'POST', body:{emoji: emoji}})
          .then(function(rx){
            var old = document.querySelector('[data-mid="'+m.id+'"]');
            if (old){ m.reactions = rx; old.parentNode.replaceChild(renderMsg(m), old); }
          }).catch(function(e){ alert(e.message); });
      });
    })(chips[i]);
  }
}

function bindMsgLongPress(el, m){
  if (m.deleted) return;
  el.style.userSelect = 'none';
  var timer = null, fired = false;
  function start(){
    fired = false;
    timer = setTimeout(function(){ fired = true; try{navigator.vibrate&&navigator.vibrate(20);}catch(e){} showMsgMenu(m); }, 500);
  }
  function cancel(){ if (timer){ clearTimeout(timer); timer = null; } }
  el.addEventListener('touchstart', start, {passive:true});
  el.addEventListener('touchend', function(e){ if (fired){ if (e.cancelable) e.preventDefault(); e.stopPropagation(); } cancel(); });
  el.addEventListener('touchmove', cancel, {passive:true});
  el.addEventListener('touchcancel', cancel, {passive:true});
  el.addEventListener('contextmenu', function(e){ e.preventDefault(); showMsgMenu(m); });
}

function showMsgMenu(m){
  var isMe = m.sender && ME && m.sender.id === ME.id;
  var myRx = (m.reactions||[]).filter(function(r){ return r.user_ids.indexOf(ME.id)>=0; }).map(function(r){ return r.emoji; });
  var emojiHtml = EMOJIS.map(function(e){
    return '<button data-e="'+e+'"'+(myRx.indexOf(e)>=0?' class="on"':'')+'>'+e+'</button>';
  }).join('');
  var actions = '<button class="primary-btn" id="mm-reply" style="background:var(--tg-input-bg);color:var(--tg-text)">Ответить</button>';
  if (isMe && !m.file && !m.is_sticker && !m.is_voice && !m.poll && !m.enc){
    actions += '<button class="primary-btn" id="mm-edit" style="background:var(--tg-input-bg);color:var(--tg-text)">Изменить</button>';
  }
  var c = null; for (var i=0;i<CHATS.length;i++) if (CHATS[i].id === ACTIVE) c = CHATS[i];
  var isOwner = c && c.owner_id === ME.id;
  if (isMe || isOwner){
    actions += '<button class="primary-btn" id="mm-del" style="background:#e64545">Удалить</button>';
  }
  actions += '<button class="primary-btn" id="mm-pin" style="background:var(--tg-input-bg);color:var(--tg-text)">📌 Закрепить</button>';

  var mm = modal('<div class="modal-title">Действия</div><div class="emoji-row">'+emojiHtml+'</div>'+actions);
  var es = mm.querySelectorAll('.emoji-row button');
  for (var k=0; k<es.length; k++){
    (function(b){
      onceTap(b, function(){
        var emoji = b.getAttribute('data-e');
        api('/api/messages/'+m.id+'/reactions', {method:'POST', body:{emoji: emoji}})
          .then(function(rx){
            m.reactions = rx;
            var old = document.querySelector('[data-mid="'+m.id+'"]');
            if (old) old.parentNode.replaceChild(renderMsg(m), old);
            mm.remove();
          }).catch(function(e){ alert(e.message); });
      });
    })(es[k]);
  }
  onceTap(mm.querySelector('#mm-reply'), function(){ mm.remove(); setReply(m); });
  var ed = mm.querySelector('#mm-edit');
  if (ed) onceTap(ed, function(){ mm.remove(); editMessage(m); });
  var dl = mm.querySelector('#mm-del');
  if (dl) onceTap(dl, function(){
    mm.remove();
    if (!confirm('Удалить?')) return;
    api('/api/messages/'+m.id, {method:'DELETE'}).then(function(){
      var el = document.querySelector('[data-mid="'+m.id+'"]');
      if (el && el.parentNode) el.parentNode.removeChild(el);
    }).catch(function(e){ alert(e.message); });
  });
  onceTap(mm.querySelector('#mm-pin'), function(){
    mm.remove();
    api('/api/chats/'+ACTIVE+'/pin/'+m.id, {method:'POST'}).then(function(){ return pollMessages(); })
      .catch(function(e){ alert(e.message); });
  });
}

function editMessage(m){
  var mm = modal('<div class="modal-title">Редактировать</div>'
    + '<input class="modal-input" id="ed-text" value="'+esc(m.text||'')+'">'
    + '<button class="primary-btn" id="ed-save">Сохранить</button>');
  var inp = mm.querySelector('#ed-text'); inp.focus();
  onceTap(mm.querySelector('#ed-save'), function(){
    var t = inp.value.trim(); if (!t) return;
    api('/api/messages/'+m.id, {method:'PATCH', body:{text: t}}).then(function(){
      m.text = t; m.edited = true;
      var old = document.querySelector('[data-mid="'+m.id+'"]');
      if (old) old.parentNode.replaceChild(renderMsg(m), old);
      mm.remove();
    }).catch(function(e){ alert(e.message); });
  });
}

function bindVoice(wrap){
  var audio = wrap.querySelector('audio');
  var play = wrap.querySelector('.vplay');
  var bar = wrap.querySelector('.vbar');
  var fill = wrap.querySelector('.vbar-fill');
  var t = wrap.querySelector('.vt');
  var dur = parseFloat(wrap.getAttribute('data-dur')) || 0;
  var raf = null;
  function tick(){
    if (!audio.duration || !isFinite(audio.duration)) return;
    var p = audio.currentTime / audio.duration;
    fill.style.width = (p*100) + '%';
    t.textContent = fmtDur(audio.currentTime);
    if (!audio.paused) raf = requestAnimationFrame(tick);
  }
  onceTap(play, function(){
    if (audio.paused){
      var all = document.querySelectorAll('.m-voice audio');
      for (var i=0; i<all.length; i++) if (all[i] !== audio) all[i].pause();
      audio.play().catch(function(){}); play.textContent = '❚❚';
      raf = requestAnimationFrame(tick);
    } else { audio.pause(); play.textContent = '▶'; cancelAnimationFrame(raf); }
  });
  audio.onended = function(){ play.textContent = '▶'; fill.style.width='0'; t.textContent = fmtDur(dur); };
  bar.onclick = function(e){
    var r = bar.getBoundingClientRect();
    var p = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width));
    if (audio.duration && isFinite(audio.duration)) audio.currentTime = p * audio.duration;
  };
}

/* ---------- SEARCH ---------- */
function openSearchScreen(){
  showScreen('search');
  var q = $('#msg-search-q'); q.value = '';
  $('#search-results').innerHTML = '<div class="empty-list">Введите 2+ символа</div>';
  setTimeout(function(){ q.focus(); }, 50);
}
var searchTimer = null;
function doMsgSearch(){
  var q = $('#msg-search-q').value.trim();
  var box = $('#search-results');
  clearTimeout(searchTimer);
  if (q.length < 2){ box.innerHTML = '<div class="empty-list">Введите 2+ символа</div>'; return; }
  searchTimer = setTimeout(function(){
    api('/api/chats/'+ACTIVE+'/search?q='+encodeURIComponent(q)).then(function(list){
      if (!list.length){ box.innerHTML = '<div class="empty-list">Ничего не найдено</div>'; return; }
      box.innerHTML = '';
      list.forEach(function(m){
        var el = document.createElement('div');
        el.className = 'search-result';
        var txt = m.text || (m.is_sticker?'стикер':(m.is_voice?'голосовое':(m.file?'файл':'')));
        var safeTxt = esc(txt);
        var rx = new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&') + ')', 'ig');
        safeTxt = safeTxt.replace(rx, '<mark>$1</mark>');
        el.innerHTML = '<div class="sr-info"><div class="sr-name">'+esc((m.sender&&m.sender.name)||'')
          + '<span class="sr-time">'+fmtDay(m.created)+'</span></div>'
          + '<div class="sr-text">'+safeTxt+'</div></div>';
        onceTap(el, function(){ showScreen('chat'); setTimeout(function(){ scrollToMsg(m.id); }, 100); });
        box.appendChild(el);
      });
    }).catch(function(e){ box.innerHTML = '<div class="empty-list">Ошибка: '+esc(e.message)+'</div>'; });
  }, 400);
}

/* ---------- FOLDERS ---------- */
function renderFoldersScreen(){
  $('#folders-body').innerHTML = FOLDERS.length
    ? FOLDERS.map(function(f){
        return '<div class="folder-row" data-fid="'+f.id+'">'
          + '<div class="fr-name">'+esc(f.name)+'</div>'
          + '<div class="muted">'+f.chat_ids.length+' чатов</div>'
          + '<div class="fr-del" data-del="'+f.id+'">✕</div></div>';
      }).join('')
    : '<div class="empty-list">Нет папок. Нажмите ＋</div>';
  var body = $('#folders-body');
  var dels = body.querySelectorAll('[data-del]');
  for (var i=0; i<dels.length; i++){
    (function(d){
      onceTap(d, function(ev){
        ev.stopPropagation();
        if (!confirm('Удалить папку?')) return;
        api('/api/folders/'+d.getAttribute('data-del'), {method:'DELETE'}).then(function(){
          return loadFolders();
        }).then(function(){ renderFoldersScreen(); renderFolderTabs(); }).catch(function(e){ alert(e.message); });
      });
    })(dels[i]);
  }
  var rows = body.querySelectorAll('.folder-row');
  for (var j=0; j<rows.length; j++){
    (function(r){ onceTap(r, function(){ editFolder(parseInt(r.getAttribute('data-fid'),10)); }); })(rows[j]);
  }
}

function editFolder(fid){
  var f = null; for (var i=0; i<FOLDERS.length; i++) if (FOLDERS[i].id === fid) f = FOLDERS[i];
  if (!f) return;
  var chatsHtml = CHATS.map(function(c){
    var on = f.chat_ids.indexOf(c.id) >= 0;
    return '<label class="folder-chat-pick"><input type="checkbox" data-cid="'+c.id+'"'+(on?' checked':'')+'>'
      + '<span>'+esc(c.title)+'</span></label>';
  }).join('');
  var m = modal('<div class="modal-title">Папка</div>'
    + '<input class="modal-input" id="f-name" value="'+esc(f.name)+'">'
    + '<div style="max-height:40vh;overflow-y:auto">'+chatsHtml+'</div>'
    + '<button class="primary-btn" id="f-save">Сохранить</button>');
  onceTap(m.querySelector('#f-save'), function(){
    var name = m.querySelector('#f-name').value.trim(); if (!name) return;
    var cids = [];
    var cbs = m.querySelectorAll('input[type=checkbox]');
    for (var i=0; i<cbs.length; i++) if (cbs[i].checked) cids.push(parseInt(cbs[i].getAttribute('data-cid'),10));
    api('/api/folders/'+f.id, {method:'PATCH', body:{name: name, chat_ids: cids}}).then(function(){
      m.remove(); return loadFolders();
    }).then(function(){ renderFoldersScreen(); renderFolderTabs(); }).catch(function(e){ alert(e.message); });
  });
}

function newFolderDialog(){
  var chatsHtml = CHATS.map(function(c){
    return '<label class="folder-chat-pick"><input type="checkbox" data-cid="'+c.id+'">'
      + '<span>'+esc(c.title)+'</span></label>';
  }).join('');
  var m = modal('<div class="modal-title">Новая папка</div>'
    + '<input class="modal-input" id="f-name" placeholder="Название">'
    + '<div style="max-height:40vh;overflow-y:auto">'+chatsHtml+'</div>'
    + '<button class="primary-btn" id="f-save">Создать</button>');
  onceTap(m.querySelector('#f-save'), function(){
    var name = m.querySelector('#f-name').value.trim(); if (!name) return;
    var cids = [];
    var cbs = m.querySelectorAll('input[type=checkbox]');
    for (var i=0; i<cbs.length; i++) if (cbs[i].checked) cids.push(parseInt(cbs[i].getAttribute('data-cid'),10));
    api('/api/folders', {method:'POST', body:{name: name, chat_ids: cids}}).then(function(){
      m.remove(); return loadFolders();
    }).then(function(){ renderFoldersScreen(); renderFolderTabs(); }).catch(function(e){ alert(e.message); });
  });
}

/* ---------- SETTINGS ---------- */
function renderSettings(){
  var theme = 'dark';
  try { theme = localStorage.getItem('theme') || 'dark'; } catch(e){}
  var st = ME.status || 'online';
  var notifOn = false;
  try { notifOn = Notification.permission === 'granted'; } catch(e){}
  $('#settings-body').innerHTML =
    '<div class="section-label">Аккаунт</div>'
    + '<div class="card">'
    + '<div class="settings-row" data-act="profile"><div class="sr-ic bg-blue">👤</div>'
    + '<div class="sr-body"><div class="sr-title">Мой профиль</div>'
    + '<div class="sr-sub">'+esc(ME.name)+' · @'+esc(ME.username)+'</div></div>'
    + '<div class="sr-arrow">›</div></div>'
    + '<div class="settings-row" data-act="folders"><div class="sr-ic bg-orange">📁</div>'
    + '<div class="sr-body"><div class="sr-title">Папки с чатами</div></div>'
    + '<div class="sr-arrow">›</div></div></div>'
    + '<div class="section-label">Статус</div>'
    + '<div class="card" style="padding:.6rem"><div class="status-select">'
    + '<button data-s="online"'+(st==='online'?' class="on"':'')+'><span class="dot"></span>В сети</button>'
    + '<button data-s="recently"'+(st==='recently'?' class="on"':'')+'><span class="dot"></span>Недавно</button>'
    + '<button data-s="dnd"'+(st==='dnd'?' class="on"':'')+'><span class="dot"></span>Не беспокоить</button>'
    + '</div></div>'
    + '<div class="section-label">Уведомления</div>'
    + '<div class="card">'
    + '<div class="settings-row" data-act="notif"><div class="sr-ic bg-purple">🔔</div>'
    + '<div class="sr-body"><div class="sr-title">Уведомления</div>'
    + '<div class="sr-sub">'+(notifOn?'Разрешены':'Запрещены')+'</div></div>'
    + '<div class="sr-arrow">›</div></div></div>'
    + '<div class="section-label">Оформление</div>'
    + '<div class="card"><div class="settings-row" id="row-theme">'
    + '<div class="sr-ic bg-purple">🌙</div>'
    + '<div class="sr-body"><div class="sr-title">Тёмная тема</div></div>'
    + '<div class="sr-switch'+(theme==='dark'?' on':'')+'" id="sw-theme"></div></div></div>'
    + '<div class="section-label">Безопасность</div>'
    + '<div class="card">'
    + '<div class="settings-row" data-act="password"><div class="sr-ic bg-green">🔒</div>'
    + '<div class="sr-body"><div class="sr-title">Изменить пароль</div></div>'
    + '<div class="sr-arrow">›</div></div>'
    + '<div class="settings-row" data-act="delete_acc"><div class="sr-ic bg-red">🗑</div>'
    + '<div class="sr-body"><div class="sr-title" style="color:#e64545">Удалить аккаунт</div></div>'
    + '<div class="sr-arrow">›</div></div></div>'
    + '<div class="section-label">О приложении</div>'
    + '<div class="card">'
    + '<div class="settings-row" data-act="about"><div class="sr-ic bg-teal">ℹ</div>'
    + '<div class="sr-body"><div class="sr-title">О мессенджере</div></div>'
    + '<div class="sr-arrow">›</div></div>'
    + '<div class="settings-row" data-act="logout"><div class="sr-ic bg-red">↪</div>'
    + '<div class="sr-body"><div class="sr-title" style="color:#e64545">Выйти</div></div></div></div>';

  var stBtns = $('#settings-body').querySelectorAll('.status-select button');
  for (var i=0; i<stBtns.length; i++){
    (function(b){
      onceTap(b, function(){
        var s = b.getAttribute('data-s');
        api('/api/me/status', {method:'POST', body:{status: s}}).then(function(){
          ME.status = s;
          var ss = $('#settings-body').querySelectorAll('.status-select button');
          for (var j=0;j<ss.length;j++) ss[j].classList.toggle('on', ss[j]===b);
        }).catch(function(e){ alert(e.message); });
      });
    })(stBtns[i]);
  }
  onceTap($('#settings-body'), function(e){
    var row = e.target.closest ? e.target.closest('.settings-row') : null;
    if (!row) return;
    if (row.id === 'row-theme'){
      var cur = 'dark';
      try { cur = localStorage.getItem('theme') || 'dark'; } catch(err){}
      var next = cur === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      $('#sw-theme').classList.toggle('on', next === 'dark');
      return;
    }
    var act = row.getAttribute('data-act');
    if (act === 'profile'){ renderProfileEdit(); showScreen('profile'); }
    else if (act === 'folders'){ renderFoldersScreen(); showScreen('folders'); }
    else if (act === 'about'){ renderAbout(); showScreen('about'); }
    else if (act === 'logout'){ api('/api/logout', {method:'POST'}).catch(function(){}).then(function(){ location.reload(); }); }
    else if (act === 'password') changePassword();
    else if (act === 'notif'){
      if (!('Notification' in window)){ alert('Уведомления не поддерживаются'); return; }
      Notification.requestPermission().then(function(){ renderSettings(); });
    }
    else if (act === 'delete_acc') deleteAccount();
  });
}

function deleteAccount(){
  var m = modal('<div class="modal-title" style="color:#e64545">Удалить аккаунт?</div>'
    + '<p class="muted" style="text-align:center">Необратимо. Ваши сообщения станут анонимными.</p>'
    + '<input class="modal-input" id="del-pw" type="password" placeholder="Ваш пароль">'
    + '<button class="primary-btn" id="del-go" style="background:#e64545">Удалить навсегда</button>');
  onceTap(m.querySelector('#del-go'), function(){
    var pw = m.querySelector('#del-pw').value;
    if (!pw) return;
    if (!confirm('ТОЧНО удалить аккаунт?')) return;
    api('/api/me', {method:'DELETE', body:{password: pw}}).then(function(){
      alert('Аккаунт удалён'); location.reload();
    }).catch(function(e){ alert(e.message); });
  });
}

function renderProfileEdit(){
  var av = ME.avatar ? '<img src="/api/avatars/'+ME.avatar+'">' : initial(ME.name);
  $('#profile-body').innerHTML =
    '<div class="profile-edit"><div class="pe-avatar" id="pe-av">'+av+'</div>'
    + '<div class="pe-hint">Нажмите на аватар чтобы изменить</div></div>'
    + '<div class="card pe-section">'
    + '<div class="pe-field"><div class="pe-ic">👤</div>'
    + '<input id="pe-name" value="'+esc(ME.name)+'" placeholder="Имя"></div>'
    + '<div class="pe-field"><div class="pe-ic">@</div>'
    + '<input id="pe-user" value="'+esc(ME.username)+'" placeholder="Юзернейм"></div>'
    + '<div class="pe-field"><div class="pe-ic">✏</div>'
    + '<input id="pe-bio" value="'+esc(ME.bio||'')+'" placeholder="Описание профиля"></div>'
    + '</div>'
    + '<div class="username-hint" id="un-hint-profile" style="padding:.4rem 1rem"></div>';
  onceTap($('#pe-av'), function(){
    var inp = document.createElement('input'); inp.type='file'; inp.accept='image/*';
    inp.onchange = function(){
      var f = inp.files[0]; if (!f) return;
      var fd = new FormData(); fd.append('file', f);
      api('/api/avatar', {method:'POST', body: fd}).then(function(r){
        ME.avatar = r.avatar; renderProfileEdit(); fillDrawerUser();
      }).catch(function(e){ alert(e.message); });
    };
    inp.click();
  });
  var unInp = $('#pe-user'), hint = $('#un-hint-profile'), tmr = null;
  unInp.addEventListener('input', function(){
    clearTimeout(tmr);
    var v = unInp.value.trim().replace(/^@/,'');
    if (v === ME.username || v.length < 3){ hint.textContent = ''; return; }
    tmr = setTimeout(function(){
      api('/api/check_username?u=' + encodeURIComponent(v) + '&current=' + encodeURIComponent(ME.username))
        .then(function(r){
          hint.className = 'username-hint ' + (r.available ? 'ok' : 'bad');
          hint.textContent = (r.available ? '✓ ' : '✗ ') + r.reason;
        }).catch(function(){ hint.textContent = ''; });
    }, 400);
  });
}

function saveProfile(){
  var d = {};
  var n = $('#pe-name').value.trim();
  var un = $('#pe-user').value.trim().replace(/^@/,'');
  var bio = $('#pe-bio').value.trim();
  if (n !== ME.name) d.name = n;
  if (un !== ME.username) d.username = un;
  if (bio !== (ME.bio||'')) d.bio = bio;
  if (!Object.keys(d).length){ showScreen('chats'); return; }
  api('/api/me', {method:'PATCH', body: d}).then(function(){ return api('/api/me'); })
    .then(function(u){ ME = u; fillDrawerUser(); return loadChats(); })
    .then(function(){ showScreen('chats'); renderChatList(); })
    .catch(function(e){ alert(e.message); });
}

function changePassword(){
  var m = modal('<div class="modal-title">Изменить пароль</div>'
    + '<input class="modal-input" id="pw-old" type="password" placeholder="Старый пароль">'
    + '<input class="modal-input" id="pw-new" type="password" placeholder="Новый пароль">'
    + '<button class="primary-btn" id="pw-save">Сохранить</button>');
  onceTap(m.querySelector('#pw-save'), function(){
    api('/api/me', {method:'PATCH', body:{
      password: m.querySelector('#pw-new').value,
      old_password: m.querySelector('#pw-old').value
    }}).then(function(){ m.remove(); alert('Пароль изменён'); }).catch(function(e){ alert(e.message); });
  });
}

function renderAbout(){
  $('#about-body').innerHTML =
    '<div class="about-page">'
    + '<img src="/static/icon.svg" class="about-logo" alt="">'
    + '<div class="about-title">Голубь</div>'
    + '<div class="about-ver">v'+APP_VERSION+' · локальная сеть</div>'
    + '<p class="about-text">Свободный и локальный мессенджер с шифрованием, разработанный ИИ.</p>'
    + '<p class="about-text">Сообщения и файлы шифруются на сервере (Fernet / AES-128-CBC + HMAC). Пароли — PBKDF2-SHA256.</p>'
    + '<p class="about-text">Секретные чаты — E2E через WebCrypto (ECDH P-256 + AES-GCM). Звонки — WebRTC P2P (аудио).</p>'
    + '<a class="primary-btn" href="https://github.com/s05623821-creator/messenger-D-ove-" target="_blank" rel="noopener" style="display:block;text-decoration:none;margin-top:1rem">GitHub</a>'
    + '<a class="primary-btn" href="https://t.me/+q8KZwVuPrTswOTcy" target="_blank" rel="noopener" style="display:block;text-decoration:none;margin-top:.5rem;background:#229ED9">Telegram-канал</a>'
    + '</div>';
}

/* ---------- INFO ---------- */
function showInfo(id){
  api('/api/chats/'+id).then(function(c){
    var cur = null; for (var i=0; i<CHATS.length; i++) if (CHATS[i].id === id) cur = CHATS[i];
    if (!cur) cur = {};
    if (c.type === 'dm' || c.type === 'secret'){
      var p = c.peer;
      if (!p){ $('#info-body').innerHTML = '<div class="empty-list">Недоступно</div>'; showScreen('info'); return; }
      var av = p.avatar ? '<img src="/api/avatars/'+p.avatar+'">' : initial(p.name);
      var actions = '<div class="info-action" data-a="open">💬 Написать</div>';
      if (c.blocked_by_me) actions += '<div class="info-action" data-a="unblock">✅ Разблокировать</div>';
      else if (c.type === 'dm') actions += '<div class="info-action danger" data-a="block">🚫 Заблокировать</div>';
      if (c.is_dev_local && p && p.id !== ME.id)
        actions += '<div class="info-action danger" data-a="ban">⛔ Забанить</div>';
      var statusText = fmtStatus(p.status, p.last_seen);
      var statusHtml = '<div style="text-align:center;padding:.2rem 1rem .8rem">'
        + '<span class="status-inline '+p.status+'"><span class="dot"></span>'+statusText+'</span></div>';
      if (c.type === 'secret') statusHtml += '<div style="text-align:center;color:var(--tg-accent);font-size:.85rem;margin-bottom:.8rem">🔒 Секретный чат (E2E)</div>';
      $('#info-body').innerHTML =
        '<div class="info-hero"><div class="info-av">'+av+'</div>'
        + '<div class="info-name">'+esc(p.name)+'</div>'
        + '<div class="info-type">@'+esc(p.username)+'</div></div>'
        + statusHtml
        + (p.bio ? '<div style="text-align:center;padding:0 1rem 1rem;color:var(--tg-text-muted);font-size:.9rem">'+esc(p.bio)+'</div>' : '')
        + '<div class="info-actions">'+actions+'</div>'
        + '<div class="section-label">Информация</div>'
        + '<div class="card info-rows">'
        + '<div class="info-row"><div class="sr-ic bg-blue">@</div>'
        + '<div class="ir-v">@'+esc(p.username)+'<div class="ir-l">юзернейм</div></div></div>'
        + '<div class="info-row"><div class="sr-ic bg-green">👤</div>'
        + '<div class="ir-v">'+esc(p.name)+'<div class="ir-l">имя</div></div></div></div>';
      showScreen('info');
      var acts = $('#info-body').querySelectorAll('.info-action');
      for (var i2=0; i2<acts.length; i2++){
        (function(el){
          var a = el.getAttribute('data-a');
          onceTap(el, function(){
            if (a === 'open') showScreen('chat');
            else if (a === 'block'){
              if (!confirm('Заблокировать?')) return;
              api('/api/blocks/'+p.id, {method:'POST'}).then(function(){ showInfo(id); }).catch(function(e){ alert(e.message); });
            }
            else if (a === 'unblock'){
              api('/api/blocks/'+p.id, {method:'DELETE'}).then(function(){ showInfo(id); }).catch(function(e){ alert(e.message); });
            }
            else if (a === 'ban'){
              if (!confirm('Забанить?')) return;
              api('/api/dev/users/'+p.id+'/ban', {method:'POST', body:{value:true}}).then(function(){ showInfo(id); }).catch(function(e){ alert(e.message); });
            }
          });
        })(acts[i2]);
      }
      return;
    }
    var gav = cur.avatar ? '<img src="/api/avatars/'+cur.avatar+'">' : initial(cur.title);
    var typeText = c.type === 'group' ? 'Группа' : 'Канал';
    var invite = c.invite_hash ? (location.origin + '/j/' + c.invite_hash) : '';
    var descHtml = c.description ? '<div style="padding:0 1rem .8rem;color:var(--tg-text-muted);font-size:.9rem;text-align:center">'+esc(c.description)+'</div>' : '';
    var inviteHtml = '';
    if (invite){
      inviteHtml = '<div style="padding:0 1rem .8rem"><div class="muted" style="font-size:.8rem;margin-bottom:.3rem">Ссылка-приглашение</div>'
        + '<div class="invite-link"><input readonly value="'+esc(invite)+'" id="inv-input">'
        + '<button class="sp-act" id="inv-copy">Копировать</button></div></div>';
    }
    var membersHtml = '<div class="section-label">Участники</div><div class="card">';
    c.members.forEach(function(u){
      var adm = u.is_admin ? '<span class="badge-admin">админ</span>' : '';
      membersHtml += '<div class="member-row" data-uid="'+u.id+'">'
        + '<div class="ur-av">'+(u.avatar ? '<img src="/api/avatars/'+u.avatar+'">' : initial(u.name))+'</div>'
        + '<div class="ur-body"><div class="ur-name">'+esc(u.name)+' '+adm+'</div>'
        + '<div class="ur-user">@'+esc(u.username)+'</div></div></div>';
    });
    membersHtml += '</div>';
    var addHtml = '';
    if (c.my_perms && (c.my_perms.is_admin || c.my_perms.can_invite)){
      addHtml = '<div class="section-label">Добавить участника</div>'
        + '<div class="card" style="padding:.7rem">'
        + '<input class="modal-input" id="add-un" placeholder="@юзернейм" style="width:100%">'
        + '<button class="primary-btn" id="add-btn" style="margin-top:.6rem">Добавить</button></div>';
    }
    var permsHtml = '';
    if (c.my_perms && c.my_perms.is_admin){
      permsHtml = '<div class="section-label">Настройки</div><div class="card">'
        + '<div class="settings-row" data-act="edit_chat"><div class="sr-ic bg-blue">✏</div>'
        + '<div class="sr-body"><div class="sr-title">Редактировать</div></div>'
        + '<div class="sr-arrow">›</div></div>'
        + '<div class="settings-row" data-act="slow"><div class="sr-ic bg-orange">🐌</div>'
        + '<div class="sr-body"><div class="sr-title">Медленный режим</div>'
        + '<div class="sr-sub">'+(c.slow_mode ? c.slow_mode+' сек' : 'выкл')+'</div></div>'
        + '<div class="sr-arrow">›</div></div>'
        + '<div class="settings-row" data-act="rotate_inv"><div class="sr-ic bg-teal">🔄</div>'
        + '<div class="sr-body"><div class="sr-title">Сменить ссылку</div></div>'
        + '<div class="sr-arrow">›</div></div></div>';
    }
    $('#info-body').innerHTML =
      '<div class="info-hero"><div class="info-av">'+gav+'</div>'
      + '<div class="info-name">'+esc(c.name||cur.title||'Чат')+'</div>'
      + '<div class="info-type">'+typeText+' · '+c.members.length+' участн.</div></div>'
      + descHtml + inviteHtml + addHtml + permsHtml + membersHtml;
    showScreen('info');
    var cp = $('#inv-copy');
    if (cp) onceTap(cp, function(){
      var inp = $('#inv-input'); inp.select();
      try { document.execCommand('copy'); alert('Скопировано'); } catch(e){}
    });
    var ab = $('#add-btn');
    if (ab) onceTap(ab, function(){
      var un = $('#add-un').value.trim(); if (!un) return;
      api('/api/chats/'+id+'/members', {method:'POST', body:{username:un}})
        .then(function(){ showInfo(id); }).catch(function(e){ alert(e.message); });
    });
    onceTap($('#info-body'), function(ev){
      var row = ev.target.closest ? ev.target.closest('.settings-row') : null;
      if (row){
        var act = row.getAttribute('data-act');
        if (act === 'edit_chat') editChatDialog(id, c);
        else if (act === 'slow') slowModeDialog(id, c);
        else if (act === 'rotate_inv'){
          if (!confirm('Обновить ссылку?')) return;
          api('/api/chats/'+id+'/rotate_invite', {method:'POST'}).then(function(r){
            alert('Новая ссылка: ' + location.origin + '/j/' + r.invite);
            showInfo(id);
          }).catch(function(e){ alert(e.message); });
        }
        return;
      }
      var mrow = ev.target.closest ? ev.target.closest('.member-row') : null;
      if (mrow){
        var uid = parseInt(mrow.getAttribute('data-uid'),10);
        if (uid === ME.id) return;
        showMemberPerms(id, uid, c);
      }
    });
  }).catch(function(e){ alert(e.message); showScreen('chats'); });
}

function showMemberPerms(cid, uid, chat){
  var m = null;
  chat.members.forEach(function(u){ if (u.id === uid) m = u; });
  if (!m) return;
  var canEdit = chat.my_perms && chat.my_perms.is_admin;
  var mm = modal('<div class="modal-title">'+esc(m.name)+'</div>'
    + '<div style="padding:.2rem .5rem"><div class="muted" style="font-size:.8rem;margin-bottom:.5rem">@'+esc(m.username)+'</div>'
    + permRow('is_admin', 'Администратор', m.is_admin, canEdit)
    + permRow('can_send', 'Писать сообщения', m.can_send, canEdit)
    + permRow('can_invite', 'Приглашать', m.can_invite, canEdit)
    + permRow('can_pin', 'Закреплять', m.can_pin, canEdit)
    + permRow('can_delete', 'Удалять сообщения', m.can_delete, canEdit)
    + '</div>'
    + '<button class="primary-btn" id="mp-save">Сохранить</button>');
  onceTap(mm.querySelector('#mp-save'), function(){
    var d = {};
    var cbs = mm.querySelectorAll('input[type=checkbox]');
    for (var i=0; i<cbs.length; i++) d[cbs[i].getAttribute('data-k')] = cbs[i].checked;
    api('/api/chats/'+cid+'/member/'+uid, {method:'PATCH', body: d})
      .then(function(){ mm.remove(); showInfo(cid); }).catch(function(e){ alert(e.message); });
  });
}
function permRow(key, label, val, enabled){
  return '<label class="check-row"><input type="checkbox" data-k="'+key+'"'+(val?' checked':'')+(enabled?'':' disabled')+'>'
    + '<span>'+label+'</span></label>';
}

function editChatDialog(cid, c){
  var m = modal('<div class="modal-title">Редактировать</div>'
    + '<input class="modal-input" id="ec-name" value="'+esc(c.name||'')+'" placeholder="Название">'
    + '<input class="modal-input" id="ec-desc" value="'+esc(c.description||'')+'" placeholder="Описание">'
    + '<button class="primary-btn" id="ec-save">Сохранить</button>');
  onceTap(m.querySelector('#ec-save'), function(){
    api('/api/chats/'+cid, {method:'PATCH', body:{
      name: m.querySelector('#ec-name').value,
      description: m.querySelector('#ec-desc').value
    }}).then(function(){ m.remove(); loadChats().then(function(){ showInfo(cid); }); })
      .catch(function(e){ alert(e.message); });
  });
}

function slowModeDialog(cid, c){
  var m = modal('<div class="modal-title">Медленный режим</div>'
    + '<p class="muted" style="text-align:center">Пауза между сообщениями (сек, 0 = выкл)</p>'
    + '<input class="modal-input" id="sm-val" type="number" value="'+(c.slow_mode||0)+'">'
    + '<button class="primary-btn" id="sm-save">Сохранить</button>');
  onceTap(m.querySelector('#sm-save'), function(){
    var v = parseInt(m.querySelector('#sm-val').value,10) || 0;
    api('/api/chats/'+cid, {method:'PATCH', body:{slow_mode: v}})
      .then(function(){ m.remove(); loadChats().then(function(){ showInfo(cid); }); })
      .catch(function(e){ alert(e.message); });
  });
}

/* ---------- NEW CHAT ---------- */
function newChat(){
  var m = modal('<div class="modal-title">Новый чат</div>'
    + '<div class="seg">'
    + '<button class="on" data-t="dm">Личный</button>'
    + '<button data-t="group">Группа</button>'
    + '<button data-t="channel">Канал</button>'
    + '<button data-t="secret">🔒 Секрет</button>'
    + '</div>'
    + '<div id="nc-body"></div>');
  var body = m.querySelector('#nc-body');
  function render(t){
    if (t === 'dm' || t === 'secret'){
      api('/api/users').then(function(users){
        if (!users.length){ body.innerHTML = '<div class="muted" style="text-align:center;padding:1.2rem">Нет пользователей</div>'; return; }
        body.innerHTML = '<div class="list-scroll"></div>';
        var sc = body.querySelector('.list-scroll');
        users.forEach(function(u){
          var el = document.createElement('div');
          el.className = 'user-row';
          el.innerHTML = '<div class="ur-av">'+(u.avatar?'<img src="/api/avatars/'+u.avatar+'">':initial(u.name))+'</div>'
            + '<div class="ur-body"><div class="ur-name">'+esc(u.name)+'</div>'
            + '<div class="ur-user">'+esc(fmtStatus(u.status, u.last_seen))+'</div></div>';
          onceTap(el, function(){
            api('/api/chats', {method:'POST', body:{type:t, user_id:u.id}}).then(function(r){
              m.remove(); loadChats().then(function(){ renderChatList(); openChat(r.id); });
            }).catch(function(e){ alert(e.message); });
          });
          sc.appendChild(el);
        });
      }).catch(function(e){ alert(e.message); });
    } else {
      body.innerHTML = '<input class="modal-input" id="nc-name" placeholder="Название" style="margin-bottom:.5rem">'
        + '<textarea class="modal-input" id="nc-desc" placeholder="Описание (необязательно)" rows="2" style="resize:none"></textarea>'
        + '<button class="primary-btn" id="nc-create" style="margin-top:.6rem">Создать</button>';
      onceTap(body.querySelector('#nc-create'), function(){
        var name = body.querySelector('#nc-name').value.trim();
        var desc = body.querySelector('#nc-desc').value.trim();
        if (!name) return;
        api('/api/chats', {method:'POST', body:{type:t, name: name, description: desc}}).then(function(r){
          m.remove(); loadChats().then(function(){ renderChatList(); openChat(r.id); });
        }).catch(function(e){ alert(e.message); });
      });
    }
  }
  var segs = m.querySelectorAll('.seg button');
  for (var i=0; i<segs.length; i++){
    (function(seg){
      onceTap(seg, function(){
        var ss = m.querySelectorAll('.seg button');
        for (var j=0; j<ss.length; j++) ss[j].classList.toggle('on', ss[j]===seg);
        render(seg.getAttribute('data-t'));
      });
    })(segs[i]);
  }
  render('dm');
}

/* ---------- POLL ---------- */
function createPollDialog(){
  var m = modal('<div class="modal-title">Новый опрос</div>'
    + '<input class="modal-input" id="poll-q" placeholder="Вопрос">'
    + '<div id="poll-opts"></div>'
    + '<button class="sp-act" id="poll-add-opt" style="margin-top:.5rem">＋ Вариант</button>'
    + '<label class="check-row"><input type="checkbox" id="poll-multi"><span>Несколько ответов</span></label>'
    + '<label class="check-row"><input type="checkbox" id="poll-anon" checked><span>Анонимный</span></label>'
    + '<button class="primary-btn" id="poll-save">Создать</button>');
  var opts = $('#poll-opts');
  function addOpt(){
    var d = document.createElement('div');
    d.innerHTML = '<input class="modal-input" placeholder="Вариант" style="margin-bottom:.4rem">';
    opts.appendChild(d);
  }
  addOpt(); addOpt();
  onceTap(m.querySelector('#poll-add-opt'), addOpt);
  onceTap(m.querySelector('#poll-save'), function(){
    var q = m.querySelector('#poll-q').value.trim();
    var arr = [];
    var ins = opts.querySelectorAll('input');
    for (var i=0; i<ins.length; i++){ var v = ins[i].value.trim(); if (v) arr.push(v); }
    if (!q || arr.length < 2){ alert('Введите вопрос и 2+ варианта'); return; }
    api('/api/chats/'+ACTIVE+'/polls', {method:'POST', body:{
      question: q, options: arr,
      multiple: m.querySelector('#poll-multi').checked,
      anonymous: m.querySelector('#poll-anon').checked
    }}).then(function(){ m.remove(); pollMessages(); }).catch(function(e){ alert(e.message); });
  });
}

function modal(html){
  var m = document.createElement('div');
  m.className = 'modal';
  m.innerHTML = '<div class="modal-card">'+html+'</div>';
  m.onclick = function(e){ if (e.target === m) m.remove(); };
  document.body.appendChild(m);
  return m;
}

/* ---------- INVITES ---------- */
function joinInvite(hash){
  api('/api/join/'+hash, {method:'POST'}).then(function(r){
    var m = $('#invite-modal');
    m.classList.remove('hidden');
    onceTap($('#invite-accept'), function(){
      m.classList.add('hidden');
      history.replaceState(null, '', '/');
      loadChats().then(function(){ renderChatList(); openChat(r.id); });
    });
    onceTap($('#invite-cancel'), function(){ m.classList.add('hidden'); history.replaceState(null, '', '/'); });
  }).catch(function(e){ alert(e.message); history.replaceState(null, '', '/'); });
}

/* ---------- CALLS (audio only) ---------- */
function startIncomingCallPoll(){
  setInterval(function(){
    if (CALL_ID) return;
    api('/api/calls/incoming').then(function(c){
      if (!c) return;
      if (confirm(c.caller.name + ' звонит. Принять?')){
        joinCall(c.id, 'callee');
      } else {
        api('/api/calls/'+c.id, {method:'DELETE'}).catch(function(){});
      }
    }).catch(function(){});
  }, 4000);
}

function startCall(){
  if (!ACTIVE) return;
  var c = null; for (var i=0;i<CHATS.length;i++) if (CHATS[i].id===ACTIVE) c = CHATS[i];
  if (!c || (c.type !== 'dm' && c.type !== 'secret')){ alert('Звонки только в личных чатах'); return; }
  if (!c.peer_id){ alert('Нет собеседника'); return; }
  if (location.protocol !== 'https:' && location.hostname !== '127.0.0.1' && location.hostname !== 'localhost'){
    alert('Звонки работают только на https:// или http://127.0.0.1 — браузер блокирует микрофон на других адресах');
    return;
  }
  api('/api/calls/start', {method:'POST', body:{callee_id: c.peer_id, chat_id: ACTIVE}})
    .then(function(r){ joinCall(r.id, 'caller'); })
    .catch(function(e){ alert(e.message); });
}

function joinCall(cid, role){
  CALL_ID = cid; CALL_ROLE = role;
  $('#call-screen').classList.remove('hidden');
  $('#call-status').textContent = 'Соединение…';
  navigator.mediaDevices.getUserMedia({audio:true, video:false})
    .then(function(stream){
      LOCAL_STREAM = stream;
      PC = new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
      stream.getTracks().forEach(function(t){ PC.addTrack(t, stream); });
      PC.onicecandidate = function(e){
        if (e.candidate) api('/api/calls/'+cid+'/signal', {method:'POST', body:{ice: e.candidate}}).catch(function(){});
      };
      PC.ontrack = function(e){
        $('#call-remote').srcObject = e.streams[0];
        $('#call-status').textContent = 'В разговоре';
      };
      if (role === 'caller'){
        PC.createOffer().then(function(off){
          return PC.setLocalDescription(off).then(function(){
            return api('/api/calls/'+cid+'/signal', {method:'POST', body:{offer: off}});
          });
        }).catch(function(e){ alert(e.message); endCall(); });
      }
      startCallSignalPoll();
    }).catch(function(e){
      alert('Микрофон недоступен: ' + e.message);
      endCall();
    });
}

function startCallSignalPoll(){
  clearInterval(CALL_POLL);
  CALL_POLL = setInterval(function(){
    if (!CALL_ID) return;
    api('/api/calls/'+CALL_ID).then(function(s){
      if (s.state === 'ended'){ endCall(); return; }
      if (CALL_ROLE === 'callee' && s.offer && !PC.currentRemoteDescription){
        PC.setRemoteDescription(new RTCSessionDescription(s.offer)).then(function(){
          return PC.createAnswer();
        }).then(function(ans){
          return PC.setLocalDescription(ans).then(function(){
            return api('/api/calls/'+CALL_ID+'/signal', {method:'POST', body:{answer: ans}});
          });
        }).catch(function(e){ console.error(e); });
      }
      if (CALL_ROLE === 'caller' && s.answer && !PC.currentRemoteDescription){
        PC.setRemoteDescription(new RTCSessionDescription(s.answer)).catch(function(e){});
      }
      (s.ice||[]).forEach(function(cand){
        PC.addIceCandidate(new RTCIceCandidate(cand)).catch(function(){});
      });
    }).catch(function(){});
  }, 1500);
}

function endCall(){
  if (CALL_ID) api('/api/calls/'+CALL_ID, {method:'DELETE'}).catch(function(){});
  clearInterval(CALL_POLL); CALL_POLL = null;
  if (PC){ try { PC.close(); } catch(e){} PC = null; }
  if (LOCAL_STREAM){ LOCAL_STREAM.getTracks().forEach(function(t){ t.stop(); }); LOCAL_STREAM = null; }
  CALL_ID = null; CALL_ROLE = null;
  $('#call-screen').classList.add('hidden');
  $('#call-remote').srcObject = null;
}

/* ---------- NOTIFICATIONS ---------- */
var LAST_NOTIF_MSG = {};
function checkNotifications(){
  CHATS.forEach(function(c){
    if (!c.last) return;
    if (c.last.sender === ME.name) return;
    var key = c.id;
    if (LAST_NOTIF_MSG[key] === c.last.id) return;
    if (!Object.keys(LAST_NOTIF_MSG).length){ LAST_NOTIF_MSG[key] = c.last.id; return; }
    LAST_NOTIF_MSG[key] = c.last.id;
    try {
      if (Notification.permission === 'granted' && document.hidden){
        new Notification('Голубь · ' + c.title, {body: c.last.sender + ': ' + (c.last.text || 'файл'), tag: 'golub-'+c.id});
      }
    } catch(e){}
  });
}

/* ---------- INIT ---------- */
function init(){
  bindBacks();
  onceTap($('#btn-menu'), openDrawer);
  onceTap($('#backdrop'), closeDrawer);
  onceTap($('#drawer-nav'), function(e){
    var btn = e.target.closest ? e.target.closest('button[data-act]') : null;
    if (!btn) return;
    onDrawerClick(btn);
  });
  $('#q').oninput = renderChatList;
  onceTap($('#btn-new'), newChat);
  onceTap($('#chat-back'), function(){
    ACTIVE = null; showScreen('chats'); renderChatList(); closeStickers(); clearReply();
  });
  onceTap($('#chat-title-wrap'), function(){ if (ACTIVE) showInfo(ACTIVE); });
  onceTap($('#chat-menu-btn'), function(e){ if (e) e.stopPropagation(); showChatMenu($('#chat-menu-btn')); });
  onceTap($('#btn-search-msg'), openSearchScreen);
  $('#msg-search-q').addEventListener('input', doMsgSearch);
  onceTap($('#reply-close'), clearReply);
  $('#composer').onsubmit = function(e){
    e.preventDefault();
    var inp = $('#msg');
    var text = inp.value.trim(); if (!text) return;
    inp.value = ''; sendText(text);
  };
  $('#msg').addEventListener('input', function(){
    if (!ACTIVE) return;
    var now = Date.now();
    if (now - LAST_TYPING_SENT < 1500) return;
    LAST_TYPING_SENT = now;
    api('/api/chats/'+ACTIVE+'/typing', {method:'POST', body:{}}).catch(function(){});
  });
  $('#file').onchange = function(e){
    if (e.target.files && e.target.files.length)
      uploadAndSendFiles(e.target.files).catch(function(err){ alert(err.message); });
    e.target.value = '';
  };
  onceTap($('#btn-voice'), startVoiceRec);
  onceTap($('#btn-stickers'), function(){
    if (STICKERS_OPEN) closeStickers(); else openStickers();
  });
  onceTap($('#btn-poll'), function(){
    if (!ACTIVE){ alert('Сначала откройте чат'); return; }
    createPollDialog();
  });
  onceTap($('#prof-save'), saveProfile);
  onceTap($('#folder-add'), newFolderDialog);
  onceTap($('#btn-call'), function(){
    if (!ACTIVE){ alert('Откройте чат'); return; }
    if (confirm('Позвонить ' + (CURRENT_PEER && CURRENT_PEER.name ? CURRENT_PEER.name : 'собеседнику') + '?'))
      startCall();
  });
  onceTap($('#call-end'), endCall);
  onceTap($('#call-mute'), function(){
    if (LOCAL_STREAM) LOCAL_STREAM.getAudioTracks().forEach(function(t){ t.enabled = !t.enabled; });
  });
  document.addEventListener('keydown', function(e){
    if (e.key === 'Escape'){
      if ($('#drawer').classList.contains('open')) closeDrawer();
      var m = document.querySelector('.modal'); if (m) m.remove();
      closeStickers();
      var p = document.querySelector('.popover'); if (p) p.remove();
      if (SCREEN === 'search') showScreen('chat');
      clearReply();
    }
  });
  if ('Notification' in window && Notification.permission === 'default'){
    setTimeout(function(){ try { Notification.requestPermission(); } catch(e){} }, 5000);
  }
  boot();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
