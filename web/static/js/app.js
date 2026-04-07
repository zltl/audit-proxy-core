/* ============================================================
   SSH Proxy Core — App JavaScript
   Vanilla JS with App namespace
   ============================================================ */

(function (window, document) {
  'use strict';

  const App = {};

  // ── CSRF ──────────────────────────────────────────────────
  App.csrfToken = function () {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  };

  // ── API Fetch Wrapper ─────────────────────────────────────
  App.api = async function (method, url, body) {
    const opts = {
      method: method.toUpperCase(),
      headers: {
        'Accept': 'application/json',
        'X-CSRF-Token': App.csrfToken(),
      },
      credentials: 'same-origin',
    };

    if (body && typeof body === 'object') {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }

    try {
      const res = await fetch(url, opts);
      const text = await res.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch (_) {
        data = text;
      }

      if (!res.ok) {
        const msg = (data && data.error) || (data && data.message) || res.statusText;
        throw { status: res.status, message: msg, data: data };
      }
      return data;
    } catch (err) {
      if (err.status) throw err;
      throw { status: 0, message: 'Network error: ' + err.message, data: null };
    }
  };

  // ── Toast Notifications ───────────────────────────────────
  const toastIcons = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ',
  };

  App.notify = function (message, type) {
    type = type || 'info';
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.innerHTML =
      '<span class="toast-icon">' + (toastIcons[type] || 'ℹ') + '</span>' +
      '<span class="toast-message">' + App.escapeHtml(message) + '</span>' +
      '<button class="toast-close" onclick="this.parentElement.remove()">✕</button>';

    container.appendChild(toast);

    // Auto dismiss after 5 seconds
    setTimeout(function () {
      toast.classList.add('hide');
      setTimeout(function () { toast.remove(); }, 300);
    }, 5000);
  };

  // ── Modal System ──────────────────────────────────────────
  App.modal = function (title, content, actions) {
    // Remove existing generic modal
    const existing = document.getElementById('app-modal-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'app-modal-overlay';
    overlay.className = 'modal-overlay';

    let actionsHtml = '';
    if (actions && actions.length) {
      actionsHtml = '<div class="modal-footer">';
      actions.forEach(function (a) {
        actionsHtml += '<button class="btn ' + (a.cls || 'btn-secondary') + '" data-action="' + (a.id || '') + '">' +
          App.escapeHtml(a.label) + '</button>';
      });
      actionsHtml += '</div>';
    }

    overlay.innerHTML =
      '<div class="modal">' +
        '<div class="modal-header">' +
          '<h3 class="modal-title">' + App.escapeHtml(title) + '</h3>' +
          '<button class="modal-close" data-modal-close>✕</button>' +
        '</div>' +
        '<div class="modal-body">' + content + '</div>' +
        actionsHtml +
      '</div>';

    document.body.appendChild(overlay);

    // Wire close button
    overlay.querySelector('[data-modal-close]').addEventListener('click', function () {
      App.closeModal(overlay);
    });

    // Close on backdrop click
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) App.closeModal(overlay);
    });

    // Wire action buttons
    if (actions && actions.length) {
      actions.forEach(function (a) {
        const btn = overlay.querySelector('[data-action="' + a.id + '"]');
        if (btn && typeof a.onClick === 'function') {
          btn.addEventListener('click', function () { a.onClick(overlay); });
        }
      });
    }

    // Show with slight delay for transition
    requestAnimationFrame(function () { overlay.classList.add('show'); });

    return overlay;
  };

  App.closeModal = function (overlay) {
    if (!overlay) overlay = document.querySelector('.modal-overlay.show');
    if (!overlay) return;
    overlay.classList.remove('show');
    setTimeout(function () { overlay.remove(); }, 200);
  };

  // ── Confirm Dialog ────────────────────────────────────────
  App.confirm = function (message) {
    return new Promise(function (resolve) {
      App.modal('Confirm', '<p>' + App.escapeHtml(message) + '</p>', [
        {
          id: 'cancel',
          label: 'Cancel',
          cls: 'btn-secondary',
          onClick: function (o) { App.closeModal(o); resolve(false); },
        },
        {
          id: 'confirm',
          label: 'Confirm',
          cls: 'btn-primary',
          onClick: function (o) { App.closeModal(o); resolve(true); },
        },
      ]);
    });
  };

  // ── Table Enhancement ─────────────────────────────────────
  App.table = function (selector, options) {
    const table = document.querySelector(selector);
    if (!table) return;

    options = options || {};
    const tbody = table.querySelector('tbody');
    const headers = table.querySelectorAll('thead th.sortable');

    // Sorting
    headers.forEach(function (th, colIdx) {
      th.addEventListener('click', function () {
        const dir = th.classList.contains('sort-asc') ? 'desc' : 'asc';
        headers.forEach(function (h) { h.classList.remove('sort-asc', 'sort-desc'); });
        th.classList.add('sort-' + dir);

        const rows = Array.from(tbody.querySelectorAll('tr:not(.expandable-detail)'));
        rows.sort(function (a, b) {
          const aText = a.cells[colIdx].textContent.trim();
          const bText = b.cells[colIdx].textContent.trim();
          const aNum = parseFloat(aText);
          const bNum = parseFloat(bText);
          let cmp;
          if (!isNaN(aNum) && !isNaN(bNum)) {
            cmp = aNum - bNum;
          } else {
            cmp = aText.localeCompare(bText);
          }
          return dir === 'asc' ? cmp : -cmp;
        });
        rows.forEach(function (row) { tbody.appendChild(row); });
      });
    });

    // Select-all checkbox
    const selectAll = table.querySelector('thead .select-all');
    if (selectAll) {
      selectAll.addEventListener('change', function () {
        const checked = selectAll.checked;
        table.querySelectorAll('tbody .row-check').forEach(function (cb) {
          cb.checked = checked;
          cb.closest('tr').classList.toggle('selected', checked);
        });
        if (typeof options.onSelectionChange === 'function') options.onSelectionChange();
      });
    }

    // Row checkboxes
    table.querySelectorAll('tbody .row-check').forEach(function (cb) {
      cb.addEventListener('change', function () {
        cb.closest('tr').classList.toggle('selected', cb.checked);
        if (typeof options.onSelectionChange === 'function') options.onSelectionChange();
      });
    });

    return {
      getSelected: function () {
        return Array.from(table.querySelectorAll('tbody .row-check:checked')).map(function (cb) {
          return cb.value || cb.closest('tr').dataset.id;
        });
      },
    };
  };

  // ── Formatters ────────────────────────────────────────────
  App.formatTime = function (iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString('zh-CN', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    });
  };

  App.formatDuration = function (seconds) {
    if (seconds == null || isNaN(seconds)) return '—';
    seconds = Math.floor(seconds);
    if (seconds < 60) return seconds + 's';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + (seconds % 60) + 's';
    var h = Math.floor(seconds / 3600);
    var m = Math.floor((seconds % 3600) / 60);
    return h + 'h ' + m + 'm';
  };

  App.formatBytes = function (bytes) {
    if (bytes == null || isNaN(bytes)) return '—';
    if (bytes === 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.floor(Math.log(bytes) / Math.log(1024));
    i = Math.min(i, units.length - 1);
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
  };

  App.timeAgo = function (iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    var now = new Date();
    var diff = Math.floor((now - d) / 1000);
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  };

  // ── WebSocket with auto-reconnect ─────────────────────────
  App.ws = function (url, handlers) {
    handlers = handlers || {};
    var ws, reconnectTimer, attempts = 0;
    var maxAttempts = handlers.maxReconnect || 10;
    var baseDelay = 1000;

    function connect() {
      var protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      var fullUrl = url.startsWith('ws') ? url : protocol + '//' + location.host + url;

      ws = new WebSocket(fullUrl);

      ws.onopen = function () {
        attempts = 0;
        if (typeof handlers.onOpen === 'function') handlers.onOpen(ws);
      };

      ws.onmessage = function (e) {
        var data;
        try { data = JSON.parse(e.data); } catch (_) { data = e.data; }
        if (typeof handlers.onMessage === 'function') handlers.onMessage(data, ws);
      };

      ws.onclose = function (e) {
        if (typeof handlers.onClose === 'function') handlers.onClose(e);
        if (attempts < maxAttempts) {
          var delay = Math.min(baseDelay * Math.pow(2, attempts), 30000);
          attempts++;
          reconnectTimer = setTimeout(connect, delay);
        }
      };

      ws.onerror = function (e) {
        if (typeof handlers.onError === 'function') handlers.onError(e);
      };
    }

    connect();

    return {
      send: function (data) {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(typeof data === 'string' ? data : JSON.stringify(data));
        }
      },
      close: function () {
        clearTimeout(reconnectTimer);
        maxAttempts = 0;
        if (ws) ws.close();
      },
      getSocket: function () { return ws; },
    };
  };

  // ── Dark Mode ─────────────────────────────────────────────
  App.darkMode = {
    get: function () {
      var stored = localStorage.getItem('theme');
      if (stored) return stored === 'dark';
      return window.matchMedia('(prefers-color-scheme: dark)').matches;
    },
    set: function (dark) {
      document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
      localStorage.setItem('theme', dark ? 'dark' : 'light');
      var btn = document.getElementById('theme-toggle');
      if (btn) btn.textContent = dark ? '☀️' : '🌙';
    },
    toggle: function () {
      App.darkMode.set(!App.darkMode.get());
    },
    init: function () {
      App.darkMode.set(App.darkMode.get());
      var btn = document.getElementById('theme-toggle');
      if (btn) btn.addEventListener('click', App.darkMode.toggle);
    },
  };

  // ── Auto-Refresh ──────────────────────────────────────────
  App.autoRefresh = function (callback, intervalMs) {
    intervalMs = intervalMs || 30000;
    var timer = null;
    var running = false;

    function tick() {
      if (running) return;
      running = true;
      Promise.resolve(callback()).catch(function () {}).then(function () {
        running = false;
      });
    }

    return {
      start: function () {
        tick();
        timer = setInterval(tick, intervalMs);
      },
      stop: function () {
        clearInterval(timer);
        timer = null;
      },
      refresh: tick,
    };
  };

  // ── Utilities ─────────────────────────────────────────────
  App.escapeHtml = function (str) {
    if (!str) return '';
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  };

  App.qs = function (sel, parent) { return (parent || document).querySelector(sel); };
  App.qsa = function (sel, parent) { return Array.from((parent || document).querySelectorAll(sel)); };

  App.on = function (el, event, handler) {
    if (typeof el === 'string') el = document.querySelector(el);
    if (el) el.addEventListener(event, handler);
  };

  App.delegate = function (parent, selector, event, handler) {
    if (typeof parent === 'string') parent = document.querySelector(parent);
    if (!parent) return;
    parent.addEventListener(event, function (e) {
      var target = e.target.closest(selector);
      if (target && parent.contains(target)) handler.call(target, e);
    });
  };

  // ── Sidebar Collapse ──────────────────────────────────────
  App.sidebar = {
    init: function () {
      var sidebar = App.qs('.sidebar');
      var toggle = App.qs('.sidebar-collapse-btn');
      if (!sidebar || !toggle) return;

      var collapsed = localStorage.getItem('sidebar-collapsed') === 'true';
      if (collapsed) sidebar.classList.add('collapsed');

      toggle.addEventListener('click', function () {
        sidebar.classList.toggle('collapsed');
        localStorage.setItem('sidebar-collapsed', sidebar.classList.contains('collapsed'));
      });

      // Mobile
      var mobileToggle = App.qs('.mobile-menu-btn');
      var overlay = App.qs('.mobile-overlay');
      if (mobileToggle) {
        mobileToggle.addEventListener('click', function () {
          sidebar.classList.toggle('mobile-open');
          if (overlay) overlay.classList.toggle('show');
        });
      }
      if (overlay) {
        overlay.addEventListener('click', function () {
          sidebar.classList.remove('mobile-open');
          overlay.classList.remove('show');
        });
      }
    },
  };

  // ── Dropdown ──────────────────────────────────────────────
  App.dropdown = {
    init: function () {
      // Toggle
      App.delegate(document, '[data-dropdown-toggle]', 'click', function (e) {
        e.stopPropagation();
        var target = this.getAttribute('data-dropdown-toggle');
        var menu = document.getElementById(target);
        if (!menu) return;

        // Close others
        App.qsa('.dropdown-menu.show').forEach(function (m) {
          if (m !== menu) m.classList.remove('show');
        });

        menu.classList.toggle('show');
      });

      // Close on outside click
      document.addEventListener('click', function () {
        App.qsa('.dropdown-menu.show').forEach(function (m) {
          m.classList.remove('show');
        });
      });
    },
  };

  // ── Tabs ──────────────────────────────────────────────────
  App.tabs = {
    init: function () {
      App.delegate(document, '[data-tab]', 'click', function () {
        var tabGroup = this.closest('.tabs');
        var target = this.getAttribute('data-tab');

        // Deactivate all tabs in group
        App.qsa('.tab-item', tabGroup).forEach(function (t) { t.classList.remove('active'); });
        this.classList.add('active');

        // Find associated content container
        var container = tabGroup.parentElement;
        App.qsa('.tab-content', container).forEach(function (c) { c.classList.remove('active'); });
        var content = container.querySelector('#' + target);
        if (content) content.classList.add('active');
      });
    },
  };

  // ── Loading Helpers ───────────────────────────────────────
  App.showLoading = function (selector) {
    var el = App.qs(selector);
    if (!el) return;
    el.dataset.originalContent = el.innerHTML;
    var rows = parseInt(el.dataset.skeletonRows) || 5;
    var html = '';
    for (var i = 0; i < rows; i++) {
      html += '<div class="skeleton skeleton-row"></div>';
    }
    el.innerHTML = html;
  };

  App.hideLoading = function (selector) {
    var el = App.qs(selector);
    if (!el) return;
    if (el.dataset.originalContent) {
      el.innerHTML = el.dataset.originalContent;
      delete el.dataset.originalContent;
    }
  };

  // ── Button loading state ──────────────────────────────────
  App.btnLoading = function (btn, loading) {
    if (typeof btn === 'string') btn = App.qs(btn);
    if (!btn) return;
    if (loading) {
      btn.disabled = true;
      btn.dataset.originalText = btn.innerHTML;
      btn.innerHTML = '<span class="spinner"></span> Loading…';
    } else {
      btn.disabled = false;
      if (btn.dataset.originalText) {
        btn.innerHTML = btn.dataset.originalText;
        delete btn.dataset.originalText;
      }
    }
  };

  // ── Init ──────────────────────────────────────────────────
  App.init = function () {
    App.darkMode.init();
    App.sidebar.init();
    App.dropdown.init();
    App.tabs.init();
  };

  // Boot on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', App.init);
  } else {
    App.init();
  }

  // Expose globally
  window.App = App;

})(window, document);
