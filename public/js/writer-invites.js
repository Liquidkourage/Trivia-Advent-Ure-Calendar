(function () {
  const tbody = document.querySelector('#tbl tbody');
  const out = document.getElementById('out');
  const resultsPanel = document.getElementById('resultsPanel');
  const resultsList = document.getElementById('resultsList');

  function renumber() {
    Array.from(tbody.querySelectorAll('tr')).forEach(function (tr, i) {
      var idx = tr.querySelector('.idx');
      if (idx) idx.textContent = String(i + 1);
    });
  }

  function rows() {
    return Array.from(tbody.querySelectorAll('tr'))
      .map(function (tr) {
        return {
          author: (tr.querySelector('input[name="author"]').value || '').trim(),
          email: (tr.querySelector('input[name="email"]').value || '').trim(),
          slotDate: tr.querySelector('input[name="slotDate"]').value,
          slotHalf: (tr.querySelector('input[name="slotHalf"]').value || '').toUpperCase()
        };
      })
      .filter(function (r) { return r.author || r.email; });
  }

  function toCsv(data) {
    var esc = function (v) { return '"' + String(v || '').replace(/"/g, '""') + '"'; };
    var lines = ['Author,Email,SlotDate,Half'];
    data.forEach(function (r) {
      lines.push([r.author, r.email, r.slotDate, r.slotHalf].map(esc).join(','));
    });
    return lines.join('\n');
  }

  var STORAGE_KEY = 'ta_writer_invites_v1';
  function save() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(rows())); } catch (e) {}
  }
  function load() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      var data = JSON.parse(raw);
      var trs = Array.from(tbody.querySelectorAll('tr'));
      for (var i = 0; i < trs.length && i < data.length; i++) {
        var r = data[i] || {};
        if (r.author) trs[i].querySelector('input[name="author"]').value = r.author;
        if (r.email) trs[i].querySelector('input[name="email"]').value = r.email;
      }
    } catch (e) {}
  }

  Array.from(tbody.querySelectorAll('.rm')).forEach(function (btn) {
    btn.addEventListener('click', function () {
      var tr = this.closest('tr');
      if (tr) { tr.remove(); renumber(); save(); }
    });
  });

  tbody.addEventListener('input', function (e) {
    if (e.target && (e.target.name === 'author' || e.target.name === 'email')) save();
  });

  renumber();
  load();

  var downloadBtn = document.getElementById('downloadCsv');
  if (downloadBtn) {
    downloadBtn.addEventListener('click', function () {
      var data = rows();
      if (!data.length) { out.textContent = 'Add at least one row.'; return; }
      var csv = toCsv(data);
      var blob = new Blob([csv], { type: 'text/csv' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'writer_invites.csv';
      a.click();
      URL.revokeObjectURL(a.href);
      out.textContent = 'CSV downloaded.';
    });
  }

  var genBtn = document.getElementById('generateLinks');
  if (genBtn) {
    genBtn.addEventListener('click', function () { generateLinks(); });
  }

  async function generateLinks() {
    var data = rows();
    if (!data.length) { out.textContent = 'Add at least one row.'; return; }
    out.textContent = 'Generating...';
    var results = [];
    for (var i = 0; i < data.length; i++) {
      var r = data[i];
      try {
        var body = new URLSearchParams();
        body.append('author', r.author);
        if (r.email) body.append('email', r.email);
        if (r.slotDate) body.append('slotDate', r.slotDate);
        if (r.slotHalf) body.append('slotHalf', r.slotHalf);
        var res = await fetch('/admin/writer-invite', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: body
        });
        var text = await res.text();
        if (!res.ok) throw new Error(text || 'Failed');
        results.push({ author: r.author || '(no name)', link: text });
      } catch (e) {
        results.push(r.author + ': ERROR ' + (e && e.message ? e.message : 'Failed'));
      }
    }
    // Render results
    var html = '';
    for (var j = 0; j < results.length; j++) {
      var item = results[j];
      if (typeof item === 'string') {
        html += '<div style="color:#ff6b6b;">' + item + '</div>';
      } else {
        var a = item;
        html += '<div class="result-row" style="display:flex;gap:8px;align-items:center;">'
              + '<strong style="min-width:160px;">' + a.author + ':</strong>'
              + '<a href="' + a.link + '" target="_blank" style="color:#ffd700;word-break:break-all;">' + a.link + '</a>'
              + '<button class="copy" data-link="' + a.link + '" style="margin-left:auto;background:#d4af37;color:#000;border:none;border-radius:6px;padding:4px 8px;cursor:pointer;">Copy</button>'
              + '</div>';
      }
    }
    resultsList.innerHTML = html;
    resultsPanel.style.display = 'block';
    out.textContent = 'Done - ' + results.length + ' link(s) generated.';

    resultsList.addEventListener('click', function (e) {
      var btn = e.target.closest('.copy');
      if (!btn) return;
      var link = btn.getAttribute('data-link');
      navigator.clipboard.writeText(link).then(function () {
        var old = btn.textContent; btn.textContent = 'Copied'; setTimeout(function () { btn.textContent = old; }, 1000);
      }).catch(function () {});
    }, { once: true });
    resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
})();


