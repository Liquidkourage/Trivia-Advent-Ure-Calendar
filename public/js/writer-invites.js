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

  function markDuplicateSlots() {
    var trs = Array.from(tbody.querySelectorAll('tr'));
    var keyToRows = {};
    trs.forEach(function(tr){
      var date = tr.querySelector('input[name="slotDate"]').value;
      var half = (tr.querySelector('input[name="slotHalf"]').value || '').toUpperCase();
      var key = date + '|' + half;
      if (!keyToRows[key]) keyToRows[key] = [];
      keyToRows[key].push(tr);
    });
    var hasDup = false;
    Object.keys(keyToRows).forEach(function(k){
      var arr = keyToRows[k];
      var dup = arr.length > 1;
      for (var i=0;i<arr.length;i++) {
        arr[i].style.outline = dup ? '2px solid #ef6c00' : '';
      }
      if (dup) hasDup = true;
    });
    var warn = document.getElementById('dupWarn');
    if (!warn) {
      warn = document.createElement('div');
      warn.id = 'dupWarn';
      warn.style.marginTop = '8px';
      warn.style.color = '#ef6c00';
      tbody.parentElement.insertAdjacentElement('beforebegin', warn);
    }
    warn.textContent = hasDup ? 'Warning: duplicate slot (date/half) detected. Duplicates are outlined in orange.' : '';
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
    if (e.target && (e.target.name === 'author' || e.target.name === 'email')) markDuplicateSlots();
  });

  renumber();
  load();
  markDuplicateSlots();

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
              + '<button class="sendnow" data-link="' + a.link + '" style="background:#ffd700;color:#000;border:none;border-radius:6px;padding:4px 8px;cursor:pointer;">Send now</button>'
              + '</div>';
      }
    }
    resultsList.innerHTML = html;
    resultsPanel.style.display = 'block';
    out.textContent = 'Done - ' + results.length + ' link(s) generated.';

    resultsList.addEventListener('click', function (e) {
      var copyBtn = e.target.closest('.copy');
      if (copyBtn) {
        var link = copyBtn.getAttribute('data-link');
        navigator.clipboard.writeText(link).then(function () {
          var old = copyBtn.textContent; copyBtn.textContent = 'Copied'; setTimeout(function () { copyBtn.textContent = old; }, 1000);
        }).catch(function () {});
        return;
      }
      var sendBtn = e.target.closest('.sendnow');
      if (sendBtn) {
        var link2 = sendBtn.getAttribute('data-link') || '';
        var m = link2.match(/\/writer\/([a-f0-9]{16,})/i);
        if (!m) { out.textContent = 'Invalid link'; return; }
        var token = m[1];
        sendBtn.disabled = true;
        var originalText = sendBtn.textContent;
        sendBtn.textContent = 'Sending...';
        fetch('/admin/writer-invites/' + token + '/resend', { 
          method: 'POST',
          headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
        })
          .then(function (r) { 
            if (r.ok) {
              return r.json().then(function(data) { return { ok: true, message: data.message || 'Sent' }; })
                .catch(function() { return { ok: true, message: 'Sent' }; });
            } else {
              return r.json().then(function(data) { return { ok: false, message: data.error || 'Failed' }; })
                .catch(function() { return r.text().then(function(text) { return { ok: false, message: text || 'Failed' }; }); });
            }
          })
          .then(function (result) { 
            sendBtn.textContent = result.ok ? 'Sent' : result.message.substring(0, 20);
            if (!result.ok) {
              sendBtn.style.background = '#ff6b6b';
              console.error('Send failed:', result.message);
            }
            setTimeout(function(){ 
              sendBtn.textContent = originalText; 
              sendBtn.disabled = false;
              sendBtn.style.background = '';
            }, result.ok ? 1200 : 3000); 
          })
          .catch(function(err){ 
            sendBtn.textContent = 'Error'; 
            sendBtn.style.background = '#ff6b6b';
            console.error('Send error:', err);
            setTimeout(function(){ 
              sendBtn.textContent = originalText; 
              sendBtn.disabled = false;
              sendBtn.style.background = '';
            }, 3000); 
          });
      }
    }, { once: true });
    resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
})();


