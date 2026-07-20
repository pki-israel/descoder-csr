'use strict';
/* =====================================================================
   Decodificador PEM - INTERFACE
   Renderizacao dos resultados e eventos da pagina.
   Depende de nucleo.js (carregar antes deste arquivo).
   ===================================================================== */

var currentItems = [];

function el(tag, cls, text) {
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}
function addRow(container, r) {
  var row = el('div', 'row');
  row.appendChild(el('div', 'lbl', r.label));
  var val = el('div', 'val');
  if (r.status) {
    var st = el('span', 'status ' + r.status, r.value);
    val.appendChild(st);
  } else if (r.mono) {
    val.appendChild(el('span', 'mono', r.value));
  } else val.textContent = r.value;
  if (r.copy) {
    var b = el('button', 'copybtn', 'copiar');
    b.addEventListener('click', function () {
      navigator.clipboard.writeText(r.value).then(function () { b.textContent = 'copiado'; setTimeout(function () { b.textContent = 'copiar'; }, 1200); });
    });
    val.appendChild(b);
  }
  if (r.verifySlot) val.dataset.verifySlot = '1';
  if (r.chainSlot) val.dataset.chainSlot = '1';
  row.appendChild(val);
  container.appendChild(row);
}
// Bloco monoespaçado (dump estilo openssl) com botao "copiar tudo".
// Se sec.collapsed, fica dentro de um <details> recolhido.
function makeCopyBtn(text, label) {
  label = label || 'copiar tudo';
  var b = el('button', 'copybtn', label);
  b.addEventListener('click', function () {
    navigator.clipboard.writeText(text).then(function () {
      b.textContent = 'copiado'; setTimeout(function () { b.textContent = label; }, 1200);
    });
  });
  return b;
}
function addPreBlock(section, sec) {
  var pre = el('pre', 'dump');
  pre.textContent = sec.pre;
  if (sec.collapsed) {
    var det = el('details');
    var sum = el('summary', null, sec.title);
    det.appendChild(sum);
    var bar = el('div', 'dumpbar');
    bar.appendChild(makeCopyBtn(sec.pre));
    det.appendChild(bar);
    det.appendChild(pre);
    section.appendChild(det);
  } else {
    var head = el('div', 'dumphead');
    head.appendChild(el('h3', null, sec.title));
    head.appendChild(makeCopyBtn(sec.pre));
    section.appendChild(head);
    section.appendChild(pre);
  }
}
function renderTreeNode(bytes, node) {
  var label = tagName(node) + ' ';
  var meta = '(' + (node.contentEnd - node.contentStart) + ' bytes @ ' + node.start + ')';
  var kids = node.children;
  // tenta expor DER encapsulado em OCTET/BIT STRING
  if (!kids && (node.tag === 4 || node.tag === 3) && node.cls === 0) {
    var c = content(bytes, node);
    if (node.tag === 3 && c.length > 1) c = c.subarray(1);
    if (c.length > 2 && (c[0] === 0x30 || c[0] === 0x31)) {
      try {
        var sub = derParseAll(c);
        var total = sub.reduce(function (acc, s) { return acc + (s.contentEnd - s.start); }, 0);
        if (sub.length && !sub[0].truncated && total >= c.length - 1) {
          var d0 = el('details');
          var s0 = el('summary');
          s0.appendChild(el('span', 't', label));
          s0.appendChild(el('span', 'off', meta + ' [conteudo DER]'));
          d0.appendChild(s0);
          sub.forEach(function (sn) { d0.appendChild(renderTreeNode(c, sn)); });
          return d0;
        }
      } catch (e) {}
    }
  }
  if (kids && kids.length) {
    var d = el('details');
    if (node.cls === 0 && (node.tag === 16 || node.tag === 17)) d.open = true;
    var s = el('summary');
    s.appendChild(el('span', 't', label));
    s.appendChild(el('span', 'off', meta + (node.truncated ? ' TRUNCADO' : '')));
    d.appendChild(s);
    kids.forEach(function (k) { d.appendChild(renderTreeNode(bytes, k)); });
    return d;
  }
  var leaf = el('div', 'leaf');
  leaf.appendChild(el('span', 't', label));
  var v = '';
  try {
    if (node.tag === 6 && node.cls === 0) { var o = decodeOIDContent(content(bytes, node)); v = o + (OIDS[o] ? ' (' + OIDS[o] + ')' : ''); }
    else if ([12,18,19,20,22,26,30,28].indexOf(node.tag) >= 0 && node.cls === 0) v = JSON.stringify(decodeStringNode(bytes, node));
    else if (node.tag === 23 || node.tag === 24) v = fmtDate(parseTimeNode(bytes, node));
    else if (node.tag === 2) { var cb = content(bytes, node); v = cb.length <= 8 ? bigIntFromBytes(cb).toString() : '0x' + hexOf(cb.subarray(0, 12), '') + (cb.length > 12 ? '...' : ''); }
    else if (node.tag === 1) v = content(bytes, node)[0] ? 'TRUE' : 'FALSE';
    else if (node.tag === 5) v = '';
    else { var cc = content(bytes, node); v = hexOf(cc.subarray(0, Math.min(16, cc.length))) + (cc.length > 16 ? ' ...' : ''); }
  } catch (e) { v = '?'; }
  leaf.appendChild(el('span', 'off', meta + ' '));
  leaf.appendChild(document.createTextNode(v));
  if (node.truncated) leaf.appendChild(el('span', 'off', '  TRUNCADO'));
  return leaf;
}

function renderItem(item, container) {
  var card = el('div', 'card');
  card.id = 'item-' + item.id;
  var h = el('h2', null, item.kind);
  var tag = el('span', 'kindtag', item.sourceLabel + ' - ' + item.der.length + ' bytes');
  h.appendChild(tag);
  card.appendChild(h);
  item.warnings.forEach(function (w) { card.appendChild(el('div', 'warnbox', w)); });
  if (item.rowsMain.length) {
    var s0 = el('div', 'section');
    item.rowsMain.forEach(function (r) { addRow(s0, r); });
    card.appendChild(s0);
  }
  item.sections.forEach(function (sec) {
    var s = el('div', 'section');
    if (sec.pre !== undefined) {
      addPreBlock(s, sec);
    } else {
      s.appendChild(el('h3', null, sec.title));
      sec.rows.forEach(function (r) { addRow(s, r); });
    }
    card.appendChild(s);
  });
  if (item.needsPassword) {
    var s2 = el('div', 'section');
    s2.appendChild(el('h3', null, 'Descriptografar (local, sem envio)'));
    var pr = el('div', 'pwrow');
    var inp = document.createElement('input');
    inp.type = 'password'; inp.placeholder = 'senha da chave';
    var btn = el('button', 'primary', 'Descriptografar');
    var msg = el('span', 'hint', '');
    btn.addEventListener('click', function () {
      msg.textContent = 'processando...';
      decryptEncKey(item, inp.value).then(function (plain) {
        try {
          var root = derParseAll(plain)[0];
          if (!looksLikePKCS8(plain, root)) throw new Error('resultado nao e PKCS#8');
          var sub = newItem('Chave descriptografada do item anterior', plain);
          interpretPKCS8(plain, root, sub);
          sub.treeRoot = root;
          currentItems.push(sub);
          renderAll();
        } catch (e) { msg.textContent = 'Senha incorreta (o resultado nao e uma chave valida).'; }
      }).catch(function (e) { msg.textContent = 'Falha: ' + (e.message || 'senha incorreta'); });
    });
    inp.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') btn.click(); });
    pr.appendChild(inp); pr.appendChild(btn); pr.appendChild(msg);
    s2.appendChild(pr);
    card.appendChild(s2);
  }
  // fingerprints
  var fpSec = el('div', 'section');
  fpSec.appendChild(el('h3', null, 'Impressoes digitais (fingerprints)'));
  fpSec.dataset.fp = item.id;
  card.appendChild(fpSec);
  if (item.openssl) {
    var os = el('div', 'section');
    os.appendChild(el('h3', null, 'Equivalente no OpenSSL'));
    var r = el('div', null);
    r.appendChild(el('span', 'mono', item.openssl));
    os.appendChild(r);
    card.appendChild(os);
  }
  if (item.treeRoot) {
    var det = el('details', 'tree');
    det.appendChild(el('summary', null, 'Estrutura ASN.1 completa (avancado)'));
    var wrap = el('div', 'asn1');
    wrap.appendChild(renderTreeNode(item.der, item.treeRoot));
    det.appendChild(wrap);
    card.appendChild(det);
  }
  container.appendChild(card);
  // async: fingerprints
  (async function () {
    var rows = [];
    try {
      rows.push({ label: 'SHA-256 (do DER)', value: await digestHex('SHA-256', item.der), mono: true, copy: true });
      rows.push({ label: 'SHA-1 (do DER)', value: await digestHex('SHA-1', item.der), mono: true, copy: true });
      if (item.spkiDER) rows.push({ label: 'SHA-256 da chave publica (SPKI)', value: await digestHex('SHA-256', item.spkiDER), mono: true, copy: true });
    } catch (e) { rows.push({ label: 'Erro', value: String(e) }); }
    rows.forEach(function (r2) { addRow(fpSec, r2); });
  })();
  // async: verificacao de assinatura
  if (item.pendingVerify) {
    var slot = card.querySelector('[data-verify-slot]');
    (async function () {
      var pv = item.pendingVerify;
      var res = await verifySig(pv.spkiDER, pv.keyInfo || {}, pv.sigOid, pv.sigParams, pv.signed, pv.sig);
      if (slot) { slot.textContent = ''; slot.appendChild(el('span', 'status ' + res.status, res.text)); }
    })();
  }
  // async: verificacao de cadeia (cert assinado por outro cert colado)
  if (item.certSig && !item.selfSigned && item.issuerDER) {
    var slot2 = card.querySelector('[data-chain-slot]');
    var issuer = currentItems.filter(function (it) {
      return it.subjectDER && bytesEq(it.subjectDER, item.issuerDER) && it.spkiDER;
    })[0];
    if (issuer && slot2) {
      (async function () {
        var res = await verifySig(issuer.spkiDER, issuer.keyInfo || {}, item.certSig.sigOid,
          item.certSig.sigParams, item.certSig.signed, item.certSig.sig);
        slot2.textContent = '';
        var pre = (res.status === 'ok') ? 'assinado pelo certificado tambem colado (emissor confirmado): ' : '';
        slot2.appendChild(el('span', 'status ' + res.status, pre + res.text));
      })();
    }
  }
}

async function renderMatching(container) {
  var withKey = currentItems.filter(function (it) { return it.spkiDER; });
  if (withKey.length < 2) return;
  var groups = {};
  for (var i = 0; i < withKey.length; i++) {
    var h = await digestHex('SHA-256', withKey[i].spkiDER);
    (groups[h] = groups[h] || []).push(withKey[i]);
  }
  var card = el('div', 'card');
  card.appendChild(el('h2', null, 'Correspondencia de chaves'));
  var s = el('div', 'section');
  var keys = Object.keys(groups);
  var letter = 65;
  keys.forEach(function (h) {
    var g = groups[h];
    var row = el('div', 'row');
    var l = el('div', 'lbl');
    var mt = el('span', 'matchtag', 'Chave ' + String.fromCharCode(letter++));
    l.appendChild(mt);
    row.appendChild(l);
    var names = g.map(function (it) { return it.kind + ' (item ' + it.id + ')'; }).join('  +  ');
    var v = el('div', 'val', names);
    row.appendChild(v);
    s.appendChild(row);
  });
  var verdict = el('div', null);
  if (keys.length === 1)
    verdict.appendChild(el('span', 'status ok', 'Todos os itens usam a MESMA chave publica - CSR/certificado/chave correspondem entre si.'));
  else {
    var anyMatch = keys.some(function (h) { return groups[h].length > 1; });
    verdict.appendChild(el('span', anyMatch ? 'status na' : 'status err',
      anyMatch ? 'Ha ' + keys.length + ' chaves distintas entre os itens - veja os grupos acima.'
        : 'As chaves NAO correspondem entre os itens colados.'));
  }
  s.appendChild(el('div', null, ' '));
  s.appendChild(verdict);
  card.appendChild(s);
  container.appendChild(card);
}

function renderAll() {
  var results = document.getElementById('results');
  results.textContent = '';
  currentItems.forEach(function (it) { renderItem(it, results); });
  renderMatching(results);
}

function decodeText(text) {
  currentItems = [];
  itemSeq = 0;
  var results = document.getElementById('results');
  results.textContent = '';
  var blocks = splitPEM(text);
  if (!blocks.length) {
    if (text.trim()) {
      var eb = el('div', 'errbox', 'Nenhum conteudo PEM/base64/hex reconhecido. Cole o bloco completo, incluindo as linhas -----BEGIN...----- e -----END...-----.');
      results.appendChild(eb);
    }
    return;
  }
  blocks.forEach(function (b) {
    try { analyzeBlock(b, function (it) { currentItems.push(it); }); }
    catch (e) {
      var it2 = newItem(b.label ? 'Bloco PEM: ' + b.label : 'bloco', b.bytes);
      it2.warnings.push('Falha inesperada: ' + e.message);
      currentItems.push(it2);
    }
  });
  renderAll();
}

function decodeBinary(name, buf) {
  var bytes = new Uint8Array(buf);
  if (bytes.length && bytes[0] === 0x30) {
    currentItems = []; itemSeq = 0;
    document.getElementById('results').textContent = '';
    analyzeBlock({ label: null, headers: {}, bytes: bytes, removed: 0, incomplete: false, noEnd: false },
      function (it) { it.sourceLabel = 'Arquivo DER: ' + name; currentItems.push(it); });
    renderAll();
  } else {
    var text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    document.getElementById('input').value = text;
    decodeText(text);
  }
}

/* ---------- eventos ---------- */
var debounceTimer = null;
var inputEl = document.getElementById('input');
inputEl.addEventListener('input', function () {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(function () { decodeText(inputEl.value); }, 350);
});
document.getElementById('btn-decode').addEventListener('click', function () { decodeText(inputEl.value); });
document.getElementById('btn-clear').addEventListener('click', function () {
  inputEl.value = ''; currentItems = []; document.getElementById('results').textContent = '';
});
document.getElementById('file').addEventListener('change', function (ev) {
  var f = ev.target.files[0];
  if (!f) return;
  f.arrayBuffer().then(function (buf) { decodeBinary(f.name, buf); });
});
document.body.addEventListener('dragover', function (ev) { ev.preventDefault(); document.body.classList.add('dragover'); });
document.body.addEventListener('dragleave', function () { document.body.classList.remove('dragover'); });
document.body.addEventListener('drop', function (ev) {
  ev.preventDefault();
  document.body.classList.remove('dragover');
  var f = ev.dataTransfer.files[0];
  if (f) f.arrayBuffer().then(function (buf) { decodeBinary(f.name, buf); });
});

/* ---------- exemplo embutido (CSR ficticio gerado com OpenSSL) ---------- */
var EXAMPLE_CSR = [
'-----BEGIN CERTIFICATE REQUEST-----',
'MIIDIzCCAgsCAQAwbDELMAkGA1UEBhMCQlIxDjAMBgNVBAgMBUdvaWFzMRAwDgYD',
'VQQHDAdHb2lhbmlhMSIwIAYDVQQKDBlFeGVtcGxvIENlcnRpZmljYWRvcyBMdGRh',
'MRcwFQYDVQQDDA5leGVtcGxvLmNvbS5icjCCASIwDQYJKoZIhvcNAQEBBQADggEP',
'ADCCAQoCggEBANFjdenwyeS5PaPIHCBaEA8Znvdyt/9b8ZeY/9NC+4w3H2xlCONg',
'CcHTvuwKSTlKtZKnlOyEUu6C4GpClE50Y5bGVzhUUyis8dMNZZUu484HcJTMb2Vs',
'JrHWETUYNOP5P3PbZhBUoiwA6bH8Pu1qaAH8c4OX7Y6VDzp58eyRig8/adSvehkT',
'ro0FmIfPwAW89bApXjPp9oZWRbZmQTGiOeApCETaJc3ek8oA4Yca9KEhkFdLXKhz',
'jxtBcr7ckcL0zPvdM51TluXXGOUUie/gz3Y35D4s7Y1DsrucQt6ANXgXDOu4jR7z',
'9TiRGmqCNTXzv1WtSLm/CayTU3uP8ovEnp8CAwEAAaByMHAGCSqGSIb3DQEJDjFj',
'MGEwMwYDVR0RBCwwKoIOZXhlbXBsby5jb20uYnKCEnd3dy5leGVtcGxvLmNvbS5i',
'cocEywBxCjALBgNVHQ8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF',
'BwMCMA0GCSqGSIb3DQEBCwUAA4IBAQC3WDzsr7FedX8xmf9nNhFzocmJFrnIoQO7',
'GP4VZaPyznWq1L4mHLg6yWB5pq/RzoLpo1kFol/yiGsTeupDzN8lswaR1x+C+6c7',
'zpz4HbCypq/qOkVmVwF/72prdGCjZr5pGMiRcKFGa+inmQzZMhKqI2kT0RlrUpXg',
'g8+Wv0j1oH+seSkY0/DqoAHHypLpaVTe6ozRQdER+cZS4erb6DrTPVF0/wYzYBuo',
'RIdPkW8I/pkTrU9XKtT2awLh1Q1kUF8XDD+ADL0GijChzB8RrV3YLePEGSjdHVYn',
'xwA8x1bQmuM0iiTt7sYC7QELmU3Eux1QgQUciBAtcwPNFwXXjB+b',
'-----END CERTIFICATE REQUEST-----'
].join('\n');
document.getElementById('btn-example').addEventListener('click', function () {
  inputEl.value = EXAMPLE_CSR;
  decodeText(EXAMPLE_CSR);
});
