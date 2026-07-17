'use strict';
/* =====================================================================
   Decodificador PEM - NUCLEO
   Utilidades, base64/PEM, parser DER, OIDs, interpretadores, cripto.
   Este arquivo nao toca no DOM; toda a interface fica em interface.js.
   ===================================================================== */

function hexOf(bytes, sep) {
  sep = (sep === undefined) ? ':' : sep;
  var out = [];
  for (var i = 0; i < bytes.length; i++) out.push(bytes[i].toString(16).padStart(2, '0').toUpperCase());
  return out.join(sep);
}
function bytesEq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function bigIntFromBytes(b) {
  var v = 0n;
  for (var i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
  return v;
}
function bitLenOf(b) {
  var i = 0;
  while (i < b.length && b[i] === 0) i++;
  if (i >= b.length) return 0;
  return (b.length - i - 1) * 8 + (32 - Math.clz32(b[i]));
}
async function digestHex(alg, bytes) {
  var h = await crypto.subtle.digest(alg, bytes);
  return hexOf(new Uint8Array(h));
}

/* ---------- base64 tolerante (aceita truncado, ignora lixo) ---------- */
var B64MAP = (function () {
  var m = {}, a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (var i = 0; i < 64; i++) m[a[i]] = i;
  return m;
})();
function b64ToBytes(str) {
  var vals = [], removed = 0;
  for (var i = 0; i < str.length; i++) {
    var c = str[i];
    if (c in B64MAP) vals.push(B64MAP[c]);
    else if (c === '=' || c === '\r' || c === '\n' || c === ' ' || c === '\t') continue;
    else removed++;
  }
  var out = new Uint8Array(Math.floor(vals.length * 3 / 4));
  var o = 0, incomplete = false;
  for (var j = 0; j + 3 < vals.length; j += 4) {
    var n = (vals[j] << 18) | (vals[j + 1] << 12) | (vals[j + 2] << 6) | vals[j + 3];
    out[o++] = (n >> 16) & 255; out[o++] = (n >> 8) & 255; out[o++] = n & 255;
  }
  var rest = vals.length % 4;
  if (rest === 2) { out[o++] = ((vals[vals.length - 2] << 2) | (vals[vals.length - 1] >> 4)) & 255; incomplete = true; }
  else if (rest === 3) {
    var n2 = (vals[vals.length - 3] << 12) | (vals[vals.length - 2] << 6) | vals[vals.length - 1];
    out[o++] = (n2 >> 10) & 255; out[o++] = (n2 >> 2) & 255; incomplete = true;
  } else if (rest === 1) incomplete = true;
  return { bytes: out.subarray(0, o), removed: removed, incomplete: incomplete };
}

/* ---------- separacao de blocos PEM ---------- */
function splitPEM(text) {
  var blocks = [];
  var re = /-----BEGIN ([^-]+?)-----([\s\S]*?)(?:-----END [^-]+?-----|$)/g;
  var m, found = false;
  while ((m = re.exec(text)) !== null) {
    found = true;
    var label = m[1].trim(), body = m[2], headers = {};
    var noEnd = m[0].indexOf('-----END') === -1;
    // cabecalhos RFC 1421 (Proc-Type / DEK-Info) antes de linha vazia
    var hm = body.match(/^\s*((?:[A-Za-z0-9-]+:[^\n]*\n)+)\s*\n/);
    if (hm) {
      hm[1].split('\n').forEach(function (l) {
        var p = l.indexOf(':');
        if (p > 0) headers[l.slice(0, p).trim()] = l.slice(p + 1).trim();
      });
      body = body.slice(hm[0].length);
    }
    var dec = b64ToBytes(body);
    blocks.push({ label: label, headers: headers, bytes: dec.bytes, removed: dec.removed,
      incomplete: dec.incomplete || noEnd, noEnd: noEnd });
  }
  if (found) return blocks;
  var t = text.trim();
  if (!t) return [];
  // hex puro?
  var hx = t.replace(/[\s:,-]|0x/gi, '');
  if (/^[0-9a-fA-F]+$/.test(hx) && hx.length % 2 === 0 && hx.length > 8) {
    var hb = new Uint8Array(hx.length / 2);
    for (var i = 0; i < hb.length; i++) hb[i] = parseInt(hx.substr(i * 2, 2), 16);
    if (hb[0] === 0x30) return [{ label: null, headers: {}, bytes: hb, removed: 0, incomplete: false, noEnd: false }];
  }
  // base64 sem cabecalho
  var dec2 = b64ToBytes(t);
  if (dec2.bytes.length > 4 && dec2.removed < t.length / 10)
    return [{ label: null, headers: {}, bytes: dec2.bytes, removed: dec2.removed, incomplete: dec2.incomplete, noEnd: false }];
  return [];
}

/* ---------- parser DER/BER tolerante ---------- */
var UNIV_TAGS = { 1:'BOOLEAN',2:'INTEGER',3:'BIT STRING',4:'OCTET STRING',5:'NULL',6:'OBJECT IDENTIFIER',
  10:'ENUMERATED',12:'UTF8String',13:'RELATIVE-OID',16:'SEQUENCE',17:'SET',18:'NumericString',
  19:'PrintableString',20:'TeletexString',22:'IA5String',23:'UTCTime',24:'GeneralizedTime',
  26:'VisibleString',28:'UniversalString',30:'BMPString' };

function derParseOne(bytes, off, end, depth) {
  if (depth > 80) throw new Error('profundidade ASN.1 excessiva');
  var node = { start: off, cls: 0, tag: 0, constructed: false, truncated: false,
    children: null, contentStart: 0, contentEnd: 0, declaredLen: null, indefinite: false };
  var first = bytes[off];
  node.cls = first >> 6;
  node.constructed = (first & 0x20) !== 0;
  var tag = first & 0x1f, p = off + 1;
  if (tag === 0x1f) {
    tag = 0;
    while (p < end) { var tb = bytes[p++]; tag = (tag * 128) + (tb & 0x7f); if ((tb & 0x80) === 0) break; }
  }
  node.tag = tag;
  if (p >= end) { node.truncated = true; node.contentStart = node.contentEnd = end; return { node: node, next: end }; }
  var lb = bytes[p++], len = null;
  if (lb < 0x80) len = lb;
  else if (lb === 0x80) node.indefinite = true;
  else {
    var nBytes = lb & 0x7f;
    if (nBytes > 4) throw new Error('comprimento DER invalido');
    len = 0;
    for (var i = 0; i < nBytes; i++) {
      if (p >= end) { node.truncated = true; break; }
      len = len * 256 + bytes[p++];
    }
  }
  node.contentStart = p;
  node.declaredLen = len;
  if (node.indefinite) {
    // BER comprimento indefinido: filhos ate EOC (00 00)
    var kids = [], q = p;
    while (q + 1 <= end) {
      if (bytes[q] === 0 && bytes[q + 1] === 0) { q += 2; break; }
      var r = derParseOne(bytes, q, end, depth + 1);
      kids.push(r.node); q = r.next;
      if (r.node.truncated) break;
    }
    node.children = kids;
    node.contentEnd = q;
    return { node: node, next: q };
  }
  var cEnd = p + len;
  if (cEnd > end) { node.truncated = true; cEnd = end; }
  node.contentEnd = cEnd;
  if (node.constructed) {
    node.children = [];
    var q2 = p;
    while (q2 < cEnd) {
      try {
        var r2 = derParseOne(bytes, q2, cEnd, depth + 1);
        node.children.push(r2.node); q2 = r2.next;
        if (r2.node.truncated) break;
      } catch (e) { node.parseError = e.message; break; }
    }
  }
  return { node: node, next: cEnd };
}
function derParseAll(bytes) {
  var nodes = [], off = 0;
  while (off < bytes.length) {
    if (bytes[off] === 0) { off++; continue; }
    var r = derParseOne(bytes, off, bytes.length, 0);
    nodes.push(r.node);
    if (r.next <= off) break;
    off = r.next;
  }
  return nodes;
}
function content(bytes, node) { return bytes.subarray(node.contentStart, node.contentEnd); }
function rawOf(bytes, node) { return bytes.subarray(node.start, node.contentEnd); }
function child(node, i) { return (node && node.children && node.children.length > i) ? node.children[i] : null; }
function findCtx(node, tagNum) { // filho context-specific [tagNum]
  if (!node || !node.children) return null;
  for (var i = 0; i < node.children.length; i++)
    if (node.children[i].cls === 2 && node.children[i].tag === tagNum) return node.children[i];
  return null;
}
function tagName(node) {
  if (node.cls === 0) return UNIV_TAGS[node.tag] || ('UNIVERSAL ' + node.tag);
  if (node.cls === 2) return '[' + node.tag + ']';
  if (node.cls === 1) return 'APPLICATION ' + node.tag;
  return 'PRIVATE ' + node.tag;
}

/* ---------- OIDs ---------- */
function decodeOIDContent(b) {
  if (!b.length) return '';
  var parts = [], v = 0;
  for (var i = 0; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if ((b[i] & 0x80) === 0) { parts.push(v); v = 0; }
  }
  var first = parts[0];
  var out = (first < 40) ? [0, first] : (first < 80) ? [1, first - 40] : [2, first - 80];
  return out.concat(parts.slice(1)).join('.');
}
var OIDS = {
  '2.5.4.3':'CN (Common Name)','2.5.4.4':'SN (Sobrenome)','2.5.4.5':'serialNumber',
  '2.5.4.6':'C (Pais)','2.5.4.7':'L (Cidade)','2.5.4.8':'ST (Estado)','2.5.4.9':'street',
  '2.5.4.10':'O (Organizacao)','2.5.4.11':'OU (Unidade Organizacional)','2.5.4.12':'title',
  '2.5.4.13':'description','2.5.4.15':'businessCategory','2.5.4.17':'postalCode',
  '2.5.4.42':'givenName','2.5.4.46':'dnQualifier','2.5.4.97':'organizationIdentifier',
  '1.2.840.113549.1.9.1':'E (emailAddress)','0.9.2342.19200300.100.1.25':'DC (domainComponent)',
  '0.9.2342.19200300.100.1.1':'UID',
  '1.3.6.1.4.1.311.60.2.1.1':'jurisdictionLocality (EV)','1.3.6.1.4.1.311.60.2.1.2':'jurisdictionState (EV)',
  '1.3.6.1.4.1.311.60.2.1.3':'jurisdictionCountry (EV)',
  // algoritmos de chave
  '1.2.840.113549.1.1.1':'RSA','1.2.840.10045.2.1':'EC (Curva Eliptica)','1.2.840.10040.4.1':'DSA',
  '1.3.101.110':'X25519','1.3.101.111':'X448','1.3.101.112':'Ed25519','1.3.101.113':'Ed448',
  // curvas
  '1.2.840.10045.3.1.7':'P-256 (prime256v1 / secp256r1)','1.3.132.0.34':'P-384 (secp384r1)',
  '1.3.132.0.35':'P-521 (secp521r1)','1.3.132.0.10':'secp256k1','1.2.840.10045.3.1.1':'P-192 (prime192v1)',
  '1.3.36.3.3.2.8.1.1.7':'brainpoolP256r1','1.3.36.3.3.2.8.1.1.11':'brainpoolP384r1','1.3.36.3.3.2.8.1.1.13':'brainpoolP512r1',
  // algoritmos de assinatura
  '1.2.840.113549.1.1.2':'md2WithRSAEncryption','1.2.840.113549.1.1.4':'md5WithRSAEncryption',
  '1.2.840.113549.1.1.5':'sha1WithRSAEncryption','1.2.840.113549.1.1.10':'RSASSA-PSS',
  '1.2.840.113549.1.1.11':'sha256WithRSAEncryption','1.2.840.113549.1.1.12':'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13':'sha512WithRSAEncryption',
  '1.2.840.10045.4.1':'ecdsa-with-SHA1','1.2.840.10045.4.3.2':'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3':'ecdsa-with-SHA384','1.2.840.10045.4.3.4':'ecdsa-with-SHA512',
  '1.2.840.10040.4.3':'dsa-with-SHA1','2.16.840.1.101.3.4.3.2':'dsa-with-SHA256',
  // hash
  '1.3.14.3.2.26':'SHA-1','2.16.840.1.101.3.4.2.1':'SHA-256','2.16.840.1.101.3.4.2.2':'SHA-384',
  '2.16.840.1.101.3.4.2.3':'SHA-512','1.2.840.113549.2.5':'MD5',
  '1.2.840.113549.1.1.8':'MGF1',
  // atributos PKCS#9 / CSR
  '1.2.840.113549.1.9.2':'unstructuredName','1.2.840.113549.1.9.7':'challengePassword',
  '1.2.840.113549.1.9.14':'extensionRequest (extensoes solicitadas)',
  '1.3.6.1.4.1.311.13.2.2':'MS enrollment CSP','1.3.6.1.4.1.311.13.2.3':'MS OS Version',
  '1.3.6.1.4.1.311.21.20':'MS requestClientInfo','1.3.6.1.4.1.311.20.2':'MS certificate template',
  // extensoes
  '2.5.29.14':'subjectKeyIdentifier','2.5.29.15':'keyUsage','2.5.29.17':'subjectAltName (SAN)',
  '2.5.29.18':'issuerAltName','2.5.29.19':'basicConstraints','2.5.29.20':'cRLNumber',
  '2.5.29.31':'cRLDistributionPoints','2.5.29.32':'certificatePolicies','2.5.29.35':'authorityKeyIdentifier',
  '2.5.29.37':'extendedKeyUsage','1.3.6.1.5.5.7.1.1':'authorityInfoAccess (AIA)',
  '1.3.6.1.4.1.11129.2.4.2':'SCT (Certificate Transparency)','1.3.6.1.5.5.7.1.24':'TLS Feature (OCSP Must-Staple)',
  // EKU
  '1.3.6.1.5.5.7.3.1':'serverAuth (autenticacao de servidor TLS)','1.3.6.1.5.5.7.3.2':'clientAuth (autenticacao de cliente TLS)',
  '1.3.6.1.5.5.7.3.3':'codeSigning (assinatura de codigo)','1.3.6.1.5.5.7.3.4':'emailProtection (S/MIME)',
  '1.3.6.1.5.5.7.3.8':'timeStamping (carimbo do tempo)','1.3.6.1.5.5.7.3.9':'OCSPSigning',
  '1.3.6.1.4.1.311.10.3.12':'MS documentSigning','1.2.840.113583.1.1.5':'Adobe PDF signing',
  '1.3.6.1.4.1.311.20.2.2':'MS smartcardLogon',
  // AIA
  '1.3.6.1.5.5.7.48.1':'OCSP','1.3.6.1.5.5.7.48.2':'caIssuers (cadeia de certificacao)',
  '1.3.6.1.5.5.7.2.1':'CPS (URL da declaracao de praticas)','1.3.6.1.5.5.7.2.2':'userNotice',
  // policies CA/Browser
  '2.23.140.1.2.1':'Politica CA/B: DV (validacao de dominio)','2.23.140.1.2.2':'Politica CA/B: OV (validacao de organizacao)',
  '2.23.140.1.2.3':'Politica CA/B: IV (validacao individual)','2.23.140.1.1':'Politica CA/B: EV (validacao estendida)',
  '2.23.140.1.3':'Politica CA/B: EV Code Signing','2.23.140.1.4.1':'Politica CA/B: Code Signing OV',
  // ICP-Brasil otherName
  '2.16.76.1.3.1':'ICP-Brasil: dados do titular (PF)','2.16.76.1.3.2':'ICP-Brasil: nome do responsavel (PJ)',
  '2.16.76.1.3.3':'ICP-Brasil: CNPJ','2.16.76.1.3.4':'ICP-Brasil: dados do responsavel (PJ)',
  '2.16.76.1.3.5':'ICP-Brasil: titulo de eleitor','2.16.76.1.3.6':'ICP-Brasil: CEI do titular (PF)',
  '2.16.76.1.3.7':'ICP-Brasil: CEI da empresa (PJ)','2.16.76.1.3.8':'ICP-Brasil: nome empresarial',
  '1.3.6.1.4.1.311.20.2.3':'UPN (User Principal Name)',
  // PKCS#7
  '1.2.840.113549.1.7.1':'PKCS#7 data','1.2.840.113549.1.7.2':'PKCS#7 signedData',
  // criptografia de chave
  '1.2.840.113549.1.5.13':'PBES2','1.2.840.113549.1.5.12':'PBKDF2',
  '2.16.840.1.101.3.4.1.2':'AES-128-CBC','2.16.840.1.101.3.4.1.22':'AES-192-CBC','2.16.840.1.101.3.4.1.42':'AES-256-CBC',
  '1.2.840.113549.3.7':'3DES-CBC (des-ede3-cbc)','1.2.840.113549.2.7':'HMAC-SHA1','1.2.840.113549.2.9':'HMAC-SHA256',
  '1.2.840.113549.2.10':'HMAC-SHA384','1.2.840.113549.2.11':'HMAC-SHA512'
};
function oidName(oid) { return OIDS[oid] || oid; }
function oidShort(oid) {
  var n = OIDS[oid];
  if (!n) return oid;
  var p = n.indexOf(' (');
  return p > 0 ? n.slice(0, p) : n;
}

/* ---------- strings, inteiros, datas ---------- */
var TD_UTF8 = new TextDecoder('utf-8'), TD_L1 = new TextDecoder('latin1');
function decodeStringNode(bytes, node) {
  var c = content(bytes, node);
  switch (node.tag) {
    case 12: return TD_UTF8.decode(c);
    case 19: case 22: case 18: case 26: case 23: case 24: return TD_L1.decode(c);
    case 20: return TD_L1.decode(c); // TeletexString tratado como latin1 (pratica comum)
    case 30: { // BMPString UTF-16BE
      var s = '';
      for (var i = 0; i + 1 < c.length; i += 2) s += String.fromCharCode((c[i] << 8) | c[i + 1]);
      return s;
    }
    case 28: { var s2 = ''; for (var j = 0; j + 3 < c.length; j += 4) s2 += String.fromCodePoint((c[j]<<24)|(c[j+1]<<16)|(c[j+2]<<8)|c[j+3]); return s2; }
    default: return TD_UTF8.decode(c);
  }
}
function decodeAnyValue(bytes, node) {
  if (!node) return '';
  if (node.tag === 4 && node.cls === 0) { // OCTET STRING: tenta texto, senao hex
    var c = content(bytes, node);
    var printable = true;
    for (var i = 0; i < c.length; i++) if (c[i] < 32 || c[i] > 126) { printable = false; break; }
    return printable && c.length ? TD_L1.decode(c) : hexOf(c);
  }
  if ([12,18,19,20,22,26,30,28].indexOf(node.tag) >= 0 && node.cls === 0) return decodeStringNode(bytes, node);
  if (node.tag === 2 && node.cls === 0) return '0x' + hexOf(content(bytes, node), '');
  if (node.tag === 6 && node.cls === 0) return oidName(decodeOIDContent(content(bytes, node)));
  if (node.tag === 1 && node.cls === 0) return content(bytes, node)[0] ? 'TRUE' : 'FALSE';
  return hexOf(content(bytes, node));
}
function parseTimeNode(bytes, node) {
  var s = TD_L1.decode(content(bytes, node)).trim();
  var y, mo, d, h, mi, se;
  try {
    if (node.tag === 23) { // UTCTime YYMMDDHHMMSSZ
      y = parseInt(s.slice(0, 2), 10); y += (y < 50) ? 2000 : 1900;
      mo = s.slice(2, 4); d = s.slice(4, 6); h = s.slice(6, 8); mi = s.slice(8, 10); se = s.slice(10, 12) || '00';
    } else { // GeneralizedTime YYYYMMDDHHMMSS
      y = parseInt(s.slice(0, 4), 10);
      mo = s.slice(4, 6); d = s.slice(6, 8); h = s.slice(8, 10); mi = s.slice(10, 12); se = s.slice(12, 14) || '00';
    }
    var dt = new Date(Date.UTC(y, parseInt(mo,10) - 1, parseInt(d,10), parseInt(h,10), parseInt(mi,10), parseInt(se,10)));
    return isNaN(dt.getTime()) ? null : dt;
  } catch (e) { return null; }
}
function fmtDate(dt) {
  if (!dt) return '(data invalida)';
  var p = function (n) { return String(n).padStart(2, '0'); };
  return p(dt.getUTCDate()) + '/' + p(dt.getUTCMonth() + 1) + '/' + dt.getUTCFullYear() + ' ' +
    p(dt.getUTCHours()) + ':' + p(dt.getUTCMinutes()) + ':' + p(dt.getUTCSeconds()) + ' UTC';
}

/* ---------- Nome (RDNSequence) ---------- */
var RDN_ABBR = { '2.5.4.3':'CN','2.5.4.6':'C','2.5.4.7':'L','2.5.4.8':'ST','2.5.4.10':'O','2.5.4.11':'OU',
  '2.5.4.5':'serialNumber','2.5.4.4':'SN','2.5.4.42':'givenName','2.5.4.9':'street','2.5.4.17':'postalCode',
  '2.5.4.12':'title','2.5.4.13':'description','2.5.4.15':'businessCategory','2.5.4.97':'organizationIdentifier',
  '1.2.840.113549.1.9.1':'emailAddress','0.9.2342.19200300.100.1.25':'DC','0.9.2342.19200300.100.1.1':'UID',
  '1.3.6.1.4.1.311.60.2.1.1':'jurisdictionL','1.3.6.1.4.1.311.60.2.1.2':'jurisdictionST','1.3.6.1.4.1.311.60.2.1.3':'jurisdictionC' };
function parseRDNs(bytes, nameNode) {
  var parts = [];
  if (!nameNode || !nameNode.children) return parts;
  nameNode.children.forEach(function (setNode) {
    (setNode.children || []).forEach(function (atv) {
      var oidNode = child(atv, 0), valNode = child(atv, 1);
      if (!oidNode) return;
      var oid = decodeOIDContent(content(bytes, oidNode));
      var val = valNode ? decodeStringNode(bytes, valNode) : '';
      parts.push({ oid: oid, abbr: RDN_ABBR[oid] || oid, value: val });
    });
  });
  return parts;
}
function nameToString(parts) {
  return parts.map(function (p) { return p.abbr + '=' + p.value; }).join(', ');
}

/* ---------- codificador DER minimo (para reconstruir SPKI) ---------- */
function encTLV(tag, contents) {
  var len = 0;
  contents.forEach(function (c) { len += c.length; });
  var head;
  if (len < 0x80) head = [tag, len];
  else {
    var lb = [];
    var l = len;
    while (l > 0) { lb.unshift(l & 255); l >>= 8; }
    head = [tag, 0x80 | lb.length].concat(lb);
  }
  var out = new Uint8Array(head.length + len);
  out.set(head, 0);
  var o = head.length;
  contents.forEach(function (c) { out.set(c, o); o += c.length; });
  return out;
}
function encInt(contentBytes) { return encTLV(0x02, [contentBytes]); }
function encOIDRaw(contentBytes) { return encTLV(0x06, [contentBytes]); }
var OID_RSA_ENC = new Uint8Array([0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01]);
var OID_EC_PUB = new Uint8Array([0x2a,0x86,0x48,0xce,0x3d,0x02,0x01]);
function spkiFromRSA(nContent, eContent) {
  var alg = encTLV(0x30, [encOIDRaw(OID_RSA_ENC), new Uint8Array([0x05, 0x00])]);
  var pk = encTLV(0x30, [encInt(nContent), encInt(eContent)]);
  var bs = encTLV(0x03, [new Uint8Array([0]), pk]);
  return encTLV(0x30, [alg, bs]);
}
function spkiFromEC(curveOidContent, point) {
  var alg = encTLV(0x30, [encOIDRaw(OID_EC_PUB), encOIDRaw(curveOidContent)]);
  var bs = encTLV(0x03, [new Uint8Array([0]), point]);
  return encTLV(0x30, [alg, bs]);
}

/* ---------- SubjectPublicKeyInfo ---------- */
var CURVE_BITS = { 'P-256':256, 'P-384':384, 'P-521':521, 'secp256k1':256, 'P-192':192,
  'brainpoolP256r1':256, 'brainpoolP384r1':384, 'brainpoolP512r1':512 };
function parseSPKI(bytes, spkiNode) {
  var info = { rows: [], keyType: '?', bits: null, curveName: null, spkiDER: null, webCurve: null };
  if (!spkiNode || !spkiNode.children) return info;
  var algSeq = child(spkiNode, 0), bitStr = child(spkiNode, 1);
  var algOidNode = child(algSeq, 0);
  if (!algOidNode) return info;
  var algOid = decodeOIDContent(content(bytes, algOidNode));
  info.algOid = algOid;
  info.spkiDER = rawOf(bytes, spkiNode);
  var pkBytes = null;
  if (bitStr && !bitStr.truncated) {
    var c = content(bytes, bitStr);
    pkBytes = c.subarray(1); // primeiro byte = unused bits
  }
  if (algOid === '1.2.840.113549.1.1.1' || algOid === '1.2.840.113549.1.1.10') { // RSA / RSA-PSS
    info.keyType = 'RSA';
    if (pkBytes) {
      try {
        var seq = derParseAll(pkBytes)[0];
        var n = child(seq, 0), e = child(seq, 1);
        info.bits = bitLenOf(pkBytes.subarray(n.contentStart, n.contentEnd));
        var ev = bigIntFromBytes(pkBytes.subarray(e.contentStart, e.contentEnd));
        info.rows.push({ label: 'Algoritmo', value: 'RSA (' + info.bits + ' bits)' });
        info.rows.push({ label: 'Expoente publico', value: ev.toString() + ' (0x' + ev.toString(16) + ')' });
        var nb = pkBytes.subarray(n.contentStart, n.contentEnd);
        var nhex = hexOf(nb.subarray(0, Math.min(nb.length, 16)));
        info.rows.push({ label: 'Modulo (inicio)', value: nhex + (nb.length > 16 ? ' ...' : ''), mono: true });
      } catch (e2) { info.rows.push({ label: 'Algoritmo', value: 'RSA (chave nao decodificavel: ' + e2.message + ')' }); }
    } else info.rows.push({ label: 'Algoritmo', value: 'RSA (bits da chave indisponiveis - dados truncados)' });
  } else if (algOid === '1.2.840.10045.2.1') { // EC
    info.keyType = 'EC';
    var params = child(algSeq, 1);
    if (params && params.tag === 6) {
      var cOid = decodeOIDContent(content(bytes, params));
      info.curveName = oidShort(cOid);
      var full = oidName(cOid);
      info.bits = CURVE_BITS[info.curveName] || null;
      info.rows.push({ label: 'Algoritmo', value: 'ECDSA / curva ' + full + (info.bits ? ' (' + info.bits + ' bits)' : '') });
      if (['P-256','P-384','P-521'].indexOf(info.curveName) >= 0) info.webCurve = info.curveName;
    } else info.rows.push({ label: 'Algoritmo', value: 'EC (parametros de curva nao identificados)' });
    if (pkBytes && pkBytes.length) {
      var fmt = pkBytes[0] === 4 ? 'nao comprimido' : (pkBytes[0] === 2 || pkBytes[0] === 3 ? 'comprimido' : '?');
      info.rows.push({ label: 'Ponto publico', value: fmt + ', ' + pkBytes.length + ' bytes: ' +
        hexOf(pkBytes.subarray(0, Math.min(pkBytes.length, 12))) + (pkBytes.length > 12 ? ' ...' : ''), mono: true });
    }
  } else if (algOid === '1.3.101.112' || algOid === '1.3.101.113' || algOid === '1.3.101.110' || algOid === '1.3.101.111') {
    info.keyType = oidShort(algOid);
    info.bits = (algOid === '1.3.101.112' || algOid === '1.3.101.110') ? 255 : 448;
    info.rows.push({ label: 'Algoritmo', value: oidName(algOid) });
    if (pkBytes) info.rows.push({ label: 'Chave publica', value: hexOf(pkBytes), mono: true });
  } else if (algOid === '1.2.840.10040.4.1') {
    info.keyType = 'DSA';
    info.rows.push({ label: 'Algoritmo', value: 'DSA (legado - nao aceito por ACs atuais)' });
  } else {
    info.rows.push({ label: 'Algoritmo', value: oidName(algOid) });
  }
  return info;
}

/* ---------- GeneralNames / SAN / ICP-Brasil ---------- */
function fmtCPF(s) { return s.length === 11 ? s.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4') : s; }
function fmtCNPJ(s) { return s.length === 14 ? s.replace(/(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})/, '$1.$2.$3/$4-$5') : s; }
function allZeros(s) { return /^0+$/.test(s); }
function parseICPOtherName(oid, txt) {
  var out = [];
  function push(l, v) { if (v && !allZeros(v.replace(/\D/g, '') || '0')) out.push(l + ': ' + v); }
  if (oid === '2.16.76.1.3.1' || oid === '2.16.76.1.3.4') {
    var data = txt.slice(0, 8), cpf = txt.slice(8, 19), nis = txt.slice(19, 30), rg = txt.slice(30, 45), org = txt.slice(45);
    if (data && !allZeros(data)) push('Data de nascimento', data.replace(/(\d{2})(\d{2})(\d{4})/, '$1/$2/$3'));
    push('CPF', fmtCPF(cpf));
    push('NIS/PIS', nis.replace(/^0+/, ''));
    push('RG', rg.replace(/^0+/, '') + (org ? ' (' + org.trim() + ')' : ''));
    return out.join(' | ') || '(campos zerados)';
  }
  if (oid === '2.16.76.1.3.3') return 'CNPJ: ' + fmtCNPJ(txt.trim());
  if (oid === '2.16.76.1.3.5') {
    var tit = txt.slice(0, 12), zona = txt.slice(12, 15), secao = txt.slice(15, 19), mun = txt.slice(19);
    if (allZeros(txt.replace(/\D/g, '') || '0')) return '(nao informado)';
    return 'Titulo: ' + tit.replace(/^0+/, '') + ' Zona: ' + zona + ' Secao: ' + secao + (mun ? ' ' + mun.trim() : '');
  }
  if (oid === '2.16.76.1.3.6' || oid === '2.16.76.1.3.7') return 'CEI: ' + txt.trim();
  return txt;
}
function parseGeneralNames(bytes, node) {
  var out = [];
  (node.children || []).forEach(function (gn) {
    if (gn.cls !== 2) return;
    var c = content(bytes, gn);
    switch (gn.tag) {
      case 0: { // otherName
        var oidNode = child(gn, 0);
        var oid = oidNode ? decodeOIDContent(content(bytes, oidNode)) : '?';
        var valWrap = findCtx(gn, 0);
        var inner = valWrap ? (child(valWrap, 0) || valWrap) : null;
        var txt = inner ? decodeAnyValue(bytes, inner) : '';
        if (oid.indexOf('2.16.76.1.3.') === 0) txt = parseICPOtherName(oid, txt);
        out.push({ type: 'otherName', label: oidName(oid), value: txt });
        break;
      }
      case 1: out.push({ type: 'email', label: 'E-mail', value: TD_L1.decode(c) }); break;
      case 2: out.push({ type: 'dns', label: 'DNS', value: TD_L1.decode(c) }); break;
      case 4: { // directoryName
        var dn = child(gn, 0);
        out.push({ type: 'dirName', label: 'DirName', value: nameToString(parseRDNs(bytes, dn)) });
        break;
      }
      case 6: out.push({ type: 'uri', label: 'URI', value: TD_L1.decode(c) }); break;
      case 7: {
        var ip = (c.length === 4) ? Array.from(c).join('.') :
          (c.length === 16) ? Array.from({length:8},function(_,i){return ((c[i*2]<<8)|c[i*2+1]).toString(16);}).join(':') :
          (c.length === 8) ? Array.from(c.subarray(0,4)).join('.') + '/' + Array.from(c.subarray(4)).join('.') : hexOf(c);
        out.push({ type: 'ip', label: 'IP', value: ip });
        break;
      }
      default: out.push({ type: 'gn' + gn.tag, label: 'GeneralName [' + gn.tag + ']', value: hexOf(c) });
    }
  });
  return out;
}

/* ---------- Extensoes X.509 ---------- */
var KU_BITS = ['digitalSignature','nonRepudiation (contentCommitment)','keyEncipherment','dataEncipherment',
  'keyAgreement','keyCertSign','cRLSign','encipherOnly','decipherOnly'];
function parseExtensions(bytes, extsSeq) {
  var list = [];
  (extsSeq.children || []).forEach(function (ext) {
    var oidNode = child(ext, 0);
    if (!oidNode || oidNode.tag !== 6) return;
    var oid = decodeOIDContent(content(bytes, oidNode));
    var idx = 1, critical = false;
    var maybeBool = child(ext, 1);
    if (maybeBool && maybeBool.tag === 1 && maybeBool.cls === 0) { critical = content(bytes, maybeBool)[0] !== 0; idx = 2; }
    var octet = child(ext, idx);
    var entry = { oid: oid, name: oidShort(oid), critical: critical, rows: [], sans: null };
    var innerBytes = octet ? content(bytes, octet) : new Uint8Array(0);
    var inner = null;
    try { inner = innerBytes.length ? derParseAll(innerBytes)[0] : null; } catch (e) { inner = null; }
    try {
      if (oid === '2.5.29.17' || oid === '2.5.29.18') {
        entry.sans = inner ? parseGeneralNames(innerBytes, inner) : [];
      } else if (oid === '2.5.29.15' && inner) {
        var c = innerBytes.subarray(inner.contentStart, inner.contentEnd);
        var unused = c[0] || 0, names = [];
        for (var i = 1; i < c.length; i++)
          for (var b = 0; b < 8; b++) {
            var bitIdx = (i - 1) * 8 + b;
            if (i === c.length - 1 && b >= 8 - unused) break;
            if (c[i] & (0x80 >> b)) names.push(KU_BITS[bitIdx] || ('bit' + bitIdx));
          }
        entry.rows.push({ label: 'Usos', value: names.join(', ') || '(nenhum)' });
      } else if (oid === '2.5.29.37' && inner) {
        var ekus = (inner.children || []).map(function (o) { return oidName(decodeOIDContent(innerBytes.subarray(o.contentStart, o.contentEnd))); });
        entry.rows.push({ label: 'Usos estendidos', value: ekus.join('; ') });
      } else if (oid === '2.5.29.19' && inner) {
        var isCA = false, pathLen = null;
        (inner.children || []).forEach(function (n) {
          if (n.tag === 1) isCA = innerBytes[n.contentStart] !== 0;
          if (n.tag === 2) pathLen = Number(bigIntFromBytes(innerBytes.subarray(n.contentStart, n.contentEnd)));
        });
        entry.rows.push({ label: 'CA', value: (isCA ? 'SIM (certificado de AC)' : 'NAO (entidade final)') +
          (pathLen !== null ? ', pathLen=' + pathLen : '') });
      } else if (oid === '2.5.29.14' && inner) {
        entry.rows.push({ label: 'Key ID', value: hexOf(innerBytes.subarray(inner.contentStart, inner.contentEnd)), mono: true });
      } else if (oid === '2.5.29.35' && inner) {
        var kid = findCtx(inner, 0);
        if (kid) entry.rows.push({ label: 'Key ID da AC emissora', value: hexOf(innerBytes.subarray(kid.contentStart, kid.contentEnd)), mono: true });
      } else if (oid === '2.5.29.31' && inner) {
        (inner.children || []).forEach(function (dp) {
          var dpn = findCtx(dp, 0);
          var full = dpn ? findCtx(dpn, 0) : null;
          if (full) parseGeneralNames(innerBytes, full).forEach(function (g) {
            entry.rows.push({ label: 'CRL', value: g.value, mono: true });
          });
        });
      } else if (oid === '1.3.6.1.5.5.7.1.1' && inner) {
        (inner.children || []).forEach(function (ad) {
          var mNode = child(ad, 0), loc = child(ad, 1);
          var method = mNode ? oidShort(decodeOIDContent(innerBytes.subarray(mNode.contentStart, mNode.contentEnd))) : '?';
          var v = (loc && loc.cls === 2 && loc.tag === 6) ? TD_L1.decode(innerBytes.subarray(loc.contentStart, loc.contentEnd)) : '';
          entry.rows.push({ label: method, value: v, mono: true });
        });
      } else if (oid === '2.5.29.32' && inner) {
        (inner.children || []).forEach(function (pi) {
          var pOidN = child(pi, 0);
          if (!pOidN) return;
          var pOid = decodeOIDContent(innerBytes.subarray(pOidN.contentStart, pOidN.contentEnd));
          var label = oidName(pOid);
          if (pOid.indexOf('2.16.76.1.2.1.') === 0) label = 'Politica ICP-Brasil A1 (' + pOid + ')';
          else if (pOid.indexOf('2.16.76.1.2.2.') === 0) label = 'Politica ICP-Brasil A2 (' + pOid + ')';
          else if (pOid.indexOf('2.16.76.1.2.3.') === 0) label = 'Politica ICP-Brasil A3 (' + pOid + ')';
          else if (pOid.indexOf('2.16.76.1.2.4.') === 0) label = 'Politica ICP-Brasil A4 (' + pOid + ')';
          var cps = '';
          var quals = child(pi, 1);
          (quals && quals.children || []).forEach(function (q) {
            var qOidN = child(q, 0), qv = child(q, 1);
            if (qOidN && decodeOIDContent(innerBytes.subarray(qOidN.contentStart, qOidN.contentEnd)) === '1.3.6.1.5.5.7.2.1' && qv)
              cps = TD_L1.decode(innerBytes.subarray(qv.contentStart, qv.contentEnd));
          });
          entry.rows.push({ label: 'Politica', value: label + (cps ? ' | CPS: ' + cps : '') });
        });
      } else if (oid === '2.5.29.20' && inner) {
        entry.rows.push({ label: 'Numero da CRL', value: bigIntFromBytes(innerBytes.subarray(inner.contentStart, inner.contentEnd)).toString() });
      } else if (oid === '1.3.6.1.4.1.11129.2.4.2') {
        entry.rows.push({ label: 'Conteudo', value: 'presente (' + innerBytes.length + ' bytes) - carimbos SCT de Certificate Transparency' });
      } else {
        entry.rows.push({ label: 'Valor (bruto)', value: hexOf(innerBytes.subarray(0, Math.min(64, innerBytes.length))) + (innerBytes.length > 64 ? ' ...' : ''), mono: true });
      }
    } catch (e) {
      entry.rows.push({ label: 'Valor', value: '(erro ao interpretar: ' + e.message + ')' });
    }
    list.push(entry);
  });
  return list;
}

/* ---------- verificacao de assinatura (Web Crypto) ---------- */
var SIG_ALGS = {
  '1.2.840.113549.1.1.5': { key: 'RSASSA-PKCS1-v1_5', hash: 'SHA-1' },
  '1.2.840.113549.1.1.11': { key: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  '1.2.840.113549.1.1.12': { key: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
  '1.2.840.113549.1.1.13': { key: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
  '1.2.840.10045.4.1': { key: 'ECDSA', hash: 'SHA-1' },
  '1.2.840.10045.4.3.2': { key: 'ECDSA', hash: 'SHA-256' },
  '1.2.840.10045.4.3.3': { key: 'ECDSA', hash: 'SHA-384' },
  '1.2.840.10045.4.3.4': { key: 'ECDSA', hash: 'SHA-512' },
  '1.3.101.112': { key: 'Ed25519' }
};
var HASH_OIDS = { '1.3.14.3.2.26':'SHA-1','2.16.840.1.101.3.4.2.1':'SHA-256','2.16.840.1.101.3.4.2.2':'SHA-384','2.16.840.1.101.3.4.2.3':'SHA-512' };
function ecSigDerToRaw(sigDer, size) {
  var seq = derParseAll(sigDer)[0];
  var r = content(sigDer, child(seq, 0)), s = content(sigDer, child(seq, 1));
  function pad(x) {
    var i = 0; while (i < x.length && x[i] === 0) i++;
    x = x.subarray(i);
    var out = new Uint8Array(size);
    out.set(x, size - x.length);
    return out;
  }
  var out = new Uint8Array(size * 2);
  out.set(pad(r), 0); out.set(pad(s), size);
  return out;
}
async function verifySig(spkiDER, keyInfo, sigOid, sigParamsBytes, signedBytes, sigBytes) {
  try {
    if (sigOid === '1.2.840.113549.1.1.4' || sigOid === '1.2.840.113549.1.1.2')
      return { status: 'na', text: 'assinatura ' + oidShort(sigOid) + ' (MD5/MD2) nao verificavel no navegador' };
    var importAlg, verifyAlg, sig = sigBytes;
    if (sigOid === '1.2.840.113549.1.1.10') { // RSA-PSS
      var hash = 'SHA-1', saltLen = 20;
      if (sigParamsBytes && sigParamsBytes.length) {
        try {
          var ps = derParseAll(sigParamsBytes)[0];
          var h = findCtx(ps, 0);
          if (h) {
            var hOidNode = child(child(h, 0), 0);
            hash = HASH_OIDS[decodeOIDContent(sigParamsBytes.subarray(hOidNode.contentStart, hOidNode.contentEnd))] || 'SHA-1';
          }
          var sl = findCtx(ps, 2);
          if (sl) saltLen = Number(bigIntFromBytes(sigParamsBytes.subarray(child(sl,0).contentStart, child(sl,0).contentEnd)));
        } catch (e) {}
      }
      importAlg = { name: 'RSA-PSS', hash: hash };
      verifyAlg = { name: 'RSA-PSS', saltLength: saltLen };
    } else {
      var a = SIG_ALGS[sigOid];
      if (!a) return { status: 'na', text: 'algoritmo de assinatura sem suporte a verificacao (' + oidShort(sigOid) + ')' };
      if (a.key === 'ECDSA') {
        if (!keyInfo.webCurve) return { status: 'na', text: 'curva ' + (keyInfo.curveName || '?') + ' sem suporte no Web Crypto' };
        importAlg = { name: 'ECDSA', namedCurve: keyInfo.webCurve };
        verifyAlg = { name: 'ECDSA', hash: a.hash };
        var size = { 'P-256': 32, 'P-384': 48, 'P-521': 66 }[keyInfo.webCurve];
        sig = ecSigDerToRaw(sigBytes, size);
      } else if (a.key === 'Ed25519') {
        importAlg = { name: 'Ed25519' }; verifyAlg = { name: 'Ed25519' };
      } else {
        importAlg = { name: a.key, hash: a.hash }; verifyAlg = { name: a.key };
      }
    }
    var key = await crypto.subtle.importKey('spki', spkiDER, importAlg, false, ['verify']);
    var ok = await crypto.subtle.verify(verifyAlg, key, sig, signedBytes);
    return ok ? { status: 'ok', text: 'VALIDA - a assinatura confere com a chave publica' }
      : { status: 'err', text: 'INVALIDA - a assinatura NAO confere (arquivo corrompido ou adulterado)' };
  } catch (e) {
    return { status: 'na', text: 'nao foi possivel verificar (' + (e.message || e) + ')' };
  }
}

/* ---------- interpretadores por tipo ---------- */
function sigAlgRow(bytes, algSeq) {
  var oidNode = child(algSeq, 0);
  if (!oidNode) return { oid: null, name: '?' };
  var oid = decodeOIDContent(content(bytes, oidNode));
  var params = child(algSeq, 1);
  return { oid: oid, name: oidName(oid), paramsBytes: params ? rawOf(bytes, params) : null };
}
function truncWarning(bytes, root) {
  if (!root) return null;
  var declared = (root.declaredLen !== null) ? (root.contentStart - root.start) + root.declaredLen : null;
  if (declared !== null && declared > bytes.length)
    return 'Conteudo INCOMPLETO: a estrutura declara ' + declared + ' bytes, mas apenas ' + bytes.length +
      ' foram recebidos (faltam ' + (declared - bytes.length) + '). Decodificando o que esta disponivel. ' +
      'Confira se o texto foi colado ate a linha -----END...----- final.';
  return null;
}

function interpretCSR(bytes, root, item) {
  item.kind = 'CSR (Requisicao de Assinatura de Certificado - PKCS#10)';
  var tw = truncWarning(bytes, root);
  if (tw) item.warnings.push(tw);
  var cri = child(root, 0);
  if (!cri) { item.warnings.push('Estrutura vazia - nada decodificavel.'); return; }
  var version = child(cri, 0);
  if (version && version.tag === 2)
    item.rowsMain.push({ label: 'Versao', value: String(bigIntFromBytes(content(bytes, version))) + ' (v1)' });
  var nameNode = child(cri, 1);
  if (nameNode) {
    var parts = parseRDNs(bytes, nameNode);
    item.subjectParts = parts;
    var sec = { title: 'Titular (Subject)', rows: [] };
    sec.rows.push({ label: 'DN completo', value: nameToString(parts), mono: true, copy: true });
    parts.forEach(function (p) { sec.rows.push({ label: oidName(p.oid), value: p.value }); });
    item.sections.push(sec);
  }
  var spkiNode = child(cri, 2);
  if (spkiNode && spkiNode.children) {
    var ki = parseSPKI(bytes, spkiNode);
    item.keyInfo = ki;
    item.spkiDER = ki.spkiDER;
    item.sections.push({ title: 'Chave publica', rows: ki.rows });
    if (ki.keyType === 'RSA' && ki.bits && ki.bits < 2048)
      item.warnings.push('Chave RSA de ' + ki.bits + ' bits: abaixo do minimo aceito (2048). A AC rejeitara este CSR.');
    if (ki.keyType === 'EC' && ki.bits && ki.bits < 256)
      item.warnings.push('Curva EC de ' + ki.bits + ' bits: abaixo do minimo recomendado (256).');
  }
  // atributos [0]
  var attrs = findCtx(cri, 0);
  var hasSAN = false, sanValues = [];
  if (attrs && attrs.children && attrs.children.length) {
    var secA = { title: 'Atributos e extensoes solicitadas', rows: [] };
    attrs.children.forEach(function (attr) {
      var aOidN = child(attr, 0);
      if (!aOidN) return;
      var aOid = decodeOIDContent(content(bytes, aOidN));
      var valSet = child(attr, 1);
      if (aOid === '1.2.840.113549.1.9.14' && valSet && valSet.children) {
        var extSeq = child(valSet, 0);
        if (extSeq) parseExtensions(bytes, extSeq).forEach(function (ex) {
          if (ex.sans) {
            hasSAN = true;
            ex.sans.forEach(function (g) {
              sanValues.push(g.value);
              secA.rows.push({ label: 'SAN - ' + g.label, value: g.value, mono: g.type === 'dns' || g.type === 'uri' });
            });
            if (!ex.sans.length) secA.rows.push({ label: 'SAN', value: '(extensao presente, vazia)' });
          } else {
            ex.rows.forEach(function (r) {
              secA.rows.push({ label: ex.name + (ex.critical ? ' (critica)' : '') + ' - ' + r.label, value: r.value, mono: r.mono });
            });
          }
        });
      } else if (aOid === '1.2.840.113549.1.9.7') {
        var pw = valSet && child(valSet, 0) ? decodeAnyValue(bytes, child(valSet, 0)) : '';
        secA.rows.push({ label: 'challengePassword', value: pw ? pw : '(presente)' });
        item.warnings.push('CSR contem challengePassword. Isso nao e a senha da chave privada; e um atributo raramente usado pelas ACs.');
      } else {
        var v = valSet && child(valSet, 0) ? decodeAnyValue(bytes, child(valSet, 0)) : '(vazio)';
        secA.rows.push({ label: oidName(aOid), value: v });
      }
    });
    if (secA.rows.length) item.sections.push(secA);
  }
  if (!tw && !hasSAN)
    item.warnings.push('CSR sem subjectAltName (SAN). ACs publicas ignoram o CN e exigem os dominios no SAN; ' +
      'normalmente a propria AC adiciona o SAN na emissao a partir do pedido, mas confirme o dominio na hora da solicitacao.');
  if (hasSAN && item.subjectParts) {
    var cn = item.subjectParts.filter(function (p) { return p.oid === '2.5.4.3'; }).map(function (p) { return p.value; })[0];
    if (cn && sanValues.indexOf(cn) === -1)
      item.warnings.push('O CN (' + cn + ') nao aparece entre os SANs solicitados. Navegadores validam apenas o SAN.');
  }
  // assinatura
  var algSeq = child(root, 1), sigBit = child(root, 2);
  if (algSeq && algSeq.children) {
    var sa = sigAlgRow(bytes, algSeq);
    var secS = { title: 'Assinatura do CSR', rows: [{ label: 'Algoritmo', value: sa.name }] };
    if (sa.oid === '1.2.840.113549.1.1.5' || sa.oid === '1.2.840.10045.4.1')
      item.warnings.push('Assinatura com SHA-1 (obsoleto). Gere novamente com -sha256.');
    if (sa.oid === '1.2.840.113549.1.1.4')
      item.warnings.push('Assinatura com MD5 (inseguro e rejeitado). Gere novamente com -sha256.');
    if (sigBit && sigBit.tag === 3 && !sigBit.truncated && item.spkiDER && !child(root,0).truncated) {
      var sigContent = content(bytes, sigBit).subarray(1);
      item.pendingVerify = { spkiDER: item.spkiDER, keyInfo: item.keyInfo, sigOid: sa.oid,
        sigParams: sa.paramsBytes, signed: rawOf(bytes, cri), sig: sigContent };
      secS.rows.push({ label: 'Verificacao', value: '(verificando...)', verifySlot: true });
    } else if (tw) {
      secS.rows.push({ label: 'Verificacao', value: 'impossivel - assinatura ausente/truncada', status: 'na' });
    }
    item.sections.push(secS);
  }
  item.openssl = 'openssl req -in arquivo.csr -noout -text -verify';
}

function interpretCert(bytes, root, item) {
  item.kind = 'Certificado X.509';
  var tw = truncWarning(bytes, root);
  if (tw) item.warnings.push(tw);
  var tbs = child(root, 0);
  if (!tbs) return;
  var idx = 0;
  var vNode = findCtx(tbs, 0);
  var version = 1;
  if (vNode) { version = Number(bigIntFromBytes(content(bytes, child(vNode, 0) || vNode))) + 1; idx = 1; }
  item.rowsMain.push({ label: 'Versao', value: 'v' + version });
  var serial = child(tbs, idx);
  if (serial && serial.tag === 2)
    item.rowsMain.push({ label: 'Numero de serie', value: hexOf(content(bytes, serial)), mono: true, copy: true });
  var issuerNode = child(tbs, idx + 2), validity = child(tbs, idx + 3), subjectNode = child(tbs, idx + 4), spkiNode = child(tbs, idx + 5);
  if (subjectNode) {
    var sp = parseRDNs(bytes, subjectNode);
    item.subjectParts = sp;
    var secSub = { title: 'Titular (Subject)', rows: [{ label: 'DN completo', value: nameToString(sp), mono: true, copy: true }] };
    sp.forEach(function (p) { secSub.rows.push({ label: oidName(p.oid), value: p.value }); });
    item.sections.push(secSub);
  }
  if (issuerNode) {
    var ip = parseRDNs(bytes, issuerNode);
    item.issuerDER = rawOf(bytes, issuerNode);
    item.sections.push({ title: 'Emissor (Issuer)', rows: [{ label: 'DN completo', value: nameToString(ip), mono: true }] });
  }
  if (subjectNode) item.subjectDER = rawOf(bytes, subjectNode);
  if (validity && validity.children && validity.children.length >= 2) {
    var nb = parseTimeNode(bytes, validity.children[0]), na = parseTimeNode(bytes, validity.children[1]);
    var now = new Date();
    var secV = { title: 'Validade', rows: [
      { label: 'Valido a partir de', value: fmtDate(nb) },
      { label: 'Valido ate', value: fmtDate(na) }
    ]};
    if (na) {
      var days = Math.floor((na - now) / 86400000);
      if (days < 0) { secV.rows.push({ label: 'Situacao', value: 'EXPIRADO ha ' + (-days) + ' dia(s)', status: 'err' }); }
      else if (nb && now < nb) secV.rows.push({ label: 'Situacao', value: 'ainda nao vigente', status: 'na' });
      else {
        secV.rows.push({ label: 'Situacao', value: 'valido - expira em ' + days + ' dia(s)', status: days < 30 ? 'err' : 'ok' });
        if (days < 30) item.warnings.push('Certificado expira em ' + days + ' dia(s). Programe a renovacao.');
      }
    }
    item.sections.push(secV);
  }
  if (spkiNode) {
    var ki = parseSPKI(bytes, spkiNode);
    item.keyInfo = ki; item.spkiDER = ki.spkiDER;
    item.sections.push({ title: 'Chave publica', rows: ki.rows });
  }
  var exts = findCtx(tbs, 3);
  if (exts && child(exts, 0)) {
    var secE = { title: 'Extensoes', rows: [] };
    parseExtensions(bytes, child(exts, 0)).forEach(function (ex) {
      if (ex.sans) {
        ex.sans.forEach(function (g) { secE.rows.push({ label: (ex.oid === '2.5.29.18' ? 'IAN - ' : 'SAN - ') + g.label, value: g.value, mono: g.type === 'dns' || g.type === 'uri' }); });
      } else ex.rows.forEach(function (r) {
        secE.rows.push({ label: ex.name + (ex.critical ? ' (critica)' : '') + (ex.rows.length > 1 ? ' - ' + r.label : ''), value: r.value, mono: r.mono });
      });
    });
    if (secE.rows.length) item.sections.push(secE);
  }
  var algSeq = child(root, 1), sigBit = child(root, 2);
  if (algSeq && algSeq.children) {
    var sa = sigAlgRow(bytes, algSeq);
    var secS = { title: 'Assinatura', rows: [{ label: 'Algoritmo', value: sa.name }] };
    item.selfSigned = !!(item.issuerDER && item.subjectDER && bytesEq(item.issuerDER, item.subjectDER));
    if (item.selfSigned) secS.rows.push({ label: 'Tipo', value: 'AUTOASSINADO (Subject = Issuer)' });
    if (sigBit && sigBit.tag === 3 && !sigBit.truncated && tbs && !tbs.truncated) {
      item.certSig = { sigOid: sa.oid, sigParams: sa.paramsBytes, signed: rawOf(bytes, tbs), sig: content(bytes, sigBit).subarray(1) };
      if (item.selfSigned && item.spkiDER) {
        item.pendingVerify = { spkiDER: item.spkiDER, keyInfo: item.keyInfo, sigOid: sa.oid,
          sigParams: sa.paramsBytes, signed: item.certSig.signed, sig: item.certSig.sig };
        secS.rows.push({ label: 'Verificacao', value: '(verificando...)', verifySlot: true });
      } else {
        secS.rows.push({ label: 'Verificacao', value: 'para validar, cole tambem o certificado da AC emissora', status: 'na', chainSlot: true });
      }
    }
    item.sections.push(secS);
  }
  item.openssl = 'openssl x509 -in arquivo.cer -noout -text';
}

function keyMetaSections(bytes, item, kt) {
  if (kt.keyType === 'RSA' && kt.bits && kt.bits < 2048)
    item.warnings.push('Chave RSA de ' + kt.bits + ' bits: abaixo do minimo atual (2048).');
  item.warnings.push('ATENCAO: isto e uma CHAVE PRIVADA. Nunca envie este arquivo por e-mail ou ticket; quem tiver este conteudo pode se passar pelo titular.');
}
function interpretRSAPrivate(bytes, root, item) {
  item.kind = 'Chave privada RSA (PKCS#1)';
  var tw = truncWarning(bytes, root); if (tw) item.warnings.push(tw);
  var n = child(root, 1), e = child(root, 2);
  var rows = [];
  if (n && e && !n.truncated) {
    var nC = content(bytes, n), eC = content(bytes, e);
    var bits = bitLenOf(nC);
    rows.push({ label: 'Algoritmo', value: 'RSA (' + bits + ' bits)' });
    rows.push({ label: 'Expoente publico', value: bigIntFromBytes(eC).toString() });
    item.spkiDER = spkiFromRSA(nC, eC);
    item.keyInfo = { keyType: 'RSA', bits: bits, webCurve: null };
    keyMetaSections(bytes, item, item.keyInfo);
  } else rows.push({ label: 'Estado', value: 'chave truncada/ilegivel' });
  rows.push({ label: 'Componentes privados', value: 'presentes (nao exibidos por seguranca)' });
  item.sections.push({ title: 'Chave', rows: rows });
  item.openssl = 'openssl rsa -in chave.key -noout -text';
}
function interpretECPrivate(bytes, root, item, inheritedCurve) {
  item.kind = 'Chave privada EC (SEC1)';
  var tw = truncWarning(bytes, root); if (tw) item.warnings.push(tw);
  var rows = [];
  var curveNode = findCtx(root, 0);
  var curveOidContent = null, curveName = null;
  if (curveNode && child(curveNode, 0)) {
    curveOidContent = content(bytes, child(curveNode, 0));
    curveName = oidShort(decodeOIDContent(curveOidContent));
  } else if (inheritedCurve) { curveOidContent = inheritedCurve.content; curveName = inheritedCurve.name; }
  rows.push({ label: 'Algoritmo', value: 'ECDSA / curva ' + (curveName || 'desconhecida') });
  var pubNode = findCtx(root, 1);
  if (pubNode && child(pubNode, 0) && curveOidContent) {
    var point = content(bytes, child(pubNode, 0)).subarray(1);
    item.spkiDER = spkiFromEC(curveOidContent, point);
    item.keyInfo = { keyType: 'EC', curveName: curveName, bits: CURVE_BITS[curveName] || null,
      webCurve: ['P-256','P-384','P-521'].indexOf(curveName) >= 0 ? curveName : null };
  } else rows.push({ label: 'Chave publica embutida', value: 'ausente - correspondencia com CSR/certificado indisponivel' });
  rows.push({ label: 'Componente privado', value: 'presente (nao exibido por seguranca)' });
  keyMetaSections(bytes, item, item.keyInfo || { keyType: 'EC' });
  item.sections.push({ title: 'Chave', rows: rows });
  item.openssl = 'openssl ec -in chave.key -noout -text';
}
function interpretPKCS8(bytes, root, item) {
  item.kind = 'Chave privada (PKCS#8)';
  var tw = truncWarning(bytes, root); if (tw) item.warnings.push(tw);
  var algSeq = child(root, 1), octet = child(root, 2);
  if (!algSeq || !child(algSeq, 0)) { item.warnings.push('AlgorithmIdentifier ausente.'); return; }
  var algOid = decodeOIDContent(content(bytes, child(algSeq, 0)));
  if (algOid === '1.2.840.113549.1.1.1') {
    if (octet) {
      var innerBytes = content(bytes, octet);
      try {
        var inner = derParseAll(innerBytes)[0];
        interpretRSAPrivate(innerBytes, inner, item);
        item.kind = 'Chave privada RSA (PKCS#8)';
      } catch (e) { item.warnings.push('Conteudo RSA interno ilegivel: ' + e.message); }
    }
  } else if (algOid === '1.2.840.10045.2.1') {
    var curveParam = child(algSeq, 1);
    var inherited = null;
    if (curveParam && curveParam.tag === 6) {
      var cc = content(bytes, curveParam);
      inherited = { content: cc, name: oidShort(decodeOIDContent(cc)) };
    }
    if (octet) {
      var ib = content(bytes, octet);
      try {
        var inner2 = derParseAll(ib)[0];
        interpretECPrivate(ib, inner2, item, inherited);
        item.kind = 'Chave privada EC (PKCS#8)';
      } catch (e2) { item.warnings.push('Conteudo EC interno ilegivel: ' + e2.message); }
    }
  } else if (algOid === '1.3.101.112' || algOid === '1.3.101.113' || algOid === '1.3.101.110' || algOid === '1.3.101.111') {
    item.kind = 'Chave privada ' + oidShort(algOid) + ' (PKCS#8)';
    var rows = [{ label: 'Algoritmo', value: oidName(algOid) }];
    var pub = findCtx(root, 1); // PKCS#8 v2 publicKey [1]
    if (pub) rows.push({ label: 'Chave publica embutida', value: 'presente' });
    rows.push({ label: 'Componente privado', value: 'presente (nao exibido por seguranca)' });
    keyMetaSections(bytes, item, { keyType: oidShort(algOid) });
    item.sections.push({ title: 'Chave', rows: rows });
  } else {
    item.sections.push({ title: 'Chave', rows: [{ label: 'Algoritmo', value: oidName(algOid) }] });
    keyMetaSections(bytes, item, { keyType: '?' });
  }
  item.openssl = 'openssl pkey -in chave.key -noout -text';
}
function interpretEncryptedPKCS8(bytes, root, item) {
  item.kind = 'Chave privada CRIPTOGRAFADA (PKCS#8)';
  var algSeq = child(root, 0);
  var rows = [];
  var enc = { supported: false };
  if (algSeq && child(algSeq, 0)) {
    var oid = decodeOIDContent(content(bytes, child(algSeq, 0)));
    if (oid === '1.2.840.113549.1.5.13') { // PBES2
      var params = child(algSeq, 1);
      var kdfSeq = child(params, 0), cipherSeq = child(params, 1);
      var kdfOid = kdfSeq ? decodeOIDContent(content(bytes, child(kdfSeq, 0))) : '?';
      rows.push({ label: 'Esquema', value: 'PBES2' });
      if (kdfOid === '1.2.840.113549.1.5.12') {
        var kp = child(kdfSeq, 1);
        var salt = child(kp, 0), iter = child(kp, 1);
        enc.salt = salt ? content(bytes, salt) : null;
        enc.iter = iter ? Number(bigIntFromBytes(content(bytes, iter))) : null;
        enc.prf = 'SHA-1';
        (kp.children || []).forEach(function (c2) {
          if (c2.constructed && child(c2, 0) && child(c2, 0).tag === 6) {
            var prfOid = decodeOIDContent(content(bytes, child(c2, 0)));
            enc.prf = { '1.2.840.113549.2.7':'SHA-1','1.2.840.113549.2.9':'SHA-256','1.2.840.113549.2.10':'SHA-384','1.2.840.113549.2.11':'SHA-512' }[prfOid] || null;
          }
        });
        rows.push({ label: 'Derivacao da senha', value: 'PBKDF2, ' + (enc.iter || '?') + ' iteracoes, HMAC-' + (enc.prf || '?') });
      } else rows.push({ label: 'KDF', value: oidName(kdfOid) });
      if (cipherSeq && child(cipherSeq, 0)) {
        var cOid = decodeOIDContent(content(bytes, child(cipherSeq, 0)));
        enc.cipherOid = cOid;
        enc.iv = child(cipherSeq, 1) ? content(bytes, child(cipherSeq, 1)) : null;
        enc.keyLen = { '2.16.840.1.101.3.4.1.2': 16, '2.16.840.1.101.3.4.1.22': 24, '2.16.840.1.101.3.4.1.42': 32 }[cOid] || null;
        rows.push({ label: 'Cifra', value: oidName(cOid) });
        enc.supported = !!(enc.keyLen && enc.salt && enc.iter && enc.prf && enc.iv);
      }
      var data = child(root, 1);
      if (data) enc.data = content(bytes, data);
    } else {
      rows.push({ label: 'Esquema', value: oidName(oid) + ' (PBES1 legado)' });
    }
  }
  if (!enc.supported)
    rows.push({ label: 'Descriptografia', value: 'nao suportada no navegador para este esquema. Converta: openssl pkcs8 -topk8 -v2 aes-256-cbc -in chave.key -out nova.key', mono: false });
  item.sections.push({ title: 'Criptografia da chave', rows: rows });
  item.encInfo = enc.supported ? enc : null;
  item.needsPassword = enc.supported;
  item.openssl = 'openssl pkey -in chave.key -noout -text  (pedira a senha)';
}
function interpretSPKIPublic(bytes, root, item) {
  item.kind = 'Chave publica (SubjectPublicKeyInfo)';
  var ki = parseSPKI(bytes, root);
  item.keyInfo = ki; item.spkiDER = ki.spkiDER;
  item.sections.push({ title: 'Chave publica', rows: ki.rows });
  item.openssl = 'openssl pkey -pubin -in chave.pub -noout -text';
}
function interpretPKCS7(bytes, root, item) {
  item.kind = 'PKCS#7 / CMS';
  var oidNode = child(root, 0);
  var oid = oidNode && oidNode.tag === 6 ? decodeOIDContent(content(bytes, oidNode)) : null;
  var rows = [{ label: 'Tipo de conteudo', value: oidName(oid || '?') }];
  var certs = [];
  var wrap = findCtx(root, 0);
  var sd = wrap ? child(wrap, 0) : null;
  if (sd && sd.children) {
    var certSet = findCtx(sd, 0);
    if (certSet && certSet.children) certs = certSet.children;
  }
  rows.push({ label: 'Certificados no pacote', value: String(certs.length) });
  item.sections.push({ title: 'Pacote', rows: rows });
  item.subItems = certs.map(function (cNode, i) {
    var cBytes = rawOf(bytes, cNode);
    var sub = newItem('Certificado ' + (i + 1) + ' do pacote PKCS#7', cBytes);
    try {
      var cRoot = derParseAll(cBytes)[0];
      interpretCert(cBytes, cRoot, sub);
      sub.treeRoot = cRoot;
    } catch (e) { sub.warnings.push('Erro: ' + e.message); }
    return sub;
  });
  item.openssl = 'openssl pkcs7 -in arquivo.p7b -print_certs -noout';
}
function interpretCRL(bytes, root, item) {
  item.kind = 'CRL (Lista de Certificados Revogados)';
  var tbs = child(root, 0);
  if (!tbs) return;
  var idx = 0;
  if (child(tbs, 0) && child(tbs, 0).tag === 2) { item.rowsMain.push({ label: 'Versao', value: 'v' + (Number(bigIntFromBytes(content(bytes, child(tbs, 0)))) + 1) }); idx = 1; }
  var issuer = child(tbs, idx + 1);
  if (issuer) item.rowsMain.push({ label: 'Emissor', value: nameToString(parseRDNs(bytes, issuer)), mono: true });
  var thisUp = child(tbs, idx + 2), nextUp = child(tbs, idx + 3);
  if (thisUp && (thisUp.tag === 23 || thisUp.tag === 24)) item.rowsMain.push({ label: 'Emitida em', value: fmtDate(parseTimeNode(bytes, thisUp)) });
  if (nextUp && (nextUp.tag === 23 || nextUp.tag === 24)) {
    var nu = parseTimeNode(bytes, nextUp);
    item.rowsMain.push({ label: 'Proxima atualizacao', value: fmtDate(nu) });
    if (nu && nu < new Date()) item.warnings.push('CRL vencida (nextUpdate no passado).');
  }
  var revoked = null;
  for (var i = idx + 2; i < (tbs.children || []).length; i++) {
    var n = tbs.children[i];
    if (n.cls === 0 && n.tag === 16 && n.children && n.children.length && n.children[0].tag === 16) { revoked = n; break; }
  }
  var count = revoked ? revoked.children.length : 0;
  item.rowsMain.push({ label: 'Certificados revogados', value: String(count) });
  if (revoked) {
    var rows = [];
    revoked.children.slice(0, 20).forEach(function (rc) {
      var ser = child(rc, 0), dt = child(rc, 1);
      rows.push({ label: hexOf(content(bytes, ser)), value: dt ? fmtDate(parseTimeNode(bytes, dt)) : '', mono: true });
    });
    if (count > 20) rows.push({ label: '...', value: '(exibindo 20 de ' + count + ')' });
    item.sections.push({ title: 'Seriais revogados (serial / data)', rows: rows });
  }
  item.openssl = 'openssl crl -in lista.crl -noout -text';
}

/* ---------- deteccao de tipo ---------- */
function looksLikeCSR(bytes, root) {
  var c0 = child(root, 0);
  return !!(c0 && c0.tag === 16 && child(c0, 0) && child(c0, 0).tag === 2 &&
    child(c0, 1) && child(c0, 1).tag === 16 && child(c0, 2) && child(c0, 2).tag === 16 &&
    child(child(c0, 2), 0) && child(child(c0, 2), 0).tag === 16 && child(child(c0,2),1) && child(child(c0,2),1).tag === 3);
}
function looksLikeCert(bytes, root) {
  var c0 = child(root, 0);
  if (!c0 || c0.tag !== 16 || !c0.children) return false;
  return !!(findCtx(c0, 0) || (child(c0, 0) && child(c0, 0).tag === 2 && child(c0, 1) && child(c0, 1).tag === 16 &&
    child(c0, 2) && child(c0, 2).tag === 16 && child(c0, 3) && (child(c0,3).tag === 16)));
}
function looksLikePKCS8(bytes, root) {
  return !!(child(root, 0) && child(root, 0).tag === 2 && child(root, 1) && child(root, 1).tag === 16 &&
    child(root, 1).children && child(root, 1).children[0] && child(root, 1).children[0].tag === 6 &&
    child(root, 2) && child(root, 2).tag === 4);
}
function looksLikeEncPKCS8(bytes, root) {
  return !!(child(root, 0) && child(root, 0).tag === 16 && child(root, 0).children &&
    child(root, 0).children[0] && child(root, 0).children[0].tag === 6 &&
    child(root, 1) && child(root, 1).tag === 4);
}
function looksLikeRSAPrivate(bytes, root) {
  return !!(root.children && root.children.length >= 9 && root.children.every(function (c) { return c.tag === 2 || c.tag === 16; }) &&
    child(root, 0).tag === 2);
}
function looksLikeECPrivate(bytes, root) {
  return !!(child(root, 0) && child(root, 0).tag === 2 && child(root, 1) && child(root, 1).tag === 4);
}
function looksLikeSPKI(bytes, root) {
  return !!(child(root, 0) && child(root, 0).tag === 16 && child(root, 0).children &&
    child(root, 0).children[0] && child(root, 0).children[0].tag === 6 && child(root, 1) && child(root, 1).tag === 3);
}
function looksLikePKCS7(bytes, root) {
  return !!(child(root, 0) && child(root, 0).tag === 6);
}

var itemSeq = 0;
function newItem(sourceLabel, derBytes) {
  return { id: ++itemSeq, sourceLabel: sourceLabel, der: derBytes, kind: '?', rowsMain: [],
    sections: [], warnings: [], spkiDER: null, keyInfo: null, pendingVerify: null,
    needsPassword: false, encInfo: null, treeRoot: null, openssl: null };
}

function analyzeBlock(block, addItem) {
  var bytes = block.bytes;
  var label = block.label;
  var item = newItem(label ? ('Bloco PEM: ' + label) : 'Conteudo sem cabecalho PEM', bytes);
  if (block.removed > 10)
    item.warnings.push(block.removed + ' caracteres invalidos foram ignorados no base64 (possivel corrupcao ao copiar/colar).');
  if (block.noEnd)
    item.warnings.push('Bloco sem a linha -----END...----- : o conteudo provavelmente foi colado incompleto.');
  if (label === 'NEW CERTIFICATE REQUEST')
    item.rowsMain.push({ label: 'Formato', value: 'BEGIN NEW CERTIFICATE REQUEST (estilo Windows/IIS) - mesmo PKCS#10' });
  if (block.headers['DEK-Info']) {
    item.kind = 'Chave privada CRIPTOGRAFADA (PEM legado)';
    item.sections.push({ title: 'Criptografia da chave', rows: [
      { label: 'Formato', value: 'PEM legado com DEK-Info: ' + block.headers['DEK-Info'] },
      { label: 'Descriptografia', value: 'este formato usa derivacao MD5 (EVP_BytesToKey) e nao e suportado no navegador. Use: openssl rsa -in chave.key -out chave-aberta.key' }
    ]});
    addItem(item);
    return;
  }
  var root = null;
  try {
    var roots = derParseAll(bytes);
    root = roots[0] || null;
    // varios DER concatenados sem PEM (raro): tratar cada um
    if (roots.length > 1 && !label) {
      roots.forEach(function (r) {
        analyzeBlock({ label: null, headers: {}, bytes: bytes.subarray(r.start, r.contentEnd), removed: 0, noEnd: false }, addItem);
      });
      return;
    }
  } catch (e) {
    item.warnings.push('Erro ao interpretar DER: ' + e.message);
    addItem(item);
    return;
  }
  if (!root) { item.warnings.push('Nenhuma estrutura ASN.1 encontrada.'); addItem(item); return; }
  item.treeRoot = root;
  try {
    if (label === 'CERTIFICATE REQUEST' || label === 'NEW CERTIFICATE REQUEST') interpretCSR(bytes, root, item);
    else if (label === 'CERTIFICATE' || label === 'X509 CERTIFICATE' || label === 'TRUSTED CERTIFICATE') interpretCert(bytes, root, item);
    else if (label === 'PRIVATE KEY') interpretPKCS8(bytes, root, item);
    else if (label === 'ENCRYPTED PRIVATE KEY') interpretEncryptedPKCS8(bytes, root, item);
    else if (label === 'RSA PRIVATE KEY') interpretRSAPrivate(bytes, root, item);
    else if (label === 'EC PRIVATE KEY') interpretECPrivate(bytes, root, item, null);
    else if (label === 'PUBLIC KEY') interpretSPKIPublic(bytes, root, item);
    else if (label === 'PKCS7' || label === 'CMS') interpretPKCS7(bytes, root, item);
    else if (label === 'X509 CRL') interpretCRL(bytes, root, item);
    else {
      // sem label: heuristica estrutural
      if (looksLikeCSR(bytes, root)) interpretCSR(bytes, root, item);
      else if (looksLikeEncPKCS8(bytes, root) && !looksLikeCert(bytes, root)) interpretEncryptedPKCS8(bytes, root, item);
      else if (looksLikePKCS8(bytes, root)) interpretPKCS8(bytes, root, item);
      else if (looksLikeRSAPrivate(bytes, root)) interpretRSAPrivate(bytes, root, item);
      else if (looksLikeSPKI(bytes, root)) interpretSPKIPublic(bytes, root, item);
      else if (looksLikeCert(bytes, root)) interpretCert(bytes, root, item);
      else if (looksLikePKCS7(bytes, root)) interpretPKCS7(bytes, root, item);
      else if (looksLikeECPrivate(bytes, root)) interpretECPrivate(bytes, root, item, null);
      else { item.kind = 'Estrutura ASN.1 (tipo nao identificado)'; item.warnings.push('Nao foi possivel identificar o tipo. Veja a estrutura ASN.1 abaixo.'); }
    }
  } catch (e) {
    item.warnings.push('Erro na interpretacao: ' + e.message + '. A estrutura ASN.1 bruta esta disponivel abaixo.');
  }
  addItem(item);
  (item.subItems || []).forEach(addItem);
}

async function decryptEncKey(item, password) {
  var enc = item.encInfo;
  var pwKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  var bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.salt, iterations: enc.iter, hash: enc.prf }, pwKey, enc.keyLen * 8);
  var aesKey = await crypto.subtle.importKey('raw', bits, { name: 'AES-CBC' }, false, ['decrypt']);
  var plain = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: enc.iv }, aesKey, enc.data);
  return new Uint8Array(plain);
}
