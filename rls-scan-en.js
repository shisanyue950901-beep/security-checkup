/* rls-scan-en.js — offline static scanner for Supabase/Postgres migrations (English strings)
 * No network, no upload: input is scanned in browser memory and dropped.
 * Also usable as a CommonJS module in node for regression tests.
 * Logic is identical to rls-scan.js; only the human-readable strings differ.
 *
 * v2 (2026-11-26): lexer-based comment/string handling (line numbers preserved,
 * nested block comments, strings kept out of DDL parsing), Postgres identifier
 * case folding, ordered RLS enable/disable/drop tracking, tautology variants
 * (((true)), OR true, 1=1, missing USING), ALTER POLICY, .env-style unquoted
 * service-role keys, service-role JWT detection, masked secret evidence.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.RLSScan = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var USER_DATA_RE = /(user|profile|order|customer|account|invoice|payment|loan|member|crm|billing|contact|message|document|file)/i;

  // ---------- lexer ----------
  // Produces two same-length views of the input (newlines preserved everywhere):
  //  - ddl:    comments and string literals blanked; quoted identifiers kept.
  //            Used for table / policy structure parsing.
  //  - secret: comments blanked, everything else kept. Used for secret patterns.
  // A "--" only counts as a comment in the secret view when it starts a line or
  // follows whitespace, so passwords like my--secretpass inside a config value
  // are not mistaken for comments. In the ddl view any "--" outside a string
  // is a comment, per SQL.
  function lexTexts(sql) {
    var ddl = [], secret = [], i = 0, n = sql.length;
    function push(d, s) { ddl.push(d); secret.push(s); }
    function blank(ch) { return ch === '\n' ? '\n' : ' '; }
    while (i < n) {
      var c = sql[i], c2 = sql.substr(i, 2);
      if (c2 === '--') {
        var proper = i === 0 || /\s/.test(sql[i - 1]);
        while (i < n && sql[i] !== '\n') { push(blank(sql[i]), proper ? blank(sql[i]) : sql[i]); i++; }
        continue;
      }
      if (c2 === '/*') {
        var depth = 0;
        while (i < n) {
          if (sql.substr(i, 2) === '/*') { depth++; push('  ', '  '); i += 2; }
          else if (sql.substr(i, 2) === '*/') { depth--; push('  ', '  '); i += 2; if (depth === 0) break; }
          else { push(blank(sql[i]), blank(sql[i])); i++; }
        }
        continue;
      }
      if (c === "'") { // string literal: blank in ddl, keep in secret
        push(' ', c); i++;
        while (i < n) {
          if (sql[i] === "'" && sql[i + 1] === "'") { push('  ', "''"); i += 2; continue; }
          if (sql[i] === "'") { push(' ', "'"); i++; break; }
          push(blank(sql[i]), sql[i]); i++;
        }
        continue;
      }
      if (c === '"') { // quoted identifier: keep in both
        push(c, c); i++;
        while (i < n) {
          if (sql[i] === '"' && sql[i + 1] === '"') { push('""', '""'); i += 2; continue; }
          push(sql[i], sql[i]); if (sql[i] === '"') { i++; break; } i++;
        }
        continue;
      }
      if (c === '$' && /^\$[A-Za-z_][\w]*\$|^\$\$/.test(sql.substr(i, 12))) { // dollar-quoted string
        var tag = sql.substr(i).match(/^\$[\w]*\$/)[0];
        var close = sql.indexOf(tag, i + tag.length);
        var end = close === -1 ? n : close + tag.length;
        while (i < end) { push(blank(sql[i]), sql[i]); i++; }
        continue;
      }
      push(c, c); i++;
    }
    return { ddl: ddl.join(''), secret: secret.join('') };
  }

  function makeLineOf(text) {
    var starts = [0];
    for (var i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
    return function (idx) {
      var lo = 0, hi = starts.length - 1;
      while (lo < hi) { var mid = (lo + hi + 1) >> 1; if (starts[mid] <= idx) lo = mid; else hi = mid - 1; }
      return lo + 1;
    };
  }

  // A possibly-qualified SQL name: "quoted part" or bareword, dot separated.
  var NAME_RE = '((?:"[^"]+"|[A-Za-z_][\\w$]*)(?:\\s*\\.\\s*(?:"[^"]+"|[A-Za-z_][\\w$]*))*)';

  // Postgres folding: unquoted identifiers fold to lowercase, quoted keep case.
  function normTable(raw) {
    var parts = [], m, re = /"([^"]+)"|([^."]+)/g;
    while ((m = re.exec(raw))) {
      if (m[1] !== undefined) parts.push(m[1]);
      else parts.push(m[2].trim().toLowerCase());
    }
    parts = parts.filter(function (p) { return p.length; });
    if (!parts.length) return raw;
    if (parts.length === 1) return 'public.' + parts[0];
    var last2 = parts.slice(-2);
    if (last2[0].toLowerCase() === 'public') last2[0] = 'public'; // schema named PUBLIC in any case is treated as the public schema
    return last2.join('.');
  }

  function isPublic(t) { return t.indexOf('public.') === 0; }

  // Statement text from `start` up to the first ';' outside double quotes.
  function extractStatement(text, start) {
    var inQ = false;
    for (var i = start; i < text.length; i++) {
      if (text[i] === '"') inQ = !inQ;
      if (text[i] === ';' && !inQ) return { body: text.slice(start, i), start: start, end: i };
    }
    return { body: text.slice(start), start: start, end: text.length };
  }

  // Balanced-paren expression starting at the '(' at index `openIdx`.
  function extractParen(text, openIdx) {
    var depth = 0;
    for (var i = openIdx; i < text.length; i++) {
      if (text[i] === '(') depth++;
      else if (text[i] === ')') { depth--; if (depth === 0) return text.slice(openIdx + 1, i); }
    }
    return text.slice(openIdx + 1);
  }

  function stripOuterParens(e) {
    e = e.trim();
    while (e.length > 1 && e[0] === '(' && e[e.length - 1] === ')') {
      var depth = 0, wraps = true;
      for (var i = 0; i < e.length; i++) {
        if (e[i] === '(') depth++;
        else if (e[i] === ')') { depth--; if (depth === 0 && i < e.length - 1) { wraps = false; break; } }
      }
      if (!wraps) break;
      e = e.slice(1, -1).trim();
    }
    return e;
  }

  // Split on a top-level keyword (paren depth 0).
  function splitTopLevel(e, kw) {
    var out = [], depth = 0, last = 0, low = e.toLowerCase(), needle = ' ' + kw + ' ';
    for (var i = 0; i < e.length; i++) {
      if (e[i] === '(') depth++;
      else if (e[i] === ')') depth--;
      else if (depth === 0 && low.substr(i, needle.length) === needle) {
        out.push(e.slice(last, i)); last = i + needle.length; i = last - 1;
      }
    }
    out.push(e.slice(last));
    return out;
  }

  // Is this USING / WITH CHECK expression effectively "let everything through"?
  function isWideOpen(expr) {
    if (expr == null) return false;
    var e = stripOuterParens(String(expr).toLowerCase().replace(/\s+/g, ' ').trim());
    e = stripOuterParens(e.replace(/::\s*(boolean|bool)\b/g, '').trim()); // true::boolean
    if (e === 'true') return true;
    var numEq = e.match(/^(\d+)\s*=\s*(\d+)$/);
    if (numEq && numEq[1] === numEq[2]) return true; // 1=1, 2=2, ...
    if (/^exists\s*\(/.test(e) && !/auth\./.test(e)) return true; // uncorrelated EXISTS over data is always true in practice
    if (/^auth\.uid\s*\(\s*\)\s+is\s+not\s+null$/.test(e)) return true;
    if (/^auth\.role\s*\(\s*\)\s*=\s*$/.test(e)) return true; // ='authenticated' with literal blanked
    var ors = splitTopLevel(e, 'or');
    if (ors.length > 1) return ors.some(function (part) { return isWideOpen(part); });
    return false;
  }

  function decodeJwtRole(jwt) {
    try {
      var payload = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      var json;
      if (typeof Buffer !== 'undefined') json = Buffer.from(payload, 'base64').toString('utf8');
      else json = decodeURIComponent(escape(atob(payload)));
      var obj = JSON.parse(json);
      return obj.role || obj['https://hasura.io/jwt/claims'] && obj['https://hasura.io/jwt/claims']['x-hasura-default-role'] || '';
    } catch (e) { return ''; }
  }

  function maskSecret(s) {
    if (/^sk_live_/i.test(s)) return 'sk_live_***';
    if (/postgres/i.test(s)) return s.replace(/(:\/\/[^\s:'"]+:)[^\s@'"]+(@)/, '$1***$2');
    var eq = s.search(/[:=]/);
    if (eq > -1 && s.length - eq > 10) return s.slice(0, eq + 1) + '***';
    if (/^eyJ/.test(s)) return s.split('.')[0] + '.***';
    return s.slice(0, 4) + '***';
  }

  function scan(sql) {
    var rawText = String(sql || '');
    var views = lexTexts(rawText);
    var text = views.ddl;
    var lineOf = makeLineOf(text);
    var tables = {};       // name -> {rls:bool, line:n, intro:string}
    var policies = [];     // parsed policy records
    var findings = [];
    var m;

    // ---- table events, applied in document order ----
    var events = [];
    var reCreate = new RegExp('create\\s+(?:unlogged\\s+|temp(?:orary)?\\s+)?table\\s+(?:if\\s+not\\s+exists\\s+)?' + NAME_RE, 'gi');
    while ((m = reCreate.exec(text))) events.push({ idx: m.index, kind: 'create', table: normTable(m[1]), stmt: m.index });
    var reAlter = new RegExp('alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?' + NAME_RE, 'gi');
    while ((m = reAlter.exec(text))) {
      var st = extractStatement(text, m.index);
      var lowBody = st.body.toLowerCase();
      var en = lowBody.lastIndexOf('enable row level security'), dis = lowBody.lastIndexOf('disable row level security');
      if (en > -1 || dis > -1) events.push({ idx: m.index, kind: en > dis ? 'enable' : 'disable', table: normTable(m[1]), stmt: m.index });
    }
    var reDrop = new RegExp('drop\\s+table\\s+(?:if\\s+exists\\s+)?' + NAME_RE, 'gi');
    while ((m = reDrop.exec(text))) events.push({ idx: m.index, kind: 'drop', table: normTable(m[1]), stmt: m.index });
    events.sort(function (a, b) { return a.idx - b.idx; });
    events.forEach(function (ev) {
      if (ev.kind === 'drop') { delete tables[ev.table]; return; }
      if (!tables[ev.table]) tables[ev.table] = { rls: false, line: lineOf(ev.stmt), intro: oneLine(extractStatement(text, ev.stmt).body).slice(0, 120) };
      if (ev.kind === 'enable') tables[ev.table].rls = true;
      if (ev.kind === 'disable') tables[ev.table].rls = false;
    });

    // ---- policies ----
    function normName(raw) { return raw.charAt(0) === '"' ? raw.slice(1, -1) : raw.toLowerCase(); }
    var rePolicy = new RegExp('create\\s+policy\\s+("[^"]*"|[A-Za-z_][\\w]*)\\s+on\\s+' + NAME_RE, 'gi');
    while ((m = rePolicy.exec(text))) {
      var pst = extractStatement(text, m.index);
      var rest = pst.body.slice(m[0].length); // after: create policy <name> on <table>
      policies.push(parsePolicy(normTable(m[2]), rest, pst.body, lineOf(m.index), normName(m[1]), m.index));
    }
    var reDropPol = new RegExp('drop\\s+policy\\s+(?:if\\s+exists\\s+)?("[^"]*"|[A-Za-z_][\\w]*)\\s+on\\s+' + NAME_RE, 'gi');
    var polDrops = [];
    while ((m = reDropPol.exec(text))) polDrops.push({ idx: m.index, name: normName(m[1]), table: normTable(m[2]) });
    if (polDrops.length) policies = policies.filter(function (p) {
      return !polDrops.some(function (d) { return d.idx > p.idx && d.table === p.table && d.name === p.name; });
    });
    // ---- alter policy (later loosening) ----
    var reAlterPol = new RegExp('alter\\s+policy\\s+(?:"[^"]*"|[A-Za-z_][\\w]*)\\s+on\\s+' + NAME_RE, 'gi');
    while ((m = reAlterPol.exec(text))) {
      var ast = extractStatement(text, m.index);
      var arest = ast.body.slice(m[0].length);
      var aexpr = clauseExpr(arest, 'using') || clauseExpr(arest, 'with check');
      if (aexpr && isWideOpen(aexpr)) {
        findings.push({
          severity: 'critical', code: 'RLS-PERMISSIVE', table: normTable(m[1]), line: lineOf(m.index),
          title: 'Policy was loosened to a no-op by ALTER POLICY',
          evidence: oneLine(ast.body),
          impact: 'An earlier restrictive policy was replaced with an always-true condition: the whole table is open to whoever the policy targets.',
          fix: 'Scope it to the owner: using (auth.uid() = user_id) (or a tenant-membership join).'
        });
      }
    }

    function clauseExpr(rest, kw) {
      var mm = new RegExp('\\b' + kw.replace(' ', '\\s+') + '\\s*\\(', 'i').exec(rest);
      if (!mm) return null;
      return extractParen(rest, mm.index + mm[0].length - 1);
    }

    function parsePolicy(table, rest, rawBody, line, name, idx) {
      var low = rest.toLowerCase();
      var cmdM = low.match(/\bfor\s+(all|select|insert|update|delete)\b/);
      var cmd = cmdM ? cmdM[1] : 'all';
      var roles = null;
      var toM = /\bto\s+((?:"[^"]+"|[a-z_][\w]*)(?:\s*,\s*(?:"[^"]+"|[a-z_][\w]*))*)/i.exec(rest);
      if (toM) roles = toM[1].split(',').map(function (r) { return r.trim().replace(/"/g, '').toLowerCase(); });
      var usingExpr = clauseExpr(rest, 'using');
      var checkExpr = clauseExpr(rest, 'with check');
      var wide = false;
      if (usingExpr != null && isWideOpen(usingExpr)) wide = true;
      if (checkExpr != null && isWideOpen(checkExpr)) wide = true;
      if (usingExpr == null && checkExpr == null) wide = true; // PG default: permissive true
      if (cmd === 'update' && usingExpr != null && checkExpr == null && isWideOpen(usingExpr)) wide = true;
      return {
        table: table, body: rawBody, line: line, name: name, idx: idx, cmd: cmd, roles: roles,
        usingExpr: usingExpr, checkExpr: checkExpr, wide: wide,
        scopedByUid: /auth\.uid\s*\(\s*\)/.test(low)
      };
    }

    // ---- per policy findings ----
    policies.forEach(function (p) {
      var onPublic = isPublic(p.table);
      var sens = USER_DATA_RE.test(p.table.split('.')[1] || '');
      var roles = p.roles;
      var serviceOnly = roles && roles.length === 1 && roles[0] === 'service_role';
      if (serviceOnly) return; // service_role bypasses RLS by design; the policy is inert
      var noTo = !roles;
      var anonInScope = noTo || (roles && (roles.indexOf('anon') > -1 || roles.indexOf('public') > -1));

      if (p.wide) {
        var critical = noTo || anonInScope || p.cmd === 'all' || p.cmd === 'select' || p.cmd === 'insert';
        findings.push({
          severity: critical ? 'critical' : 'high',
          code: 'RLS-PERMISSIVE',
          table: p.table,
          line: p.line,
          title: 'Policy is a no-op: whole table open to ' + (noTo ? 'every role, including anon' : p.cmd.toUpperCase()),
          evidence: oneLine(p.body),
          impact: noTo
            ? 'No TO clause, so the anonymous role is in scope: anyone holding the public anon key shipped in your frontend can read and write every row.'
            : (anonInScope
              ? 'The anonymous role is in scope: anyone holding the public anon key shipped in your frontend can reach every row this policy covers.'
              : 'Any signed-in user can ' + (p.cmd === 'select' ? 'read' : 'write') + ' the entire table' + (sens ? ' — and this table holds user data.' : '.')),
          fix: 'Scope it to the owner: using (auth.uid() = user_id) (or a tenant-membership join). If a table genuinely needs public reads, keep SELECT only and comment why.'
        });
        return;
      }
      if (noTo && onPublic && !p.scopedByUid) {
        findings.push({
          severity: 'high', code: 'RLS-NO-TO', table: p.table, line: p.line,
          title: 'Policy has no TO clause, so the anon role is in scope',
          evidence: oneLine(p.body),
          impact: 'A policy without TO applies to the public role by default, so the anon key hits it without any sign-in.',
          fix: 'Write TO authenticated explicitly (or a service_role-only policy) and make sure qual contains an ownership check such as auth.uid().'
        });
      } else if (!noTo && anonInScope && onPublic && !p.scopedByUid && p.cmd !== 'select') {
        findings.push({
          severity: 'high', code: 'RLS-NO-TO', table: p.table, line: p.line,
          title: 'Policy grants ' + p.cmd.toUpperCase() + ' to the anonymous role without an ownership check',
          evidence: oneLine(p.body),
          impact: 'The policy names the anon/public role for a write operation and its condition is not scoped to an owner, so the public anon key can write rows it should not reach.',
          fix: 'Restrict writes to authenticated and scope the condition to the owner, e.g. using (auth.uid() = user_id).'
        });
      }
    });

    // ---- table level ----
    Object.keys(tables).forEach(function (name) {
      var info = tables[name];
      if (!isPublic(name) || info.rls) return;
      findings.push({
        severity: 'critical', code: 'RLS-OFF', table: name, line: info.line,
        title: 'public table with RLS never enabled',
        evidence: info.intro || ('create table ' + name),
        impact: 'With RLS off, the anon key reads and writes the table under PostgREST defaults — the database is effectively public.',
        fix: 'Add alter table ' + name + ' enable row level security; in the same migration, then add an owner-scoped policy.'
      });
    });

    // ---- secrets (on the secret view: comments blanked, values intact) ----
    var stext = views.secret;
    function addSecret(idx, matched) {
      findings.push({
        severity: 'critical', code: 'SECRET', table: '—', line: lineOf(idx),
        title: 'Secret or credential found in a migration or config file',
        evidence: maskSecret(oneLine(matched)),
        impact: 'Committed to a repo means published: .env.example included. The filename does not change what it is.',
        fix: 'Rotate the key now, then move the value into your deploy platform environment variables. Deleting the file does not unpublish history.'
      });
    }
    var seenSecretAt = {};
    function addSecretOnce(idx, matched) {
      var key = idx + ':' + matched.slice(0, 12);
      if (seenSecretAt[key]) return;
      seenSecretAt[key] = 1;
      addSecret(idx, matched);
    }
    var reSecret = /(sk_live_[A-Za-z0-9]{10,}|postgres(?:ql)?:\/\/[^\s:'"]+:[^\s@'"]{1,}@[^\s/'"]+|(?:supabase_)?service_role_key\s*[:=]\s*['"]?[^\s'"]{8,}['"]?)/gi;
    while ((m = reSecret.exec(stext))) {
      var val = m[0];
      var assign = val.search(/[:=]/);
      if (/service_role_key/i.test(val) && assign > -1) {
        var v = val.slice(assign + 1).replace(/^['"]|['"]$/g, '').trim();
        if (/^(x{3,}|\*{3,}|your[-_]|changeme|placeholder|example|test[-_]?key)/i.test(v)) continue;
      }
      addSecretOnce(m.index, val);
    }
    var reJwt = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
    while ((m = reJwt.exec(stext))) {
      if (decodeJwtRole(m[0]) === 'service_role') addSecretOnce(m.index, m[0]);
    }

    var order = { critical: 0, high: 1, medium: 2 };
    findings.sort(function (a, b) { return order[a.severity] - order[b.severity] || a.line - b.line; });

    var counts = { critical: 0, high: 0, medium: 0 };
    findings.forEach(function (f) { counts[f.severity]++; });
    var penalty = counts.critical * 30 + counts.high * 12 + counts.medium * 4;
    var score = Math.max(0, 100 - penalty);

    return {
      score: score,
      counts: counts,
      findings: findings,
      stats: {
        tables: Object.keys(tables).length,
        rlsOff: Object.keys(tables).filter(function (n) { return isPublic(n) && !tables[n].rls; }).length,
        policies: policies.length,
        permissive: policies.filter(function (p) { return p.wide; }).length
      }
    };
  }

  function oneLine(s) {
    return String(s).replace(/\s+/g, ' ').trim().slice(0, 220);
  }

  function toMarkdown(r) {
    var head = '### RLS self-check: ' + r.score + '/100\n\n'
      + r.stats.tables + ' tables, ' + r.stats.policies + ' policies scanned; '
      + 'critical ' + r.counts.critical + ' / high ' + r.counts.high + ' / medium ' + r.counts.medium + '.\n';
    if (!r.findings.length) return head + '\nNo issues matched. Note this is a static rule match, not a human review.\n';
    return head + r.findings.map(function (f) {
      return '\n- **[' + f.severity.toUpperCase() + ']** `' + f.table + '` L' + f.line + ' ' + f.title + '\n  - `' + f.evidence + '`';
    }).join('\n') + '\n';
  }

  return { scan: scan, toMarkdown: toMarkdown };
}));
