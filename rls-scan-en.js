/* rls-scan-en.js — offline static scanner for Supabase/Postgres migrations (English strings)
 * No network, no upload: input is scanned in browser memory and dropped.
 * Also usable as a CommonJS module in node for regression tests.
 * Logic is identical to rls-scan.js; only the human-readable strings differ.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.RLSScan = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var USER_DATA_RE = /(user|profile|order|customer|account|invoice|payment|loan|member|crm|billing|contact|message|document|file)/i;

  function stripComments(sql) {
    return sql
      .replace(/\/\*[\s\S]*?\*\//g, function (m) { return new Array(m.length + 1).join(' '); })
      .replace(/--[^\n]*/g, function (m) { return new Array(m.length + 1).join(' '); });
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

  function normTable(raw) {
    var parts = raw.replace(/["'`]/g, '').split('.').filter(Boolean);
    if (parts.length === 1) return 'public.' + parts[0];
    return parts.slice(-2).join('.');
  }

  function isPublic(t) { return t.indexOf('public.') === 0; }

  function extractStatement(text, startIdx) {
    var end = text.indexOf(';', startIdx);
    if (end === -1) end = text.length;
    return { body: text.slice(startIdx, end), start: startIdx, end: end };
  }

  function scan(sql) {
    var text = stripComments(String(sql || ''));
    var lineOf = makeLineOf(text);
    var tables = {};       // name -> {rls:bool, line:n}
    var policies = [];     // {table, body, line}
    var findings = [];
    var i;

    // ---- tables ----
    var reCreate = /create\s+table\s+(?:if\s+not\s+exists\s+)?([\w."]+)/gi, m;
    while ((m = reCreate.exec(text))) {
      var t = normTable(m[1]);
      if (!tables[t]) tables[t] = { rls: false, line: lineOf(m.index) };
    }

    // ---- enable RLS ----
    var reEnable = /alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([\w."]+)\s+enable\s+row\s+level\s+security/gi;
    while ((m = reEnable.exec(text))) {
      var t2 = normTable(m[1]);
      if (!tables[t2]) tables[t2] = { rls: false, line: lineOf(m.index) };
      tables[t2].rls = true;
    }

    // ---- policies ----
    var rePolicy = /create\s+policy\s+(?:"[^"]*"|[A-Za-z_][\w]*)\s+on\s+([\w."]+)/gi;
    while ((m = rePolicy.exec(text))) {
      var st = extractStatement(text, m.index);
      policies.push({ table: normTable(m[1]), body: st.body, line: lineOf(m.index), raw: st.body });
    }

    // ---- per policy ----
    policies.forEach(function (p) {
      var body = p.body;
      var low = body.toLowerCase();
      var permissive = /using\s*\(\s*true\s*\)/.test(low) || /with\s+check\s*\(\s*true\s*\)/.test(low)
        || /using\s*\(\s*1\s*=\s*1\s*\)/.test(low);
      var noTo = !/\bto\s+[a-z_]/.test(low);
      var cmdM = low.match(/\bfor\s+(all|select|insert|update|delete)\b/);
      var cmd = cmdM ? cmdM[1] : 'all';
      var scopedByUid = /auth\.uid\s*\(\s*\)/.test(low);
      var onPublic = isPublic(p.table);
      var sens = USER_DATA_RE.test(p.table.split('.')[1] || '');

      if (permissive) {
        findings.push({
          severity: (noTo || cmd === 'all' || cmd === 'select') ? 'critical' : 'high',
          code: 'RLS-PERMISSIVE',
          table: p.table,
          line: p.line,
          title: 'Policy is a no-op: whole table open to ' + (noTo ? 'every role, including anon' : cmd.toUpperCase()),
          evidence: oneLine(p.raw),
          impact: noTo
            ? 'No TO clause, so the anonymous role is in scope: anyone holding the public anon key shipped in your frontend can read and write every row.'
            : 'Any signed-in user can ' + (cmd === 'select' ? 'read' : 'write') + ' the entire table' + (sens ? ' — and this table holds user data.' : '.'),
          fix: 'Scope it to the owner: using (auth.uid() = user_id) (or a tenant-membership join). If a table genuinely needs public reads, keep SELECT only and comment why.'
        });
        return;
      }
      if (noTo && onPublic && !scopedByUid) {
        findings.push({
          severity: 'high', code: 'RLS-NO-TO', table: p.table, line: p.line,
          title: 'Policy has no TO clause, so the anon role is in scope',
          evidence: oneLine(p.raw),
          impact: 'A policy without TO applies to the public role by default, so the anon key hits it without any sign-in.',
          fix: 'Write TO authenticated explicitly (or a service_role-only policy) and make sure qual contains an ownership check such as auth.uid().'
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
        evidence: 'create table ' + name,
        impact: 'With RLS off, the anon key reads and writes the table under PostgREST defaults — the database is effectively public.',
        fix: 'Add alter table ' + name + ' enable row level security; in the same migration, then add an owner-scoped policy.'
      });
    });

    // ---- secrets ----
    var reSecret = /(service_role\s*key|supabase_service|sk_live_[A-Za-z0-9]{10,}|SERVICE_ROLE_KEY\s*[:=]\s*['"][^'"]{8,}['"]?|postgres(?:ql)?:\/\/[^\s:'"]+:[^\s@'"]{6,}@)/g;
    while ((m = reSecret.exec(text))) {
      var snippet = oneLine(text.slice(m.index, m.index + m[0].length));
      findings.push({
        severity: 'critical', code: 'SECRET', table: '—', line: lineOf(m.index),
        title: 'Secret or credential found in a migration or config file',
        evidence: snippet.replace(/(['"])[^'"]{6,}\1/g, '$1***$1'),
        impact: 'Committed to a repo means published: .env.example included. The filename does not change what it is.',
        fix: 'Rotate the key now, then move the value into your deploy platform environment variables. Deleting the file does not unpublish history.'
      });
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
        permissive: policies.filter(function (p) {
          var l = p.body.toLowerCase();
          return /using\s*\(\s*true\s*\)/.test(l) || /with\s+check\s*\(\s*true\s*\)/.test(l);
        }).length
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
