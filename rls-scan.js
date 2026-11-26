/* rls-scan.js — 纯本地静态扫描器：Supabase / Postgres 迁移里的 RLS 与密钥问题
 * 无网络、无上传：输入贴进来，只在浏览器内存里算，扫完即丢。
 * 同时可作为 CommonJS 模块在 node 里跑回归测试。
 * 逻辑与 rls-scan-en.js 完全一致，只有文案是中文。
 *
 * v2（2026-11-26）：词法级注释/字符串处理（行号不再错位、支持嵌套块注释、
 * 字符串内容不参与 DDL 解析）、标识符大小写折叠、RLS 开/关/删表按文档顺序跟踪、
 * 恒真式变体（((true))、OR true、1=1、缺 USING）、ALTER POLICY、
 * .env 无引号 service-role 密钥、service-role JWT 识别、密钥证据脱敏。
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
    if (e === 'true' || e === '1=1' || e === '1 = 1') return true;
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
    var rePolicy = new RegExp('create\\s+policy\\s+(?:"[^"]*"|[A-Za-z_][\\w]*)\\s+on\\s+' + NAME_RE, 'gi');
    while ((m = rePolicy.exec(text))) {
      var pst = extractStatement(text, m.index);
      var rest = pst.body.slice(m[0].length); // after: create policy <name> on <table>
      policies.push(parsePolicy(normTable(m[1]), rest, pst.body, lineOf(m.index)));
    }
    // ---- alter policy (later loosening) ----
    var reAlterPol = new RegExp('alter\\s+policy\\s+(?:"[^"]*"|[A-Za-z_][\\w]*)\\s+on\\s+' + NAME_RE, 'gi');
    while ((m = reAlterPol.exec(text))) {
      var ast = extractStatement(text, m.index);
      var arest = ast.body.slice(m[0].length);
      var aexpr = clauseExpr(arest, 'using') || clauseExpr(arest, 'with check');
      if (aexpr && isWideOpen(aexpr)) {
        findings.push({
          severity: 'critical', code: 'RLS-PERMISSIVE', table: normTable(m[1]), line: lineOf(m.index),
          title: '策略被 ALTER POLICY 改成了摆设',
          evidence: oneLine(ast.body),
          impact: '先前收窄的策略被换成了恒真条件：整张表对这条策略的目标角色敞开',
          fix: '改成 auth.uid() = user_id（或 tenant 成员表 join），按 owner 收窄'
        });
      }
    }

    function clauseExpr(rest, kw) {
      var mm = new RegExp('\\b' + kw.replace(' ', '\\s+') + '\\s*\\(', 'i').exec(rest);
      if (!mm) return null;
      return extractParen(rest, mm.index + mm[0].length - 1);
    }

    function parsePolicy(table, rest, rawBody, line) {
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
        table: table, body: rawBody, line: line, cmd: cmd, roles: roles,
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
          title: '策略等于没有策略：' + (noTo ? '对所有角色' : p.cmd.toUpperCase()) + ' 放开整张表',
          evidence: oneLine(p.body),
          impact: noTo
            ? '策略没写 TO 子句，连未登录的 anon 角色都适用——拿着前端公开的 anon key 就能读写整张表'
            : (anonInScope
              ? '匿名角色也在适用范围——拿着前端公开的 anon key 就能触及这条策略覆盖的每一行'
              : '任何一个已登录用户都能' + (p.cmd === 'select' ? '读到' : '改写') + '全表' + (sens ? '，这张表存的是用户数据' : '')),
          fix: '改成 auth.uid() = user_id（或 tenant 成员表 join），按 owner 收窄；确需公开读的表只留 SELECT 并写注释说明原因'
        });
        return;
      }
      if (noTo && onPublic && !p.scopedByUid) {
        findings.push({
          severity: 'high', code: 'RLS-NO-TO', table: p.table, line: p.line,
          title: '策略缺 TO 子句，匿名角色也在适用范围',
          evidence: oneLine(p.body),
          impact: '没有 TO 子句的策略默认对 public 角色生效，anon key 不需要登录即可命中该策略',
          fix: '显式写 TO authenticated（或 service_role 专用），并确认 qual 里有 auth.uid() 之类的主体判断'
        });
      } else if (!noTo && anonInScope && onPublic && !p.scopedByUid && p.cmd !== 'select') {
        findings.push({
          severity: 'high', code: 'RLS-NO-TO', table: p.table, line: p.line,
          title: '策略对匿名角色开放 ' + p.cmd.toUpperCase() + ' 且没有主体收窄',
          evidence: oneLine(p.body),
          impact: '策略点名 anon/public 角色做写操作，条件又没按 owner 收窄，前端公开的 anon key 能写到不该写的行',
          fix: '写操作只给 authenticated，并把条件按 owner 收窄，例如 using (auth.uid() = user_id)'
        });
      }
    });

    // ---- table level ----
    Object.keys(tables).forEach(function (name) {
      var info = tables[name];
      if (!isPublic(name) || info.rls) return;
      findings.push({
        severity: 'critical', code: 'RLS-OFF', table: name, line: info.line,
        title: 'public 表没开 RLS',
        evidence: info.intro || ('create table ' + name),
        impact: 'RLS 未启用 = 前端 anon key 直接按 PostgREST 默认权限读写，等同于数据库公开',
        fix: '在同一个 migration 里 alter table ' + name + ' enable row level security; 随后补 owner 策略'
      });
    });

    // ---- secrets (on the secret view: comments blanked, values intact) ----
    var stext = views.secret;
    function addSecret(idx, matched) {
      findings.push({
        severity: 'critical', code: 'SECRET', table: '—', line: lineOf(idx),
        title: '密钥/凭据出现在迁移或配置文件里',
        evidence: maskSecret(oneLine(matched)),
        impact: '提交进仓库就等于已发布：.env.example 也一样，文件名不改变它的公开属性',
        fix: '立刻轮换该密钥，然后把值挪到部署平台的环境变量；删文件不会让历史提交里的值失效'
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
    var head = '### RLS 自检结果：' + r.score + '/100\n\n'
      + '扫描到 ' + r.stats.tables + ' 张表、' + r.stats.policies + ' 条策略；'
      + '严重 ' + r.counts.critical + ' / 高 ' + r.counts.high + ' / 中 ' + r.counts.medium + '。\n';
    if (!r.findings.length) return head + '\n没扫出严重问题。注意这只是一次静态规则匹配，不等于人工复核。\n';
    return head + r.findings.map(function (f) {
      return '\n- **[' + f.severity.toUpperCase() + ']** `' + f.table + '` L' + f.line + ' ' + f.title + '\n  - `' + f.evidence + '`';
    }).join('\n') + '\n';
  }

  return { scan: scan, toMarkdown: toMarkdown };
}));
