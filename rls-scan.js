/* rls-scan.js — 纯本地静态扫描器：Supabase / Postgres 迁移里的 RLS 与密钥问题
 * 无网络、无上传：输入贴进来，只在浏览器内存里算，扫完即丢。
 * 同时可作为 CommonJS 模块在 node 里跑回归测试。
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

    // ---- 建表 ----
    var reCreate = /create\s+table\s+(?:if\s+not\s+exists\s+)?([\w."]+)/gi, m;
    while ((m = reCreate.exec(text))) {
      var t = normTable(m[1]);
      if (!tables[t]) tables[t] = { rls: false, line: lineOf(m.index) };
    }

    // ---- 开 RLS ----
    var reEnable = /alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([\w."]+)\s+enable\s+row\s+level\s+security/gi;
    while ((m = reEnable.exec(text))) {
      var t2 = normTable(m[1]);
      if (!tables[t2]) tables[t2] = { rls: false, line: lineOf(m.index) };
      tables[t2].rls = true;
    }

    // ---- 策略 ----
    var rePolicy = /create\s+policy\s+(?:"[^"]*"|[A-Za-z_][\w]*)\s+on\s+([\w."]+)/gi;
    while ((m = rePolicy.exec(text))) {
      var st = extractStatement(text, m.index);
      policies.push({ table: normTable(m[1]), body: st.body, line: lineOf(m.index), raw: st.body });
    }

    // ---- 逐条判 ----
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
          title: '策略等于没有策略：' + (noTo ? '对所有角色' : cmd.toUpperCase()) + ' 放开整张表',
          evidence: oneLine(p.raw),
          impact: noTo
            ? '策略没写 TO 子句，连未登录的 anon 角色都适用——拿着前端公开的 anon key 就能读写整张表'
            : '任何一个已登录用户都能' + (cmd === 'select' ? '读到' : '改写') + '全表' + (sens ? '，这张表存的是用户数据' : ''),
          fix: '改成 auth.uid() = user_id（或 tenant 成员表 join），按 owner 收窄；确需公开读的表只留 SELECT 并写注释说明原因'
        });
        return;
      }
      if (noTo && onPublic && !scopedByUid) {
        findings.push({
          severity: 'high', code: 'RLS-NO-TO', table: p.table, line: p.line,
          title: '策略缺 TO 子句，匿名角色也在适用范围',
          evidence: oneLine(p.raw),
          impact: '没有 TO 子句的策略默认对 public 角色生效，anon key 不需要登录即可命中该策略',
          fix: '显式写 TO authenticated（或 service_role 专用），并确认 qual 里有 auth.uid() 之类的主体判断'
        });
      }
    });

    // ---- 表级 ----
    Object.keys(tables).forEach(function (name) {
      var info = tables[name];
      if (!isPublic(name) || info.rls) return;
      findings.push({
        severity: 'critical', code: 'RLS-OFF', table: name, line: info.line,
        title: 'public 表没开 RLS',
        evidence: 'create table ' + name,
        impact: 'RLS 未启用 = 前端 anon key 直接按 PostgREST 默认权限读写，等同于数据库公开',
        fix: '在同一个 migration 里 alter table ' + name + ' enable row level security; 随后补 owner 策略'
      });
    });

    // ---- 密钥 ----
    var reSecret = /(service_role\s*key|supabase_service|sk_live_[A-Za-z0-9]{10,}|SERVICE_ROLE_KEY\s*[:=]\s*['"][^'"]{8,}['"]?|postgres(?:ql)?:\/\/[^\s:'"]+:[^\s@'"]{6,}@)/g;
    while ((m = reSecret.exec(text))) {
      var snippet = oneLine(text.slice(m.index, m.index + m[0].length));
      findings.push({
        severity: 'critical', code: 'SECRET', table: '—', line: lineOf(m.index),
        title: '密钥/凭据出现在迁移或配置文件里',
        evidence: snippet.replace(/(['"])[^'"]{6,}\1/g, '$1***$1'),
        impact: '提交进仓库就等于已发布：.env.example 也一样，文件名不改变它的公开属性',
        fix: '立刻轮换该密钥，然后把值挪到部署平台的环境变量；删文件不会让历史提交里的值失效'
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
