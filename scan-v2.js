/* Bremta local static analyzer v2. Built from the frozen v1 lexer/helpers.
 * SQL/Firebase parsers accept documented subsets; unsupported input is unknown.
 * No network, persistence, evaluation, telemetry, or raw evidence in reports.
 * Acorn 8.19.0 (MIT) is vendored alongside this file for JS AST parsing.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./vendor/acorn.js'));
  else root.BremtaScan = factory(root.acorn);
}(typeof self !== 'undefined' ? self : this, function (acorn) {
  'use strict';
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

  function decodeJwtRole(jwt) {
    try {
      var payload = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      var json;
      if (typeof Buffer !== 'undefined') json = Buffer.from(payload, 'base64').toString('utf8');
      else json = decodeURIComponent(escape(atob(payload)));
      var obj = JSON.parse(json);
      return obj && typeof obj === 'object' ? obj.role || '' : '';
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


  const STATES = Object.freeze({ found:'Confirmed issue', review:'Needs manual review', clear:'Not observed in pasted input', unknown:'Unable to determine' });
  const VERSION = '2.0.0-staging';
  const MAX = 1000000;
  function walk(n, visit, ancestors = []) {
    if (!n || typeof n.type !== 'string') return;
    visit(n, ancestors);
    for (const [k,v] of Object.entries(n)) {
      if (k === 'loc') continue;
      if (Array.isArray(v)) v.forEach(x => walk(x, visit, ancestors.concat(n)));
      else if (v && typeof v.type === 'string') walk(v, visit, ancestors.concat(n));
    }
  }
  function path(n) {
    if (!n) return '';
    if (n.type === 'Identifier') return n.name;
    if (n.type === 'MemberExpression' && (!n.computed || n.property.type === 'Literal')) return path(n.object)+'.'+(n.property.name || n.property.value);
    return '';
  }
  function value(n) { return n && n.type === 'Literal' ? n.value : undefined; }
  function parseJS(s) { return acorn.parse(s, {ecmaVersion:2022, sourceType:'module', locations:true}); }
  function testFile(s) { s=(s||'').replace(/((?:^|[/\\])(?:app|pages)[/\\]api[/\\])(?:test|seed)(?=[/\\.]|$)/,'$1endpoint'); return /(?:^|[/\\])(?:__tests__|tests?|fixtures?|examples?|docs?|seed)(?:[/\\.]|$)|\.(?:spec|test)\.[cm]?[jt]sx?$|\.env\.test$/.test(s || ''); }
  function placeholder(s) {
    return !s || /(?:your[-_ ]|replace[-_ ]|placeholder|changeme|example|dummy|<[^>]+>|\$\{|process\.env|import\.meta\.env)/i.test(s) || /^(?:x+|\*+|0+|test[-_]?key)$/i.test(s) || /(?:^|_)(?:x{6,}|0{6,})(?:$|_)/i.test(s);
  }
  function keyKind(v) {
    if (typeof v !== 'string' || placeholder(v)) return '';
    // Value classification always precedes names. Only these shapes can pass A0.
    if (/^eyJ[\w-]+\.[\w-]+\.[\w-]+$/.test(v)) {
      const role = decodeJwtRole(v);
      return role === 'anon' ? 'public' : role === 'service_role' ? 'service-role JWT (decoded only, signature not verified)' : '';
    }
    if (/^(?:sb_publishable_|pk_(?:live|test)_|AIza[\w-]{20,}|phc_|6L[\w-]{20,})/.test(v)) return 'public';
    if (/^https?:\/\//i.test(v)) return 'public';
    if (/^-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]+-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----$/.test(v)) return 'private key block (structure not verified)';
    if (/^(?:postgres(?:ql)?|rediss?|smtps?|mysql|mongodb(?:\+srv)?):\/\//i.test(v)) {
      try {
        const u = new URL(v);
        if (!u.password || placeholder(decodeURIComponent(u.password)) || /^(?:password|pass|secret)$/i.test(u.password) || /^(?:localhost|127\.0\.0\.1|\[::1\])$/i.test(u.hostname)) return '';
        return 'connection string with embedded password';
      } catch (_) { return ''; }
    }
    const shapes = [
      [/^sb_secret_[\w-]{20,}$/, 'server-side secret key'],
      [/^sk_live_[A-Za-z0-9]{16,}$/, 'live payment secret key'],
      [/^sk_test_[A-Za-z0-9]{16,}$/, 'test payment secret key'],
      [/^sk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{24,}$/, 'AI provider API key'],
      [/^SG\.[\w-]{16,}\.[\w-]{24,}$/, 'email provider API key'],
      [/^re_[A-Za-z0-9_]{24,}$/, 'email provider API key'],
      [/^(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xoxb-[\w-]{24,})$/, 'service access token']
    ];
    for (const [re,k] of shapes) if (re.test(v)) return k;
    // No arbitrary entropy, variable-name-only, AKIA-id-only, or SMTP-password-only rule.
    return '';
  }
  function scan(input = {}) {
    if (typeof input === 'string') input = {sql:input};
    const out = {version:VERSION, states:STATES, findings:[], coverage:[], counts:{red:0,orange:0,blue:0}, issueCount:0};
    function add(code, state, level, source, line, title, impact, fix, boundary) {
      out.findings.push({code,state:STATES[state],level:level || null,source,line:Math.max(1,line || 1),
        evidence:'*** (redacted)',title,impact,fix,boundary:boundary || 'Covers only the pasted input; deployment state and exploitability are not verified.'});
    }
    function unknown(code, source, title, line=1) { add(code,'unknown',null,source,line,title,'Insufficient input to conclude a vulnerability exists.','Provide the complete input and context; do not blindly rewrite permissions just to silence a notice.'); }
    function covered(group, hasInput, fn) {
      const before=out.findings.length;
      if (!hasInput) unknown(group,group,'No input provided for this section');
      else { try { fn(); } catch (_) { out.findings.splice(before); unknown(group,group,'Parse failed or input is outside supported syntax; conclusions for this section stopped'); } }
      const fs=out.findings.slice(before);
      const state=fs.some(f=>f.state===STATES.found)?STATES.found:fs.some(f=>f.state===STATES.review)?STATES.review:fs.some(f=>f.state===STATES.unknown)?STATES.unknown:STATES.clear;
      out.coverage.push({group,state});
    }
    const ctx=input.context || {};
    covered('SQL',!!input.sql,()=>{ if(input.sql.length>MAX) throw Error(); sqlScan(input.sql,ctx,add,unknown); secretText(input.sql,'SQL',false,false,add); });
    covered('Firebase',!!(input.firebase && input.firebase.text),()=>{
      if(input.firebase.text.length>MAX) throw Error(); firebaseScan(input.firebase,add,unknown);
    });
    const files=Array.isArray(input.files)?input.files:[];
    covered('Code',files.length>0,()=>{
      if(files.length>40) throw Error();
      const parsed=files.map((f,i)=>{
        const source='Code file '+(i+1);
        if(typeof f.text !== 'string' || f.text.length>MAX) { unknown('JS-PARSE',source,'File content is missing or exceeds the 1 MB limit'); return null; }
        if(/\.env(?:\.|$)/.test(f.name || '') || f.language==='env') { secretText(f.text,source,f.client===true,testFile(f.name),add); return null; }
        try { if(f.language==='json'){JSON.parse(f.text);return {f,source,ast:parseJS('('+f.text+')')};} return {f,source,ast:parseJS(f.text)}; }
        catch (_) { unknown('JS-PARSE',source,'Only ECMAScript 2022 is supported; TypeScript, JSX, and incomplete syntax are not supported yet'); return null; }
      });
      parsed.filter(Boolean).forEach(p=>jsScan(p,parsed.filter(Boolean),ctx,add,unknown));
    });
    covered('Headers',!!input.headers,()=>{ if(input.headers.length>MAX) throw Error(); headerScan(input.headers,add,unknown); });
    // Merge multiple presentations of one key/route root at the same masked line.
    const keyPriority={'KEY-PUBLIC':0,'KEY-CLIENT':1,'KEY-ENV':2,'KEY-HARDCODE':3};
    const keys=new Map();for(const f of out.findings)if(f.code in keyPriority){const k=f.source+':'+f.line;const previous=keys.get(k);if(!previous||keyPriority[f.code]<keyPriority[previous.code])keys.set(k,f);}
    const debug=new Set(out.findings.filter(f=>f.code==='DEBUG-ENDPOINT').map(f=>f.source+':'+f.line));
    const seen=new Set();out.findings=out.findings.filter(f=>{if(f.code in keyPriority&&keys.get(f.source+':'+f.line)!==f)return false;if(f.code==='API-AUTH'&&debug.has(f.source+':'+f.line))return false;const k=[f.code,f.source,f.line,f.state,f.title].join('|');if(seen.has(k))return false;seen.add(k);return true;});
    for (const f of out.findings) if(f.level) out.counts[f.level]++;
    out.issueCount=out.counts.red+out.counts.orange; // Education/unknown never counted.
    out.findings.sort((a,b)=>({red:0,orange:1,blue:2}[a.level]??3)-({red:0,orange:1,blue:2}[b.level]??3) || a.line-b.line);
    return out;
  }
  function secretFinding(v,name,source,line,client,add) {
    const kind=keyKind(v);
    if(!kind || kind==='public') return;
    const pub=/^(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_)/.test(name || '');
    const code=pub?'KEY-PUBLIC':/service-role|server-side secret/.test(kind)&&client?'KEY-CLIENT':name==='ENV'?'KEY-ENV':'KEY-HARDCODE';
    add(code,'review','orange',source,line,'Found '+kind+(pub?' in a public-prefixed variable':client?' in client-reachable code':' directly in pasted input'),
      'If this is a real, exposed backend credential, anyone who gets it can read or modify your data or run up your bill using your permissions.',
      'Verify what this credential is for and where it is exposed. If it is live and leaked, revoke or rotate it first, then inject it via server-side environment variables.',
      'Classification is based on value shape or decoded JWT payload only — authenticity, signature, active status, revocation, and deployment are not verified. Server-side storage alone does not mean a leak.');
  }
  function secretText(text,source,client,isTest,add) {
    if(isTest) return;
    // SQL lexer removes comments. ENV has its own line grammar; no URL requests.
    const s=source==='SQL'?lexTexts(text).secret:text;
    const lineOf=makeLineOf(s);
    const re=/^(?:\s*(?:export\s+)?)([A-Za-z_][\w]*)\s*=\s*([^\n]+)$/gm;
    let m;
    while((m=re.exec(s))) {
      let v=m[2].trim();
      if(v[0]==='"' || v[0]==="'") { const q=v[0],end=v.indexOf(q,1); if(end<0) continue; v=v.slice(1,end); }
      else v=v.replace(/\s+#.*$/,'').trim();
      secretFinding(v,/^(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_)/.test(m[1])?m[1]:'ENV',source,lineOf(m.index),client,add);
    }
    if(source==='SQL') {
      const lit=/'((?:''|[^'])*)'/g;
      while((m=lit.exec(s))) secretFinding(m[1].replace(/''/g,"'"),'',source,lineOf(m.index),false,add);
    }
  }

  // SQL statement AST subset. Values and comments never become DDL tokens.
  function tokensSQL(text) {
    const t=[]; let i=0;
    while(i<text.length) {
      if(/\s/.test(text[i])) {i++;continue;}
      if(text[i]==='"') {let j=i+1,v=''; for(;j<text.length;j++){if(text[j]==='"'){if(text[j+1]==='"'){v+='"';j++;}else break;}else v+=text[j];} if(j===text.length) throw Error(); t.push({v,quoted:true,i});i=j+1;continue;}
      const m=/^[A-Za-z_][\w$]*|^\d+(?:\.\d+)?|^(?:->>|->|::|>=|<=|!=|<>)/.exec(text.slice(i));
      if(m){t.push({v:m[0].toLowerCase(),i});i+=m[0].length;}
      else {t.push({v:text[i],i});i++;}
    }
    return t;
  }
  // Deliberately small SQL expression AST. Unsupported operators, subqueries,
  // functions or casts stop SQL permission inference, rather than guessing.
  function sqlExpression(raw) {
    const s=lexTexts(raw).secret,ts=[];let i=0;
    while(i<s.length){
      if(/\s/.test(s[i])){i++;continue;}
      let m;
      if((m=/^'(?:''|[^'])*'/.exec(s.slice(i)))){ts.push({kind:'literal',v:m[0].slice(1,-1).replace(/''/g,"'")});i+=m[0].length;}
      else if((m=/^"(?:""|[^"])*"/.exec(s.slice(i)))){ts.push({kind:'identifier',v:m[0].slice(1,-1).replace(/""/g,'"')});i+=m[0].length;}
      else if((m=/^\d+(?:\.\d+)?/.exec(s.slice(i)))){ts.push({kind:'number',v:m[0]});i+=m[0].length;}
      else if((m=/^[A-Za-z_][\w$]*/.exec(s.slice(i)))){ts.push({kind:'word',v:m[0].toLowerCase()});i+=m[0].length;}
      else if((m=/^(?:->>|->|::|<>|!=|<=|>=|[().,=<>])/.exec(s.slice(i)))){ts.push({kind:'op',v:m[0]});i+=m[0].length;}else throw Error();
    }
    let k=0;const at=()=>ts[k]?.v;function eat(v){if(at()!==v)throw Error();k++;}
    function atom(){
      let n,t=ts[k++];if(!t)throw Error();
      if(t.kind==='op'&&t.v==='('){n=expr(0);eat(')');}
      else if(t.kind==='word'&&t.v==='not')n={type:'not',child:expr(4)};
      else if(t.kind==='literal')n={type:'literal',value:t.v};
      else if(t.kind==='number')n={type:'number',value:t.v};
      else if(t.kind==='word'&&['true','false','null'].includes(t.v))n={type:'literal',value:t.v==='null'?null:t.v==='true'};
      else if(t.kind==='word'||t.kind==='identifier'){
        let name=t.v;while(at()==='.'){k++;const a=ts[k++];if(!a||!['word','identifier'].includes(a.kind))throw Error();name+='.'+a.v;}
        if(at()==='('){k++;const args=[];while(at()!==')'){args.push(expr(0));if(at()!==',')break;k++;}eat(')');if(!['auth.uid','auth.jwt','auth.role'].includes(name)||args.length)throw Error();n={type:'call',name};}
        else n={type:'identifier',name};
      }else throw Error();
      while(at()==='->'||at()==='->>'||at()==='::'){
        const op=ts[k++].v,t=ts[k++];if(!t)throw Error();
        if(op==='::'){if(t.kind!=='word'||!['bool','boolean','uuid','text'].includes(t.v))throw Error();n={type:'cast',child:n,to:t.v};}
        else{if(!['literal','number'].includes(t.kind))throw Error();n={type:'json',child:n,key:t.v,op};}
      }return n;
    }
    function expr(min){
      let left=atom();
      while(k<ts.length){
        const op=at(),priority={or:1,and:2,'=':3,'<>':3,'!=':3,'<':3,'>':3,'<=':3,'>=':3,is:3}[op];
        if(priority===undefined||priority<min||ts[k].kind==='identifier')break;k++;
        if(op==='is'){let not=false;if(at()==='not'){not=true;k++;}eat('null');left={type:'isnull',child:left,not};}
        else left={type:'binary',op,left,right:expr(priority+1)};
      }return left;
    }
    const ast=expr(0);if(k!==ts.length)throw Error();return ast;
  }
  function sqlLexComplete(raw) {
    let i=0;
    while(i<raw.length){
      if(raw.slice(i,i+2)==='--'){const j=raw.indexOf('\n',i);i=j<0?raw.length:j+1;}
      else if(raw.slice(i,i+2)==='/*'){let d=1;i+=2;while(i<raw.length&&d){if(raw.slice(i,i+2)==='/*'){d++;i+=2;}else if(raw.slice(i,i+2)==='*/'){d--;i+=2;}else i++;}if(d)throw Error();}
      else if(raw[i]==="'"||raw[i]==='"'){const q=raw[i++];let closed=false;while(i<raw.length){if(raw[i]===q){if(raw[i+1]===q){i+=2;continue;}i++;closed=true;break;}i++;}if(!closed)throw Error();}
      else if(raw[i]==='$'&&/^\$(?:[A-Za-z_][\w]*)?\$/.test(raw.slice(i))){const tag=/^\$[\w]*\$/.exec(raw.slice(i))[0],j=raw.indexOf(tag,i+tag.length);if(j<0)throw Error();i=j+tag.length;}
      else i++;
    }
  }
  function sqlScan(raw,ctx,add,unknown) {
    sqlLexComplete(raw);
    const text=lexTexts(raw).ddl, lineOf=makeLineOf(raw), ts=tokensSQL(text);
    const statements=[]; let curr=[];
    for(const t of ts){ if(t.v===';'){if(curr.length) statements.push(curr);curr=[];} else curr.push(t); }
    if(curr.length) statements.push(curr);
    const tables=new Map(), schemaGrants=new Map(); let unsupported=false;
    function name(t,pos,qualified=true) {
      const parts=[]; let i=pos;
      if(!t[i] || (!t[i].quoted&&!/^[a-z_][\w$]*$/.test(t[i].v))) throw Error();
      if(t[i].v.includes('.')) throw Error(); parts.push(t[i++].v);
      while(t[i]&&t[i].v==='.'){i++;if(!t[i])throw Error();if(t[i].v.includes('.')) throw Error(); parts.push(t[i++].v);}
      if(parts.length>2) throw Error();
      return {v:qualified?(parts.length===1?'public.'+parts[0]:parts.join('.')):parts.join('.'),end:i};
    }
    function table(n,line){ if(!tables.has(n)) tables.set(n,{rls:null,line,grants:new Map(),policies:new Map()}); return tables.get(n); }
    function roles(t,i){return t.slice(i).filter(x=>x.v!==',').map(x=>x.v);}
    function expr(t,key){
      const at=t.findIndex((x,i)=>x.v===key&&(key!=='check'||t[i-1]?.v==='with'));
      if(at<0) return undefined;
      if(t[at+1]?.v!=='(') throw Error();
      let dep=1,j=at+2;
      for(;j<t.length;j++){if(t[j].v==='(')dep++; if(t[j].v===')'&&!--dep)break;}
      if(dep)throw Error();
      return sqlExpression(raw.slice(t[at+1].i+1,t[j].i));
    }
    function parsePolicy(t,start,old) {
      const rest=t.slice(start), p=old?{...old}: {cmd:'all',roles:['public'],restrictive:false};
      const fi=rest.findIndex(x=>x.v==='for');if(fi>=0)p.cmd=rest[fi+1]?.v;
      if(!['all','select','insert','update','delete'].includes(p.cmd))throw Error();
      const ai=rest.findIndex(x=>x.v==='as');if(ai>=0){if(!['permissive','restrictive'].includes(rest[ai+1]?.v))throw Error();p.restrictive=rest[ai+1].v==='restrictive';}
      const ri=rest.findIndex(x=>x.v==='to');
      if(ri>=0){let j=ri+1,rt=[];while(j<rest.length&&!['using','with'].includes(rest[j].v)){if(rest[j].v!==',')rt.push(rest[j].v);j++;}p.roles=rt;}
      for(const k of ['using','check']){const e=expr(rest,k);if(e!==undefined)p[k]=e;}
      if(p.cmd==='insert'&&p.using!==undefined)throw Error();
      if(['select','delete'].includes(p.cmd)&&p.check!==undefined)throw Error();
      // Only recognized policy clauses are accepted. No trailing tokens.
      let z=0;const seenClauses=new Set();let clauseOrder=-1;while(z<rest.length){
        const word=rest[z++];if(word.quoted||seenClauses.has(word.v))throw Error();seenClauses.add(word.v);const order=['as','for','to','using','with'].indexOf(word.v);if(order<clauseOrder)throw Error();clauseOrder=order;if(old&&['as','for'].includes(word.v))throw Error();
        if(word.v==='as'){if(rest[z]?.quoted)throw Error();if(!['permissive','restrictive'].includes(rest[z++]?.v))throw Error();}
        else if(word.v==='for'){if(rest[z]?.quoted)throw Error();if(!['all','select','insert','update','delete'].includes(rest[z++]?.v))throw Error();}
        else if(word.v==='to'){if(!rest[z])throw Error();z++;while(rest[z]?.v===','){z+=2;if(z>rest.length)throw Error();}}
        else if(word.v==='using'||word.v==='with'){if(word.v==='with'&&rest[z++]?.v!=='check')throw Error();if(rest[z++]?.v!=='(')throw Error();let d=1;while(z<rest.length&&d){if(rest[z].v==='(')d++;if(rest[z].v===')')d--;z++;}if(d)throw Error();}
        else throw Error();
      }
      p.line=lineOf(t[0].i);p.start=t[0].i;p.end=(t.at(-1)?.i??0)+t.at(-1).v.length;
      return p;
    }
    for(const t of statements) {
      const v=t.map(x=>x.v), line=lineOf(t[0].i);
      try {
        if(t[0].quoted||t[1]?.quoted)throw Error();
        if(v[0]==='create'&&['table','unlogged','temp','temporary'].includes(v[1])) {
          if(['temp','temporary'].includes(v[1]))throw Error();
          let i=v[1]==='unlogged'?3:2;if(v[i-1]!=='table'||t[i-1].quoted)throw Error();
          const ifNot=v[i]==='if';if(ifNot){if(v.slice(i,i+3).join(' ')!=='if not exists')throw Error();i+=3;}
          const n=name(t,i);if(v[n.end]!=='(')throw Error();
          if(tables.has(n.v)){if(ifNot)continue;throw Error();}
          if(v.slice(n.end).some(x=>['check','constraint','references','default','generated','inherits','partition'].includes(x)))unsupported=true;
          if(v.at(-1)!==')')throw Error();
          const cols=t.slice(n.end+1,-1);let column=[];const cs=[];for(const x of cols){if(x.v===','){cs.push(column);column=[];}else column.push(x);}cs.push(column);
          const types=['int','integer','bigint','smallint','text','uuid','boolean','bool','json','jsonb','date','timestamp','timestamptz'];
          const reserved=new Set('all analyse analyze and any array as asc asymmetric authorization binary both case cast check collate collation column concurrently constraint create cross current_catalog current_date current_role current_schema current_time current_timestamp current_user default deferrable desc distinct do else end except false fetch for foreign freeze from full grant group having ilike in initially inner intersect into is isnull join lateral leading left like limit localtime localtimestamp natural not notnull null offset on only or order outer overlaps placing primary references returning right select session_user similar some symmetric table tablesample then to trailing true union unique user using variadic verbose when where window with'.split(' '));
          for(const c of cs){if(!c[0]||(!c[0].quoted&&(!/^[a-z_][\w$]*$/.test(c[0].v)||reserved.has(c[0].v))))throw Error();if(c.length<2||!types.includes(c[1].v)||c[1].quoted)throw Error();const tail=c.slice(2).map(x=>x.v).join(' ');if(tail&&!/^(?:not null|primary key|unique)$/.test(tail))throw Error();}
          if(ifNot)unsupported=true;
          tables.set(n.v,{rls:false,line,grants:new Map(),policies:new Map()});
        } else if(v[0]==='alter'&&v[1]==='table') {
          let i=2;if(v[i]==='if'){if(v[i+1]!=='exists')throw Error();i+=2;}if(v[i]==='only')i++;
          const n=name(t,i),o=table(n.v,line);
          const tail=v.slice(n.end).join(' ');if(!/^(?:enable|disable|force|no force) row level security$/.test(tail)||t.slice(n.end).some(x=>x.quoted))throw Error();
          if(tail.startsWith('enable')){o.rls=true;o.line=line;}
          if(tail.startsWith('disable')){o.rls=false;o.line=line;}
        } else if(v[0]==='drop'&&v[1]==='table') {
          let i=2;if(v[i]==='if'){if(v[i+1]!=='exists')throw Error();i+=2;}const n=name(t,i);tables.delete(n.v);const tail=v.slice(n.end);if(tail.length>1||tail.some(x=>x!=='cascade'&&x!=='restrict'))unsupported=true;
        } else if(['create','alter','drop'].includes(v[0])&&v[1]==='policy') {
          let i=2;if(v[i]==='if'){if(v[0]!=='drop'||v[i+1]!=='exists')throw Error();i+=2;} const pn=name(t,i,false);if(pn.v.includes('.'))throw Error();i=pn.end;if(v[i++]!=='on')throw Error();const n=name(t,i),o=table(n.v,line);
          if(v[0]==='drop'){if(n.end!==v.length)throw Error();o.policies.delete(pn.v);continue;}
          const old=o.policies.get(pn.v);
          if((v[0]==='alter'&&!old)||(v[0]==='create'&&old))throw Error();
          if(v.includes('rename'))throw Error();
          o.policies.set(pn.v,parsePolicy(t,n.end,old));
        } else if(v[0]==='grant'||v[0]==='revoke') {
          const on=v.indexOf('on'),to=v.indexOf(v[0]==='grant'?'to':'from');
          if(on<0||to<0)throw Error();
          let i=on+1;const schema=v[i]==='schema';if(schema||v[i]==='table')i++;
          const n=name(t,i,!schema);if(n.end!==to)throw Error();
          if(t.slice(1,on).some(x=>x.quoted))throw Error();
          const opTokens=v.slice(1,on);if(!(opTokens.join(' ')==='all'||opTokens.join(' ')==='all privileges'||opTokens.every((x,j)=>j%2===0?['select','insert','update','delete','usage'].includes(x):x===',')&&opTokens.length%2===1))throw Error();
          const ops=opTokens.filter(x=>x!==','&&x!=='privileges');
          if(schema&&ops.some(x=>!['usage','all'].includes(x))||!schema&&ops.includes('usage'))throw Error();
          if(ops.some(x=>!['all','select','insert','update','delete','usage'].includes(x)))throw Error();
          const roleTokens=t.slice(to+1);if(!roleTokens.length||roleTokens.length%2!==1||roleTokens.some((x,j)=>j%2===1&&x.v!==','))throw Error();
          const rs=roles(t,to+1);if(rs.some(x=>!['public','anon','authenticated','service_role'].includes(x)))throw Error();
          const map=schema?(schemaGrants.get(n.v)||new Map()):table(n.v,line).grants;
          for(const role of rs){const set=map.get(role)||new Set();for(const op of ops.includes('all')?(schema?['usage']:['select','insert','update','delete']):ops) {if(v[0]==='grant')set.add(op);else set.delete(op);}map.set(role,set);}
          if(schema)schemaGrants.set(n.v,map);
        } else if(!['begin','commit'].includes(v[0])||v.length!==1) unsupported=true;
      } catch (_) { unsupported=true; }
    }
    if(!statements.length || unsupported) {unknown('SQL-SUBSET','SQL','Contains unsupported SQL, dynamic SQL, constraints, or incomplete statements; permission inference stopped');return;}
    const complete=ctx.completeSql===true && ctx.roleModel==='builtin-only';
    const exposed=Array.isArray(ctx.exposedSchemas)?ctx.exposedSchemas:[];
    const privates=Array.isArray(ctx.privateTables)?ctx.privateTables:[];
    function grant(map,role,op){return map.get(role)?.has(op)||map.get('public')?.has(op);}
    function reachable(n,o,role,op){return exposed.includes(n.split('.')[0])&&grant(schemaGrants.get(n.split('.')[0])||new Map(),role,'usage')&&grant(o.grants,role,op);}
    function constTrue(e) {
      if(e===undefined)return true; // Missing predicate defaults to true in PG.
      if(e.type==='literal')return e.value===true;
      if(e.type==='cast'&&['bool','boolean'].includes(e.to))return constTrue(e.child);
      if(e.type==='binary'&&e.op==='='&&e.left.type==='number'&&e.right.type==='number')return e.left.value===e.right.value;
      return false;
    }
    for(const [n,o] of tables) {
      if(!complete||!exposed.length||o.rls===null) unknown('RLS-CONTEXT','SQL','Missing complete migrations, role model confirmation, exposed schemas, or final RLS state',o.line);
      else if(o.rls===false && ['anon','authenticated'].some(r=>['select','insert','update','delete'].some(op=>reachable(n,o,r,op)))) {
        if(privates.includes(n))add('RLS-OFF','found','red','SQL',o.line,'Confirmed private table has RLS disabled in final state while standard roles have access','Under the declared API-exposed schema and table grants, visitors can bypass row-level isolation to read or modify private data.','Enable RLS on this table and add policies scoped to the actual owner, tenant, and allowed operations.','Relies on your confirmation of complete ordered SQL, private-table status, built-in role model, and exposed schemas; no live database was queried.');
        else unknown('RLS-PURPOSE','SQL','RLS is disabled and standard roles have grants, but table privacy/purpose is unconfirmed',o.line);
      }
      for(const p of o.policies.values()) {
        if(p.roles.every(r=>r==='service_role'))continue;
        if(p.roles.some(r=>!['public','anon','authenticated','service_role'].includes(r))){unknown('RLS-ROLE','SQL','Custom role inheritance is not supported',p.line);continue;}
        const activeRoles=['anon','authenticated'].filter(r=>p.roles.includes('public')||p.roles.includes(r));
        const rawPolicy=lexTexts(raw.slice(p.start,p.end)).secret;
        if(/(?:->>|->)\s*'user_metadata'\s*(?:->>|->)\s*'(?:role|isAdmin|is_admin|admin)'\s*(?:::\s*\w+\s*)?=/i.test(rawPolicy))add('RLS-METADATA','review','orange','SQL',p.line,'Policy checks user-editable user_metadata for role/admin authorization','Users can edit their own user_metadata; using it to decide admin or role privileges can let them grant themselves higher access.','Move authorization roles to server-controlled data (such as app_metadata or a locked-down table), and review the full policy and claim source.','Confirms only that the policy references this field; does not prove the claim is actively used for authorization or that the policy is reachable.');
        const usingTrue=constTrue(p.using),checkTrue=constTrue(p.check===undefined?p.using:p.check);
        if(p.cmd==='select') {
          if(usingTrue) {
            const restrictive=[...o.policies.values()].some(q=>q.restrictive);
            const privateRead=complete&&privates.includes(n)&&o.rls===true&&!p.restrictive&&!restrictive&&activeRoles.some(r=>reachable(n,o,r,'select'));
            if(privateRead)add('RLS-READ','review','orange','SQL',p.line,'Private table allows unconditional SELECT by standard roles','Based on the declared private-table status and grants, anyone matching that role can read every row in the table.','Confirm whether public reads are truly intended; if the table holds private data, tighten the USING predicate to the actual owner and review exposed columns.','Relies on your confirmation of complete ordered SQL, private-table status, built-in role model, and exposed schemas; no live database or row data was inspected.');
            else add('RLS-READ','review','blue','SQL',p.line,'Unconditional SELECT policy found','Fine for intentionally public content like docs or listings; if the table contains private columns, restrict read access.','Verify the intended audience and columns returned; public read-only tables are not counted as issues.');
          }
          continue;
        }
        if(p.restrictive)continue;
        const hasWide=(['insert','all'].includes(p.cmd)&&checkTrue)||(['delete','update','all'].includes(p.cmd)&&usingTrue)||(p.cmd==='update'&&checkTrue);
        if(!hasWide)continue;
        if(!complete||!privates.includes(n)||o.rls!==true||!exposed.length){unknown('RLS-WRITE-CONTEXT','SQL','Wide write predicate found, but complete policies, private-table status, or reachability context is missing',p.line);continue;}
        const restrictive=[...o.policies.values()].some(q=>q.restrictive);
        // UPDATE/DELETE need row visibility and can depend on SELECT, constraints and data.
        // Keep only INSERT's unconditional new-row admission as an exact red subset.
        const canInsert=['insert','all'].includes(p.cmd)&&checkTrue&&activeRoles.some(r=>reachable(n,o,r,'insert'));
        if(restrictive){unknown('RLS-COMBINATION','SQL','Restrictive policy present; effective access cannot be inferred from a single permissive predicate',p.line);continue;}
        if(canInsert)add('RLS-WRITE','found','red','SQL',p.line,'Private table allows unconditional INSERT by standard roles','This rule does not check ownership on inserted rows, so a caller may be able to write records under another user\'s ID.','Constrain WITH CHECK to the real owner (e.g., auth.uid()) and review column defaults, triggers, and grants.','Proves unconditional INSERT admission from the complete pasted SQL only; UPDATE/DELETE behavior, constraints, and live writes were not tested.');
        else unknown('RLS-WRITE-SEMANTICS','SQL','Wide write predicate depends on SELECT visibility, constraints, and business semantics; needs manual review',p.line);
      }
    }
    if(!tables.size)unknown('SQL-TABLES','SQL','No inspectable final table state found in the pasted SQL');
  }

  function firebaseScan(f,add,unknown) {
    const product=f.product,source='Firebase',lineOf=makeLineOf(f.text);
    const grants=[];let complex=false;
    function record(write,condition,idx) {grants.push({write,condition,idx});}
    if(product==='rtdb') {
      // Parse JSON as an AST (duplicate members are rejected, positions retained).
      const re=/\s*("(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|[{}\[\]:,])/gy;
      let pos=0;
      function next(){re.lastIndex=pos;const m=re.exec(f.text);if(!m)throw Error();pos=re.lastIndex;return {raw:m[1],i:m.index+(m[0].length-m[1].length)};}
      let tok=next();function eat(s){if(tok.raw!==s)throw Error();tok=pos<f.text.trimEnd().length?next():{raw:'EOF'};}
      function val(depth=0){if(depth>100)throw Error();if(tok.raw==='{'){
        eat('{');const o={type:'object',members:[]},seen=new Set();
        while(tok.raw!=='}'){if(tok.raw[0]!=='"')throw Error();const key=JSON.parse(tok.raw),i=tok.i;if(seen.has(key))throw Error();seen.add(key);eat(tok.raw);eat(':');const v=val(depth+1);o.members.push({key,i,node:v});if(tok.raw!==',')break;eat(',');if(tok.raw==='}')throw Error();}eat('}');return o;
      }if(tok.raw==='[')throw Error();const v=JSON.parse(tok.raw),i=tok.i;eat(tok.raw);return {type:'value',value:v,i};}
      const root=val();if(tok.raw!=='EOF')throw Error();
      const rules=root.members?.find(m=>m.key==='rules');if(!rules||root.members.length!==1||rules.node.type!=='object')throw Error();
      function visit(o){if(o.type!=='object')throw Error();for(const m of o.members){
        if(['.write','.read'].includes(m.key)){if(m.node.type!=='value')throw Error();record(m.key==='.write',m.node.value,m.i);}
        else if(m.key==='.validate')complex=true;
        else if(m.key==='.indexOn'){if(m.node.type!=='value'||typeof m.node.value!=='string')complex=true;}
        else if(m.key.startsWith('.'))complex=true;
        else{if(!/^(?:[A-Za-z0-9_-]+|\$[A-Za-z_][\w]*)$/.test(m.key))complex=true;visit(m.node);}
      }}visit(rules.node);
    } else if(product==='firestore'||product==='storage') {
      // Dedicated Rules grammar: blocks, wildcard paths, allow lists, conditions.
      // No JavaScript/RTDB regex is used to interpret these products.
      const ts=[];let pos=0;
      while(pos<f.text.length){
        const rest=f.text.slice(pos);let m;
        if((m=/^\s+|^\/\/[^\n]*|^\/\*[\s\S]*?\*\//.exec(rest))){pos+=m[0].length;continue;}
        if((m=/^(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")|^[A-Za-z_][\w.]*|^\d+|^(?:\*\*|&&|\|\||==|!=|<=|>=)|^[{}():;,/<>*=!+-]/.exec(rest))){ts.push({v:m[0],i:pos});pos+=m[0].length;}else throw Error();
      }
      let k=0;const at=()=>ts[k]?.v;function eat(v){if(at()!==v)throw Error();return ts[k++];}
      eat('rules_version');eat('=');const version=ts[k++]?.v;if(version!=="'2'"&&version!=='"2"')throw Error();eat(';');eat('service');
      eat(product==='firestore'?'cloud.firestore':'firebase.storage');
      function block(depth=0,match=false) {
        if(depth>60)throw Error();eat('{');
        while(at()!=='}'){
          if(at()==='match'){
            k++;eat('/');const segments=[];
            while(true){
              if(at()==='{'){
                k++;const id=ts[k++]?.v;if(!/^[A-Za-z_][\w]*$/.test(id||''))throw Error();let segment='{'+id+'}';
                if(at()==='='){k++;eat('**');segment='**';}eat('}');segments.push(segment);
              }else{const id=ts[k++]?.v;if(!/^[A-Za-z_][\w.]*$/.test(id||''))throw Error();segments.push(id);}
              if(at()==='/'){k++;continue;}break;
            }
            if(at()!=='{')throw Error();
            let nextMatch;
            if(!match){
              const fixed=product==='firestore'?['databases','{}','documents']:['b','{}','o'];
              if(segments.length!==3||segments.some((x,i)=>fixed[i]==='{}'?!/^\{\w+\}$/.test(x):x!==fixed[i]))throw Error();
              nextMatch={count:0,recursive:false,bindings:new Set(segments.filter(x=>x.startsWith('{')))};
            }else{const bindings=new Set(match.bindings);for(const x of segments.filter(x=>x.startsWith('{'))){if(bindings.has(x))throw Error();bindings.add(x);}if(segments.filter(x=>x==='**').length+(match.recursive?1:0)>1)throw Error();nextMatch={count:match.count+segments.length,recursive:match.recursive||segments.includes('**'),bindings};}
            block(depth+1,nextMatch);
          }else if(at()==='allow'&&match){
            const idx=ts[k++].i,ops=[];while(at()!==':'){const op=ts[k++]?.v;if(!['read','write','get','list','create','update','delete'].includes(op))throw Error();ops.push(op);if(at()!==',')break;k++;}
            eat(':');eat('if');const c=[];let parens=0;
            while(at()!==';'){if(!at())throw Error();const v=ts[k++].v;if(v==='(')parens++;if(v===')')parens--;if(parens<0)throw Error();c.push(v);}if(parens)throw Error();eat(';');
            const validResource=match.recursive||(match.count>0&&(product==='storage'||match.count%2===0));
            if(!validResource)complex=true;
            record(ops.some(op=>['write','create','update','delete'].includes(op)),c.join(' '),idx);
          }else if(at()==='function'){
            // Unknown function bodies are skipped as syntax, never executed.
            complex=true;k++;while(at()&&at()!=='{')k++;eat('{');let d=1;while(d){if(!at())throw Error();if(at()==='{')d++;if(at()==='}')d--;k++;}
          }else throw Error();
        }eat('}');
      }block();if(k!==ts.length)throw Error();
    }else {unknown('FIREBASE-PRODUCT',source,'Select a supported product: Firestore rules v2, Storage rules v2, or Realtime Database JSON');return;}
    for(const g of grants){const c=typeof g.condition==='boolean'?String(g.condition):stripOuterParens(String(g.condition)).trim();if(!/^(?:true|false)$/.test(c)&&!(product==='rtdb'?/^now\s*<\s*\d{13}$/.test(c):/^request\.time\s*<\s*timestamp\.date\s*\(\s*\d{4}\s*,\s*\d{1,2}\s*,\s*\d{1,2}\s*\)$/.test(c)))complex=true;}
    if(complex){unknown('FIREBASE-EXPR',source,'Contains unsupported expressions, functions, paths, or validation rules; conclusions for this product stopped');return;}
    let recognized=false;
    for(const g of grants){
      const c=typeof g.condition==='boolean'?String(g.condition):stripOuterParens(String(g.condition)).trim();
      let open=c==='true',expired=false,timeRule=false;
      if(product!=='rtdb') {
        const m=/^request\.time\s*<\s*timestamp\.date\s*\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)$/.exec(c);
        if(m){const y=+m[1],mo=+m[2],d=+m[3],date=new Date(Date.UTC(y,mo-1,d));if(date.getUTCFullYear()!==y||date.getUTCMonth()!==mo-1||date.getUTCDate()!==d)throw Error();timeRule=true;open=Date.now()<date.getTime();expired=!open;}
      } else {
        const m=/^now\s*<\s*(\d{13})$/.exec(c);if(m){timeRule=true;open=Date.now()<Number(m[1]);expired=!open;}
      }
      if(c==='false'){recognized=true;continue;}
      if(expired){recognized=true;add('FIREBASE-EXPIRED','review','blue',source,lineOf(g.idx),'Test-mode expiration date has passed; this time window no longer allows writes','Not evidence of currently open writes, though legitimate users may also be blocked by this expired rule.','Replace with production rules scoped to actual ownership, and audit other matching paths.','Evaluates only this timestamp condition against your local browser clock; sibling allow rules still combine with OR.');continue;}
      if(!open){complex=true;continue;}
      recognized=true;
      if(!g.write){add('FIREBASE-READ','review','blue',source,lineOf(g.idx),'Rule explicitly allows unconditional read access','Fine for intentionally public assets; if this path contains private user data, restrict reads.','Confirm only public data lives under this path; public read-only rules are not counted as issues.');continue;}
      if(product==='rtdb'&&complex){unknown('FIREBASE-VALIDATE',source,'RTDB rules include .validate or complex constraints; effective write scope cannot be determined',lineOf(g.idx));continue;}
      if(f.privateData!==true || f.complete!==true){unknown('FIREBASE-CONTEXT',source,'Open write condition found, but complete-file or private-data confirmation is missing',lineOf(g.idx));continue;}
      add('FIREBASE-WRITE','found','red',source,lineOf(g.idx),timeRule?'Unexpired test-mode rule allows anonymous writes':'Matching rule path allows unconditional writes',
        'Under the confirmed private-data scope, anyone on the internet could tamper with data or abuse your storage as a free public bucket.','Remove unconditional writes, enforce verified identity and resource ownership, and verify in the Firebase Rules Simulator.',
        product==='rtdb'?'In RTDB, parent write grants cascade downward and a child false cannot revoke them; live deployment is not verified.':'Matching allow rules combine with OR — another false rule does not cancel out a true; live deployment is not verified.');
    }
    if(complex || !recognized)unknown('FIREBASE-EXPR',source,'Some expressions, functions, or validation rules are outside supported syntax; affected paths were not judged');
  }

  function jsScan(p,all,ctx,add,unknown) {
    const {f,source,ast}=p,isTest=testFile(f.name)||f.environment==='test',client=f.client===true||ast.body.some(n=>n.directive==='use client');
    if(isTest)return;
    const nodes=[],calls=[],anc=new Map();walk(ast,(n,a)=>{nodes.push(n);anc.set(n,a);if(n.type==='CallExpression')calls.push(n);});
    // Only runtime literals: exclude comments, documentation strings, imports, directives.
    nodes.filter(n=>n.type==='Literal'&&typeof n.value==='string').forEach(n=>{
      const a=anc.get(n),parent=a.at(-1);let name='';
      if(parent?.type==='VariableDeclarator'&&parent.init===n)name=path(parent.id);
      else if(parent?.type==='Property'&&parent.value===n)name=parent.key.name||parent.key.value;
      else if(parent?.type==='AssignmentExpression'&&parent.right===n)name=path(parent.left).split('.').at(-1);
      else if(parent?.type==='CallExpression'&&parent.arguments.includes(n))name='';
      else return;
      secretFinding(n.value,name,source,n.loc.start.line,client,add);
    });
    const route=client?'':(f.route||routeFromName(f.name)||'');
    const functions=nodes.filter(n=>['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression'].includes(n.type));
    function fnCalls(fn){return calls.filter(n=>anc.get(n).includes(fn)&&!anc.get(n).some(a=>a!==fn&&functions.includes(a)&&anc.get(a).includes(fn)));}
    function fnFor(n){return anc.get(n).filter(a=>functions.includes(a)).at(-1);}
    const authNames=/^(?:requireAuth|withAuth|auth|authenticate|verifyToken|verifyJWT|getUser|getClaims)$/;
    const hasAuth=cs=>cs.some(n=>authNames.test(path(n.callee).split('.').at(-1)));
    const routeFns=new Set();
    for(const n of ast.body){
      if(n.type==='ExportNamedDeclaration'){
        const d=n.declaration;if(d?.type==='FunctionDeclaration'&&/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(d.id.name))routeFns.add(d);
        if(d?.type==='VariableDeclaration')for(const x of d.declarations)if(/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(x.id.name)&&functions.includes(x.init))routeFns.add(x.init);
      }
      if(n.type==='ExportDefaultDeclaration'&&functions.includes(n.declaration))routeFns.add(n.declaration);
    }
    // Express route callbacks are per-handler; never splice evidence from another handler.
    const expressRoutes=[];
    for(const c of calls) if(/\.(?:get|post|put|patch|delete|all)$/.test(path(c.callee))&&typeof value(c.arguments[0])==='string'&&c.arguments[0].value.startsWith('/api/')) {
      const handlers=c.arguments.slice(1),fn=handlers.at(-1);
      if(functions.includes(fn))expressRoutes.push({route:c.arguments[0].value,fn,pre:handlers.slice(0,-1).some(n=>authNames.test(path(n)))});
    }
    function middleware(r) {
      // Presence of a project middleware is an exemption from absence-based alerts,
      // never a claim that it authenticates. Unknown matchers stop this inference.
      const ms=all.filter(x=>/(?:^|[/\\])middleware\.[cm]?js$/.test(x.f.name||''));
      if(!ms.length)return false;
      for(const m of ms){
        const props=[];walk(m.ast,n=>{if(n.type==='Property'&&(n.key.name||n.key.value)==='matcher')props.push(n.value);});
        if(!props.length)return true;
        for(const n of props){const patterns=n.type==='ArrayExpression'?n.elements:[n];for(const x of patterns){const s=value(x);if(typeof s!=='string')return true;if(s==='/:path*'||s==='/(.*)'||s===r||s==='/api/:path*')return true;if(!/^\/[\w/-]+$/.test(s))return true;}}
      }return false;
    }
    function routeCheck(r,fn,pre=false) {
      const cs=fnCalls(fn),localAuth=pre||hasAuth(cs),exempt=middleware(r);
      const webhook=/webhook/i.test(r)||f.purpose==='webhook';
      if(webhook){
        const official=cs.some(c=>/(?:^|\.)(?:constructEvent|constructEventAsync|unmarshal|verifyAndUnmarshal|validateEvent)$/.test(path(c.callee)));
        const custom=cs.some(c=>/(?:verify.*(?:signature|webhook)|(?:signature|webhook).*verify|timingSafeEqual)/i.test(path(c.callee)));
        if(!official&&!custom)add('WEBHOOK-SIGNATURE','review','orange',source,fn.loc.start.line,'No supported webhook signature verification call found in handler','If verification is not handled upstream either, forged webhook requests could grant paid plans or alter orders.','Verify the raw request body signature, reject invalid signatures, and enforce idempotency and replay windows.','Recognizes listed SDK verification method names only; an upstream gateway or wrapper function may verify signatures, so absence here does not prove missing protection.');
        else if(custom)unknown('WEBHOOK-CUSTOM',source,'Custom signature verification call detected; review its implementation manually',fn.loc.start.line);
      }else if(!localAuth&&!exempt){
        if(f.publicEndpoint===true)unknown('API-PUBLIC',source,'Endpoint is marked intentionally public; review rate limits, quotas, and data sensitivity manually',fn.loc.start.line);
        else add('API-AUTH','review','orange',source,fn.loc.start.line,'No supported auth check call found inside this API handler','If no middleware or gateway guards this route either, unauthenticated callers could invoke backend actions or burn through paid quotas.','Include your project middleware, gateway config, or auth wrapper, and verify both identity and object ownership.','Covers explicitly exported JS route handlers and Express /api/ callbacks only; a missing local call does not prove the route is unprotected.');
      }
      if(exempt&&!localAuth)unknown('API-MIDDLEWARE',source,'Project middleware may cover this route; missing-auth alert exempted',fn.loc.start.line);
      if(/\/api\/(?:test|migrate|seed|fix-db)(?:\/|$)/.test(r)&&!localAuth&&!exempt)add('DEBUG-ENDPOINT','review','orange',source,fn.loc.start.line,'Possible leftover debug or one-off maintenance endpoint','If still reachable in production without auth, anyone could trigger migrations, seed data, or hit debug routes.','Confirm whether this route is needed in production; remove one-off endpoints or require trusted auth and authorization.','Flags only the combination of route path and no visible auth check; live deployment, gateway rules, and operational purpose are unverified.');
    }
    if(route){if(!routeFns.size)unknown('API-SYNTAX',source,'No supported API handler pattern parsed; review wrapped handlers or custom routing manually');for(const fn of routeFns)routeCheck(route,fn);}
    for(const r of expressRoutes)routeCheck(r.route,r.fn,r.pre);
    if(!client)for(const c of calls){
      if(/\.auth\.getSession$/.test(path(c.callee))){
        const fn=fnFor(c);if(!fn)continue;const cs=fnCalls(fn);if(hasAuth(cs))continue;
        // Require a direct destructured session to flow into an authorization if.
        const decl=anc.get(c).findLast(n=>n.type==='VariableDeclarator');let sessionName='';
        if(decl?.id.type==='ObjectPattern'){
          const d=decl.id.properties.find(x=>(x.key?.name||x.key?.value)==='data');
          const s=d?.value?.properties?.find(x=>(x.key?.name||x.key?.value)==='session');sessionName=s?.value?.name||'';
        }
        const branch=nodes.some(n=>n.type==='IfStatement'&&anc.get(n).includes(fn)&&containsIdentifier(n.test,sessionName));
        const sensitive=cs.some(n=>/^(?:save|insert|update|delete|upsert|remove|create|query)$/.test(n.callee.property?.name||path(n.callee).split('.').at(-1))&&n.arguments.some(a=>containsIdentifier(a,sessionName)));
        const use=branch&&sensitive;
        if(sessionName&&use)add('SESSION-AUTH','review','orange',source,c.loc.start.line,'Server code uses getSession() result to gate an auth branch','Trusting unverified session data from cookies or cache on the server can allow forged identity data to influence authorization.','Check your SDK guidance and use server-verified identity checks (such as getUser() or verified JWT claims) before checking object ownership.','Covers only the narrow pattern where destructured data.session flows directly into an if branch and write/query call; exempted when a verified auth call is present.');
      }
    }
    // This dataflow is intentionally disabled: body.userId/role alone proves nothing.
    // Keep an unknown coverage item when encountered, without a risk-count increase.
    if(!client&&nodes.some(n=>n.type==='MemberExpression'&&/^(?:req|request)\.body\.(?:userId|role|isAdmin)$/.test(path(n))))unknown('BODY-IDENTITY',source,'Dataflow for client-supplied identity fields (req.body.userId/role/isAdmin) is not tracked statically; verify server-side ownership checks manually');
    for(const c of calls){
      // Verified only for a direct imported cors() with one flat literal object,
      // unconditional top-level registration, production explicitly confirmed.
      const imp=ast.body.find(n=>n.type==='ImportDeclaration'&&value(n.source)==='cors'&&n.specifiers.some(s=>s.type==='ImportDefaultSpecifier'&&s.local.name===path(c.callee)));
      if(!imp||c.arguments.length!==1||c.arguments[0].type!=='ObjectExpression')continue;
      const ps=c.arguments[0].properties;
      if(ps.some(n=>n.type!=='Property'||n.computed||n.kind!=='init'))continue;
      if(new Set(ps.map(n=>n.key.name||n.key.value)).size!==ps.length)continue;
      const get=k=>ps.find(n=>(n.key.name||n.key.value)===k)?.value;
      if(value(get('origin'))!==true||value(get('credentials'))!==true)continue;
      if(anc.get(c).some(n=>['IfStatement','ConditionalExpression','LogicalExpression','FunctionDeclaration','FunctionExpression','ArrowFunctionExpression','TryStatement'].includes(n.type))){unknown('CORS-CONTEXT',source,'Permissive CORS config is inside a conditional branch or function; production activation unconfirmed',c.loc.start.line);continue;}
      const parent=anc.get(c).at(-1);
      const expressImport=ast.body.find(n=>n.type==='ImportDeclaration'&&value(n.source)==='express');
      const expressName=expressImport?.specifiers.find(n=>n.type==='ImportDefaultSpecifier')?.local.name;
      const apps=nodes.filter(n=>n.type==='VariableDeclarator'&&anc.get(n).at(-1)?.kind==='const'&&n.init?.type==='CallExpression'&&path(n.init.callee)===expressName).map(n=>path(n.id));
      const mutated=nodes.some(n=>n.type==='AssignmentExpression'&&[expressName,path(c.callee),...apps].some(a=>a&&(path(n.left)===a||path(n.left).startsWith(a+'.')))||n.type==='UpdateExpression'&&apps.includes(path(n.argument)));
      if(mutated){unknown('CORS-CONTEXT',source,'Related binding or method is reassigned; runtime behavior cannot be determined statically',c.loc.start.line);continue;}
      const registration=parent?.type==='CallExpression'&&ast.body.some(n=>n.type==='ExpressionStatement'&&n.expression===parent)&&apps.some(a=>path(parent.callee)===a+'.use')&&!calls.some(n=>n!==c&&n!==parent&&n.arguments.some(a=>apps.includes(path(a))));
      if(registration&&f.environment==='production'&&f.corsVersion==='2.8.5')add('CORS-REFLECT','found','red',source,c.loc.start.line,'Production Express CORS middleware reflects any Origin with credentials enabled','Untrusted websites could make credentialed cross-origin requests on behalf of signed-in users and read the responses.','Replace origin: true with an explicit origin allowlist, and review which endpoints actually need credentials.','Proves only the static cors 2.8.5 configuration as declared; does not confirm sensitive response data is readable and sent no requests.');
      else unknown('CORS-CONTEXT',source,'Permissive CORS config found, but supported version, production environment, or registration proof is missing',c.loc.start.line);
    }
    const passLiterals=nodes.filter(n=>n.type==='Literal'&&typeof n.value==='string'&&/^(?:admin|password123|letmein|123456|demo123)$/i.test(n.value));
    for(const n of passLiterals){const parent=anc.get(n).at(-1);const credential=parent?.type==='Property'&&/^(?:password|passwd)$/.test(parent.key.name||parent.key.value)||parent?.type==='BinaryExpression'&&['===','=='].includes(parent.operator)&&/password|passwd/.test(path(parent.left)||path(parent.right));
      let accepted=parent?.type==='Property';
      if(parent?.type==='BinaryExpression'){const guard=anc.get(parent).findLast(a=>a.type==='IfStatement'&&a.test===parent);const body=guard?.consequent;accepted=body?.type==='ReturnStatement'&&value(body.argument)===true||body?.type==='BlockStatement'&&body.body.some(a=>a.type==='ReturnStatement'&&value(a.argument)===true);}
      if(credential&&accepted)add('DEMO-ACCOUNT','review','orange',source,n.loc.start.line,'Hardcoded demo or weak password literal detected','If this credential ships in production login flows, anyone who knows or guesses it can sign straight in.','Remove demo shortcuts from production, disable demo accounts, and keep test fixtures strictly in isolated test environments.','Matches only a small weak-password list in password fields or accept comparisons; does not attempt login or prove the account is active.');}
  }
  function containsIdentifier(n,name){if(!name)return false;let yes=false;walk(n,x=>{if(x.type==='Identifier'&&x.name===name)yes=true;});return yes;}
  function routeFromName(name='') {
    const s=name.replace(/\\/g,'/');let m=/(?:^|\/)app(\/api\/.*?)\/route\.[cm]?js$/.exec(s);if(m)return m[1];
    m=/(?:^|\/)pages(\/api\/.*?)\.[cm]?js$/.exec(s);return m?m[1].replace(/\/index$/,''):'';
  }
  function headerScan(raw,add,unknown) {
    // Parse only the final HTTP response block. Intermediate redirect heads are
    // discarded; folded/malformed lines or duplicate security headers are unknown.
    const blocks=raw.trim().split(/\r?\n\s*\r?\n/),last=blocks.at(-1),h=new Map();let valid=0;
    const lines=last.split(/\r?\n/);let start=0;if(/^HTTP\/\S+\s+\d{3}(?:\s|$)/i.test(lines[0]))start=1;
    for(let i=start;i<lines.length;i++){
      const m=/^([A-Za-z0-9-]+):[ \t]*(.*)$/.exec(lines[i]);if(!m){unknown('HEADER-PARSE','Headers','Not a clean raw HTTP header block (may include a response body or folded/malformed lines)');return;}
      const k=m[1].toLowerCase();if(h.has(k)&&['content-security-policy','x-frame-options','strict-transport-security','x-content-type-options'].includes(k)){unknown('HEADER-DUPLICATE','Headers','Duplicate security headers found; combined browser behavior is not interpreted statically');return;}
      h.set(k,m[2].trim());valid++;
    }
    if(!valid){unknown('HEADER-PARSE','Headers','No valid HTTP response headers parsed');return;}
    const csp=h.get('content-security-policy')||'',xfo=h.get('x-frame-options')||'';
    const frame=/(?:^|;)\s*frame-ancestors\s+[^;]+/.test(csp)||/^(?:DENY|SAMEORIGIN)$/i.test(xfo);
    const suggestions=[];if(!frame)suggestions.push(['HEAD-FRAME','No clickjacking protection header observed','A malicious site could embed sensitive actions in an iframe to trick users into clicking them.','Set CSP frame-ancestors or X-Frame-Options based on your embedding needs (either valid directive is enough).']);
    if(!/^nosniff$/i.test(h.get('x-content-type-options')||''))suggestions.push(['HEAD-SNIFF','No X-Content-Type-Options: nosniff header observed','Browsers lack an extra MIME-sniffing safeguard; this alone does not prove script injection.','Serve X-Content-Type-Options: nosniff alongside accurate Content-Type headers.']);
    if(!/\bmax-age\s*=\s*[1-9]\d*\b/i.test(h.get('strict-transport-security')||''))suggestions.push(['HEAD-HSTS','No valid HSTS header observed','Browsers may not remember to force HTTPS on future visits; this alone does not prove a certificate or redirect flaw.','Once HTTPS and subdomains are confirmed ready, add Strict-Transport-Security with an appropriate max-age.']);
    for(const [code,title,impact,fix]of suggestions)add(code,'review','blue','Headers',1,title,impact,fix,'Based on a single pasted response only; CDN, path, and status code can change headers. Hardening tips are not counted as issues; TLS and certificates were not checked.');
  }
  function toMarkdown(r) {
    function covState(c) {
      const fs = r.findings.filter(f => c.group === 'Code' ? (f.source === 'Code' || f.source.startsWith('Code file ')) : f.source === c.group);
      const hasRisk = fs.some(f => f.level === 'red' || f.level === 'orange' || f.state === STATES.unknown);
      const blues = fs.filter(f => f.level === 'blue').length;
      if (!hasRisk && blues) return 'No red/orange issues observed (' + blues + ' hardening ' + (blues === 1 ? 'tip' : 'tips') + ')';
      return c.state;
    }
    return '# Bremta Security Self-Check v2\n\nScoped strictly to the pasted input.\n\n'+r.coverage.map(c=>'- '+c.group+': '+covState(c)).join('\n')+'\n\n'+r.findings.map(f=>
      '- ['+(f.level||'unrated')+'] '+(f.level==='blue'?'Hardening tip (not counted)':f.state)+' · '+f.code+' · '+f.source+' L'+f.line+'\n  '+f.title+'\n  Evidence: '+f.evidence+'\n  Impact: '+f.impact+'\n  Fix direction: '+f.fix+'\n  Boundary: '+f.boundary).join('\n\n')+'\n';
  }
  return Object.freeze({scan,toMarkdown,states:STATES,version:VERSION});
}));
