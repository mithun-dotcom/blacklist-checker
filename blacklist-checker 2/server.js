'use strict';
/*
 * ArrowInBox Blacklist Checker — standalone server
 * Runs IP-based DNSBL and domain/URI blacklist lookups from THIS server's resolver.
 *
 * Response decoding (per RFC 5782 + list docs):
 *   - NXDOMAIN / no record            -> clean
 *   - 127.0.0.1                       -> query REFUSED (SURBL/URIBL block sentinel) -> "unavailable"
 *   - 127.255.255.x                   -> query REFUSED (Spamhaus open-resolver block) -> "unavailable"
 *   - any other 127.x.x.x             -> LISTED  (e.g. SURBL 127.0.0.64 = ABUSE)
 *
 * Spamhaus lists refuse cloud/public resolvers. Set SPAMHAUS_DQS_KEY (free key from
 * spamhaus.com Data Query Service) to query the DQS zones, which work from any resolver.
 *
 * DNSBL zone list based on the open-source project github.com/molodsom/rbl-check.
 */
const http = require('http');
const fs   = require('fs');
const path = require('path');
const dns  = require('dns');
const dnsp = dns.promises;

const PORT = process.env.PORT || 3000;
const DQS  = (process.env.SPAMHAUS_DQS_KEY || '').trim();

if (process.env.RESOLVERS) {
  dns.setServers(process.env.RESOLVERS.split(',').map(s => s.trim()).filter(Boolean));
}

// Spamhaus public zone -> Data Query Service zone (used only when SPAMHAUS_DQS_KEY is set)
const SPAMHAUS_DQ = {
  'zen.spamhaus.org': 'zen.dq.spamhaus.net',
  'sbl.spamhaus.org': 'sbl.dq.spamhaus.net',
  'xbl.spamhaus.org': 'xbl.dq.spamhaus.net',
  'pbl.spamhaus.org': 'pbl.dq.spamhaus.net',
  'dbl.spamhaus.org': 'dbl.dq.spamhaus.net'
};

const IP_LISTS = [
  { z: 'zen.spamhaus.org',        n: 'Spamhaus ZEN' },
  { z: 'sbl.spamhaus.org',        n: 'Spamhaus SBL' },
  { z: 'xbl.spamhaus.org',        n: 'Spamhaus XBL' },
  { z: 'pbl.spamhaus.org',        n: 'Spamhaus PBL' },
  { z: 'b.barracudacentral.org',  n: 'Barracuda' },
  { z: 'bl.spamcop.net',          n: 'SpamCop' },
  { z: 'dnsbl.sorbs.net',         n: 'SORBS' },
  { z: 'spam.dnsbl.sorbs.net',    n: 'SORBS Spam' },
  { z: 'psbl.surriel.com',        n: 'PSBL' },
  { z: 'ix.dnsbl.manitu.net',     n: 'NiX Spam' },
  { z: 'dnsbl-1.uceprotect.net',  n: 'UCEPROTECT L1' },
  { z: 'dnsbl.dronebl.org',       n: 'DroneBL' },
  { z: 'db.wpbl.info',            n: 'WPBL' },
  { z: 'all.s5h.net',             n: 's5h.net' },
  { z: 'spam.dnsbl.anonmails.de', n: 'Anonmails' },
  { z: 'z.mailspike.net',         n: 'Mailspike' },
  { z: 'spam.spamrats.com',       n: 'SpamRats' },
  { z: 'ips.backscatterer.org',   n: 'Backscatterer' }
];
const DOMAIN_LISTS = [
  { z: 'multi.surbl.org',             n: 'SURBL multi' },
  { z: 'dbl.spamhaus.org',            n: 'Spamhaus DBL' },
  { z: 'fresh.spameatingmonkey.net',  n: 'SEM FRESH' },
  { z: 'uribl.spameatingmonkey.net',  n: 'SEM URI' },
  { z: 'urired.spameatingmonkey.net', n: 'SEM URIRED' },
  { z: 'rhsbl.sorbs.net',             n: 'SORBS RHSBL' },
  { z: 'multi.uribl.com',             n: 'URIBL multi' },
  { z: 'dbl.nordspam.com',            n: 'NordSpam DBL' }
];

function isIPv4(s) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every(o => +o >= 0 && +o <= 255);
}
function isRefusal(d) {
  return /^127\.255\.255\./.test(d) || d === '127.0.0.1';
}
function classify(ips) {
  if (!ips || !ips.length) return 'clean';               // NXDOMAIN = not listed
  if (ips.every(isRefusal)) return 'error';              // resolver blocked by the list
  if (ips.some(d => /^127\./.test(d) && !isRefusal(d))) return 'listed';
  return 'error';
}
function withTimeout(p, ms) {
  return Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms))]);
}
async function lookup(name) {
  try {
    const ips = await withTimeout(dnsp.resolve4(name), 5000);
    return { status: classify(ips), code: (ips || []).join('+') };
  } catch (e) {
    if (e && (e.code === 'ENOTFOUND' || e.code === 'ENODATA')) return { status: 'clean', code: '' };
    return { status: 'error', code: (e && e.code) || 'error' };
  }
}
async function resolveHostIP(host) {
  if (isIPv4(host)) return host;
  try {
    const ips = await withTimeout(dnsp.resolve4(host), 5000);
    return (ips && ips.length) ? ips[0] : '';
  } catch (e) { return ''; }
}
function ipQueryName(revIp, zone) {
  if (DQS && SPAMHAUS_DQ[zone]) return revIp + '.' + DQS + '.' + SPAMHAUS_DQ[zone];
  return revIp + '.' + zone;
}
function domainQueryName(host, zone) {
  if (DQS && SPAMHAUS_DQ[zone]) return host + '.' + DQS + '.' + SPAMHAUS_DQ[zone];
  return host + '.' + zone;
}
async function checkHost(raw) {
  let host = String(raw || '').trim()
    .replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/^www\./i, '').trim();
  if (!host || !/^[a-z0-9.\-]+$/i.test(host)) return { error: 'invalid host' };
  const inputIsIp = isIPv4(host);
  const ip = await resolveHostIP(host);
  if (!ip) return { host, ip: '', results: [] };
  const rev = ip.split('.').reverse().join('.');
  const jobs = IP_LISTS.map(l => lookup(ipQueryName(rev, l.z)).then(r => ({ n: l.n, status: r.status, code: r.code })));
  if (!inputIsIp) {
    DOMAIN_LISTS.forEach(l => jobs.push(lookup(domainQueryName(host, l.z)).then(r => ({ n: l.n, status: r.status, code: r.code }))));
  }
  const results = await Promise.all(jobs);
  return { host, ip, dqs: !!DQS, results };
}

const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript',
  '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.json': 'application/json' };

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  if (u.pathname === '/api/blacklist') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*'); // restrict to your domain in production
    try {
      const data = await checkHost(u.searchParams.get('host'));
      res.end(JSON.stringify(data));
    } catch (e) {
      res.statusCode = 500; res.end(JSON.stringify({ error: 'server error' }));
    }
    return;
  }
  let fp = u.pathname === '/' ? '/index.html' : u.pathname;
  fp = path.normalize(fp).replace(/^(\.\.[\/\\])+/, '');
  const full = path.join(__dirname, 'public', fp);
  fs.readFile(full, (err, buf) => {
    if (err) { res.statusCode = 404; res.end('Not found'); return; }
    res.setHeader('Content-Type', MIME[path.extname(full)] || 'application/octet-stream');
    res.end(buf);
  });
});
server.listen(PORT, () => console.log('Blacklist checker running on port ' + PORT + (DQS ? ' (Spamhaus DQS enabled)' : '')));
