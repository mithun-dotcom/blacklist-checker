<?php
declare(strict_types=1);
/*
 * ArrowInBox Blacklist Checker — PHP backend
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
 * Lookups use a small built-in UDP DNS client so all queries run in parallel with a
 * hard timeout (PHP's own DNS functions are sequential and can't pick a resolver).
 *
 * DNSBL zone list based on the open-source project github.com/molodsom/rbl-check.
 */

const LOOKUP_TIMEOUT = 5.0;   // seconds, whole batch
const RETRY_AFTER    = 1.5;   // seconds before re-sending an unanswered query to the next resolver

// Spamhaus public zone -> Data Query Service zone (used only when SPAMHAUS_DQS_KEY is set)
const SPAMHAUS_DQ = [
  'zen.spamhaus.org' => 'zen.dq.spamhaus.net',
  'sbl.spamhaus.org' => 'sbl.dq.spamhaus.net',
  'xbl.spamhaus.org' => 'xbl.dq.spamhaus.net',
  'pbl.spamhaus.org' => 'pbl.dq.spamhaus.net',
  'dbl.spamhaus.org' => 'dbl.dq.spamhaus.net',
];

const IP_LISTS = [
  ['z' => 'zen.spamhaus.org',        'n' => 'Spamhaus ZEN'],
  ['z' => 'sbl.spamhaus.org',        'n' => 'Spamhaus SBL'],
  ['z' => 'xbl.spamhaus.org',        'n' => 'Spamhaus XBL'],
  ['z' => 'pbl.spamhaus.org',        'n' => 'Spamhaus PBL'],
  ['z' => 'b.barracudacentral.org',  'n' => 'Barracuda'],
  ['z' => 'bl.spamcop.net',          'n' => 'SpamCop'],
  ['z' => 'dnsbl.sorbs.net',         'n' => 'SORBS'],
  ['z' => 'spam.dnsbl.sorbs.net',    'n' => 'SORBS Spam'],
  ['z' => 'psbl.surriel.com',        'n' => 'PSBL'],
  ['z' => 'ix.dnsbl.manitu.net',     'n' => 'NiX Spam'],
  ['z' => 'dnsbl-1.uceprotect.net',  'n' => 'UCEPROTECT L1'],
  ['z' => 'dnsbl.dronebl.org',       'n' => 'DroneBL'],
  ['z' => 'db.wpbl.info',            'n' => 'WPBL'],
  ['z' => 'all.s5h.net',             'n' => 's5h.net'],
  ['z' => 'spam.dnsbl.anonmails.de', 'n' => 'Anonmails'],
  ['z' => 'z.mailspike.net',         'n' => 'Mailspike'],
  ['z' => 'spam.spamrats.com',       'n' => 'SpamRats'],
  ['z' => 'ips.backscatterer.org',   'n' => 'Backscatterer'],
];
const DOMAIN_LISTS = [
  ['z' => 'multi.surbl.org',             'n' => 'SURBL multi'],
  ['z' => 'dbl.spamhaus.org',            'n' => 'Spamhaus DBL'],
  ['z' => 'fresh.spameatingmonkey.net',  'n' => 'SEM FRESH'],
  ['z' => 'uribl.spameatingmonkey.net',  'n' => 'SEM URI'],
  ['z' => 'urired.spameatingmonkey.net', 'n' => 'SEM URIRED'],
  ['z' => 'rhsbl.sorbs.net',             'n' => 'SORBS RHSBL'],
  ['z' => 'multi.uribl.com',             'n' => 'URIBL multi'],
  ['z' => 'dbl.nordspam.com',            'n' => 'NordSpam DBL'],
];

function dqs_key(): string {
  return trim((string) getenv('SPAMHAUS_DQS_KEY'));
}

// RESOLVERS env var if set, otherwise the system resolvers from /etc/resolv.conf.
function resolvers(): array {
  $env = trim((string) getenv('RESOLVERS'));
  $list = $env !== '' ? array_map('trim', explode(',', $env)) : [];
  if (!$list && is_readable('/etc/resolv.conf')) {
    foreach (file('/etc/resolv.conf', FILE_IGNORE_NEW_LINES) as $line) {
      if (preg_match('/^\s*nameserver\s+(\S+)/', $line, $m)) $list[] = $m[1];
    }
  }
  $list = array_values(array_filter($list, fn($s) => filter_var($s, FILTER_VALIDATE_IP)));
  return $list ?: ['1.1.1.1', '8.8.8.8'];
}

function is_ipv4(string $s): bool {
  return (bool) preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $s)
    && count(array_filter(explode('.', $s), fn($o) => (int) $o > 255)) === 0;
}
function is_refusal(string $d): bool {
  return str_starts_with($d, '127.255.255.') || $d === '127.0.0.1';
}
function classify(array $ips): string {
  if (!$ips) return 'clean';                                   // NXDOMAIN = not listed
  if (count(array_filter($ips, 'is_refusal')) === count($ips)) return 'error';  // resolver blocked by the list
  foreach ($ips as $d) if (str_starts_with($d, '127.') && !is_refusal($d)) return 'listed';
  return 'error';
}

/* ---------- minimal UDP DNS client (A records only) ---------- */

function dns_build_query(int $id, string $name): string {
  $q = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0);               // RD=1, one question
  foreach (explode('.', rtrim($name, '.')) as $label) {
    $q .= chr(strlen($label)) . $label;
  }
  return $q . "\0" . pack('nn', 1, 1);                          // QTYPE=A, QCLASS=IN
}

// Advance past a (possibly compressed) domain name; returns new offset or -1.
function dns_skip_name(string $buf, int $off): int {
  $len = strlen($buf);
  while ($off < $len) {
    $c = ord($buf[$off]);
    if ($c === 0) return $off + 1;
    if (($c & 0xC0) === 0xC0) return $off + 2;
    $off += $c + 1;
  }
  return -1;
}

// Returns ['rcode' => int, 'ips' => string[]] or null if the packet is malformed / not ours.
function dns_parse_response(string $buf, int $id): ?array {
  if (strlen($buf) < 12) return null;
  $h = unpack('nid/nflags/nqd/nan', substr($buf, 0, 8));
  if ($h['id'] !== $id || !($h['flags'] & 0x8000)) return null;
  $off = 12;
  for ($i = 0; $i < $h['qd']; $i++) {
    $off = dns_skip_name($buf, $off);
    if ($off < 0) return null;
    $off += 4;
  }
  $ips = [];
  for ($i = 0; $i < $h['an']; $i++) {
    $off = dns_skip_name($buf, $off);
    if ($off < 0 || $off + 10 > strlen($buf)) return null;
    $rr = unpack('ntype/nclass/Nttl/nlen', substr($buf, $off, 10));
    $off += 10;
    if ($rr['type'] === 1 && $rr['len'] === 4) $ips[] = inet_ntop(substr($buf, $off, 4));
    $off += $rr['len'];
  }
  return ['rcode' => $h['flags'] & 0x0F, 'ips' => $ips];
}

/**
 * Resolve many names' A records in parallel.
 * Returns name => ['ok' => bool, 'ips' => string[], 'code' => string]
 *   ok=true  : got an answer (ips may be empty for NXDOMAIN / no data)
 *   ok=false : SERVFAIL / REFUSED / timeout, with an error code
 */
function resolve_many(array $names): array {
  $servers = resolvers();
  $out = [];
  $pending = [];
  $start = microtime(true);

  $send = function (array &$p) use ($servers) {
    $srv = $servers[$p['try'] % count($servers)];
    $addr = strpos($srv, ':') !== false ? "[$srv]" : $srv;
    if ($p['sock']) fclose($p['sock']);
    $p['sock'] = @stream_socket_client("udp://$addr:53", $errno, $errstr, 1);
    if ($p['sock']) {
      stream_set_blocking($p['sock'], false);
      @fwrite($p['sock'], dns_build_query($p['id'], $p['name']));
    }
    $p['sent'] = microtime(true);
    $p['try']++;
  };

  foreach (array_unique($names) as $name) {
    $p = ['name' => $name, 'id' => random_int(0, 0xFFFF), 'sock' => null, 'try' => 0, 'sent' => 0.0];
    $send($p);
    $pending[$name] = $p;
  }

  while ($pending) {
    $now = microtime(true);
    if ($now - $start >= LOOKUP_TIMEOUT) break;
    foreach ($pending as $name => &$p) {
      if (!$p['sock'] || $now - $p['sent'] >= RETRY_AFTER) $send($p);
    }
    unset($p);

    $read = array_values(array_filter(array_map(fn($p) => $p['sock'], $pending)));
    if (!$read) { usleep(50000); continue; }
    $w = $e = null;
    if (@stream_select($read, $w, $e, 0, 100000) < 1) continue;

    foreach ($pending as $name => $p) {
      if (!in_array($p['sock'], $read, true)) continue;
      $buf = @fread($p['sock'], 4096);
      $r = $buf ? dns_parse_response($buf, $p['id']) : null;
      if (!$r) continue;
      fclose($p['sock']);
      unset($pending[$name]);
      if ($r['rcode'] === 0 || $r['rcode'] === 3) {           // NOERROR / NXDOMAIN
        $out[$name] = ['ok' => true, 'ips' => $r['ips'], 'code' => ''];
      } else {
        $codes = [1 => 'EFORMERR', 2 => 'ESERVFAIL', 4 => 'ENOTIMP', 5 => 'EREFUSED'];
        $out[$name] = ['ok' => false, 'ips' => [], 'code' => $codes[$r['rcode']] ?? 'error'];
      }
    }
  }

  foreach ($pending as $name => $p) {
    if ($p['sock']) fclose($p['sock']);
    $out[$name] = ['ok' => false, 'ips' => [], 'code' => 'timeout'];
  }
  return $out;
}

/* ---------- blacklist check ---------- */

function ip_query_name(string $revIp, string $zone): string {
  $dqs = dqs_key();
  if ($dqs !== '' && isset(SPAMHAUS_DQ[$zone])) return "$revIp.$dqs." . SPAMHAUS_DQ[$zone];
  return "$revIp.$zone";
}
function domain_query_name(string $host, string $zone): string {
  $dqs = dqs_key();
  if ($dqs !== '' && isset(SPAMHAUS_DQ[$zone])) return "$host.$dqs." . SPAMHAUS_DQ[$zone];
  return "$host.$zone";
}

function check_host($raw): array {
  $host = trim((string) $raw);
  $host = preg_replace('#^https?://#i', '', $host);
  $host = preg_replace('#/.*$#', '', $host);
  $host = trim(preg_replace('/^www\./i', '', $host));
  if ($host === '' || !preg_match('/^[a-z0-9.\-]+$/i', $host)) return ['error' => 'invalid host'];

  $inputIsIp = is_ipv4($host);
  if ($inputIsIp) {
    $ip = $host;
  } else {
    $r = resolve_many([$host])[$host];
    $ip = $r['ips'][0] ?? '';
  }
  if ($ip === '') return ['host' => $host, 'ip' => '', 'results' => []];

  $rev = implode('.', array_reverse(explode('.', $ip)));
  $jobs = [];
  foreach (IP_LISTS as $l) $jobs[] = ['n' => $l['n'], 'q' => ip_query_name($rev, $l['z'])];
  if (!$inputIsIp) {
    foreach (DOMAIN_LISTS as $l) $jobs[] = ['n' => $l['n'], 'q' => domain_query_name($host, $l['z'])];
  }

  $answers = resolve_many(array_column($jobs, 'q'));
  $results = [];
  foreach ($jobs as $j) {
    $a = $answers[$j['q']];
    $results[] = $a['ok']
      ? ['n' => $j['n'], 'status' => classify($a['ips']), 'code' => implode('+', $a['ips'])]
      : ['n' => $j['n'], 'status' => 'error', 'code' => $a['code']];
  }
  return ['host' => $host, 'ip' => $ip, 'dqs' => dqs_key() !== '', 'results' => $results];
}
