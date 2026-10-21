<?php
declare(strict_types=1);
// GET api/blacklist.php?host=example.com -> JSON
require __DIR__ . '/../../src/blacklist.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // restrict to your domain in production

try {
  echo json_encode(check_host($_GET['host'] ?? ''));
} catch (Throwable $e) {
  http_response_code(500);
  echo json_encode(['error' => 'server error']);
}
