<?php
// Small diagnostic script to run basic environment checks
function run_checks(PDO $db, $cfg) {
    $out = [];
    $out[] = 'PHP Version: ' . PHP_VERSION;
    $out[] = 'OpenSSL: ' . (function_exists('openssl_encrypt') ? 'OK' : 'MISSING');
    $out[] = 'ZipArchive: ' . (class_exists('ZipArchive') ? 'OK' : 'MISSING');
    try {
        $stmt = $db->query('SELECT 1');
        $out[] = 'DB: OK';
    } catch(Exception $e) { $out[] = 'DB: ERROR - ' . $e->getMessage(); }
    $storage = $cfg['paths']['storage'] ?? null;
    if ($storage) {
        $out[] = 'Storage path: ' . $storage . ' - ' . (is_writable($storage) ? 'writable' : 'NOT WRITABLE');
    }
    return $out;
}
if (!defined('STDOUT')) {
    // web invocation
    session_start();
    $cfg = require __DIR__ . '/../secure/config.php';
    require __DIR__ . '/autoload.php';
    Database::init($cfg['db']);
    Crypto::init_from_base64($cfg['crypto_key']);
    $db = Database::get();
    $res = run_checks($db, $cfg);
    echo '<pre>'; echo implode("\n", $res); echo '</pre>';
} else {
    echo "Run via web\n";
}