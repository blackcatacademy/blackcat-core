<?php
declare(strict_types=1);
/**
 * libs/autoload.php
 * Ruční (composer-less) autoloader pro /libs -- řeší i přednačtení kritických trait súborů (FPDI, PSR-traits)
 *
 * Umísti do /libs/autoload.php a pak v ./admin/libtest.php nebo jiných skriptech použij:
 *    require __DIR__ . '/libs/autoload.php';
 *
 * POZN: pokud najde vendor/autoload.php (tj. kompletní Composer instalaci v /libs/vendor/) tak jej použije a skončí.
 */

$vendor = __DIR__ . '/vendor/autoload.php';
if (file_exists($vendor)) {
    require $vendor;
    return;
}

/**
 * Helper: požaduj první existující soubor ze seznamu kandidátů.
 * Vrátí cestu k zahrnutému souboru nebo false.
 */
$require_first = function(array $candidates) {
    foreach ($candidates as $rel) {
        $p = __DIR__ . '/' . ltrim($rel, "/");
        if (file_exists($p)) {
            require_once $p;
            return $p;
        }
    }
    return false;
};

/* -------------------------
   Přednačtení kritických trait / bootstrap souborů
   (musí být načteny dříve než mpdf/src/FpdiTrait.php nebo mpdf/src/Mpdf.php)
   ------------------------- */

// 2) mpdf - psr-log-aware trait (mPDF očekává tento trait jménem MpdfPsrLogAwareTrait)
$require_first([
    'mpdf-psr-log-aware-trait/src/MpdfPsrLogAwareTrait.php',
    'mpdf/psr-log-aware-trait/src/MpdfPsrLogAwareTrait.php',
    'psr-log-aware-trait/src/MpdfPsrLogAwareTrait.php',
    'simple-cache/src/CacheInterface.php',
    'PHPMailer/src/PHPMailer.php',
]);

// 3) případný psr-http-message shim (může být potřeba)
$require_first([
    // nejprve PSR-7 interfaces
    'psr-http-message/src/MessageInterface.php',
    'psr-http-message/src/RequestInterface.php',
    'psr-http-message/src/ResponseInterface.php',
    'psr-http-message/src/ServerRequestInterface.php',
    'psr-http-message/src/StreamInterface.php',
    'psr-http-message/src/UriInterface.php',

    // až potom shim implementace
    'mpdf-psr-http-message-shim/src/Request.php',
    'mpdf-psr-http-message-shim/src/Response.php',
    'mpdf-psr-http-message-shim/src/ServerRequest.php'

]);

// 4) random_compat (pokud je v libs)
$require_first([
    'random_compat/lib/random.php',
    'paragonie/random_compat/lib/random.php',
    'random_compat/random.php'
]);

// 5) mpdf functions.php (mPDF definuje své "files" v composeru) - načti ho vždy jestli existuje
$require_first([
    'mpdf/src/functions.php',
    'mpdf/functions.php'
]);

// 6) PHP QR Code (server-side)
$require_first([
    'phpqrcode/phpqrcode.php',
    'phpqrcode/qrlib.php',
    'phpqrcode.php'
]);

$path = realpath(__DIR__ . '/htmlpurifier/library/HTMLPurifier.auto.php');
if ($path !== false) {
    require_once $path;
}

/* -------------------------
   PSR-4 prefix -> adresář mapy (přidej podle toho, co nahraješ do /libs)
   ------------------------- */
$prefixes = [
    // mPDF
    'Mpdf\\' => __DIR__ . '/mpdf/src/',

    // mpdf helper traits shims
    'Mpdf\\PsrHttpMessageShim\\' => __DIR__ . '/mpdf-psr-http-message-shim/src/',
    'Mpdf\\PsrLogAwareTrait\\' => __DIR__ . '/mpdf-psr-log-aware-trait/src/',

    // PSR interfaces
    'Psr\\Http\\Message\\' => __DIR__ . '/psr-http-message/src/',
    'Psr\\Http\\Client\\' => __DIR__ . '/psr-http-client/src/',
    'Psr\\Log\\' => __DIR__ . '/psr-log/src/',

    // PhpSpreadsheet
    'PhpOffice\\PhpSpreadsheet\\' => __DIR__ . '/phpspreadsheet/src/PhpSpreadsheet/',

    // DeepCopy (myclabs)
    'DeepCopy\\' => __DIR__ . '/myclabs-deep-copy/src/DeepCopy/',

    // ParagonIE / random compat namespaces (pokud jsou)
    'ParagonIE\\ConstantTime\\' => __DIR__ . '/random_compat/lib/ParagonIE/ConstantTime/',
    'RandomCompat\\' => __DIR__ . '/random_compat/lib/',

    'Psr\\SimpleCache\\' => __DIR__ . '/simple-cache/src/',

    'Composer\\Pcre\\' => __DIR__ . '/pcre/src/',

    'ZipStream\\' => __DIR__ . '/ZipStream-PHP-main/src/',

    'PHPMailer\\PHPMailer\\' => __DIR__ . '/PHPMailer/src/',
];

/* SPL autoloader */
spl_autoload_register(function($class) use ($prefixes) {
    // try PSR-4 map
    foreach ($prefixes as $prefix => $baseDir) {
        if (strncmp($prefix, $class, strlen($prefix)) !== 0) continue;
        $relative = substr($class, strlen($prefix));
        $file = $baseDir . str_replace('\\', '/', $relative) . '.php';
        if (file_exists($file)) {
            require_once $file;
            return true;
        }
    }

    // fallback: common direct path under /libs
    $direct = __DIR__ . '/' . str_replace('\\', '/', $class) . '.php';
    if (file_exists($direct)) {
        require_once $direct;
        return true;
    }

    // nic jsme nenašli (autoloader nechá další registrované autoloadery zkusit)
    return false;
});

/* Doporučené další include (volitelné) - např. js polyfily / helpery */
/* require_once __DIR__ . '/helpers.php'; // pokud máš shared helpers */

/* Volitelná diagnostika (pro ladění, zakomentuj v produkci) */
/*
$debug = function($msg){
    file_put_contents(__DIR__ . '/autoload.log', date('c') . ' ' . $msg . PHP_EOL, FILE_APPEND);
};
$debug('libs/autoload initialized');
*/