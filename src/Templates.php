<?php
declare(strict_types=1);

/**
 * libs/Templates.php
 *
 * Secure PHP template renderer that does NOT use $GLOBALS.
 *
 * Usage:
 *   // in bootstrap, after loading config:
 *   Templates::init($config);
 *
 *   // render page:
 *   echo Templates::render('pages/login.php', ['csrf' => CSRF::token()]);
 *
 *   // render email:
 *   echo EmailTemplates::render('verify_email.php', ['verify_url' => $url]);
 *
 * Expected config keys (example):
 *  $config['paths']['templates']        => path to templates root (preferred)
 *  $config['paths']['email_templates']  => optional (defaults to templates/emails)
 *  $config['debug']                     => bool (optional)
 */

if (!function_exists('templates_internal_render')) {
    /**
     * Include template in isolated scope.
     *
     * $__file - absolute path (validated)
     * $__vars - associative array of variables (already escaped or SafeHtml)
     *
     * Returns rendered string. Re-throws exceptions from template.
     */
    function templates_internal_render(string $__file, array $__vars): string
    {
        $renderer = static function (string $__file, array $__vars): string {
            // Ensure only safe variable names get extracted
            foreach ($__vars as $k => $v) {
                if (!is_string($k) || !preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $k)) {
                    unset($__vars[$k]);
                }
            }
            extract($__vars, EXTR_SKIP);
            ob_start();
            try {
                include $__file;
            } catch (\Throwable $e) {
                ob_end_clean();
                throw $e;
            }
            // capture output, cleanup $__vars to free memory in this scope, then return
            $out = (string) ob_get_clean();
            unset($__vars);
            return $out;
        };
        return $renderer($__file, $__vars);
    }
}

class Templates
{
    protected const DEFAULT_VIEWS_DIR = __DIR__ . '/../www/views';
    protected const DEFAULT_EMAIL_SUBDIR = 'emails';
    protected const ESC_FLAGS = ENT_QUOTES | ENT_SUBSTITUTE;
    protected const ENCODING = 'UTF-8';
    protected const MAX_TEMPLATE_PATH_LEN = 4096;

    /** @var array|null configuration provided via init() */
    private static ?array $config = null;

    /** @var string[] cache of resolved real paths */
    private static array $resolvedCache = [];

    /**
     * Initialize with config array. Must be called from bootstrap (once).
     *
     * @param array $config
     * @return void
     */
    public static function init(array $config): void
    {
        self::$config = $config;
        self::$resolvedCache = [];
    }

    /**
     * Runtime override / setter (alias for init).
     *
     * @param array $config
     */
    public static function setConfig(array $config): void
    {
        self::init($config);
    }

    /**
     * Render page template (relative path inside templates dir).
     *
     * @param string $template e.g. 'pages/login.php' or 'partials/header.php'
     * @param array $data
     * @return string
     */
    public static function render(string $template, array $data = []): string
    {
        $viewsDirReal = self::getViewsDirReal();
        return self::renderInternal($template, $data, $viewsDirReal);
    }

    /**
     * Render template and also supply plain text fallback (useful for email alt bodies).
     *
     * @param string $templateHtml
     * @param array $data
     * @param string|null $textTemplate optional path for explicit text template
     * @return array ['html'=>string,'text'=>string]
     */
    public static function renderWithText(string $templateHtml, array $data = [], ?string $textTemplate = null): array
    {
        $viewsDirReal = self::getViewsDirReal();
        $html = self::renderInternal($templateHtml, $data, $viewsDirReal);
        if ($textTemplate !== null) {
            $text = self::renderInternal($textTemplate, $data, $viewsDirReal);
        } else {
            $text = trim(html_entity_decode(strip_tags($html), ENT_QUOTES | ENT_SUBSTITUTE, self::ENCODING));
        }
        return ['html' => $html, 'text' => $text];
    }

    /**
     * Create SafeHtml wrapper to indicate content must not be escaped.
     *
     * @param string $html
     * @return SafeHtml
     */
    public static function raw(string $html): SafeHtml
    {
        return new SafeHtml($html);
    }

    /**
     * Recursively escape strings in arrays/Traversable/stdClass for safe template usage.
     *
     * - Escapes scalars (string/int/float/bool) with htmlspecialchars.
     * - Recursively processes arrays and Traversable.
     * - Converts stdClass and JsonSerializable -> array and recurses.
     * - Leaves non-traversable objects untouched (trusted).
     * - Protects against cycles via spl_object_id and depth limit.
     *
     * @param mixed $v
     * @param int $depth remaining recursion depth (safety)
     * @param array<int,bool> $visited object ids visited
     * @return mixed
     */
    protected static function escapeValueRecursive(mixed $v, int $depth = 12, array &$visited = []): mixed
    {
        if ($depth <= 0) {
            // depth exhausted — avoid further recursion, return raw value
            return $v;
        }

        // scalars -> escape
        if (is_string($v) || is_int($v) || is_float($v) || is_bool($v)) {
            return htmlspecialchars((string)$v, self::ESC_FLAGS, self::ENCODING);
        }

        // arrays -> recurse keys and values
        if (is_array($v)) {
            $out = [];
            foreach ($v as $kk => $vv) {
                // keep original key (keys usually come from app code)
                $out[$kk] = self::escapeValueRecursive($vv, $depth - 1, $visited);
            }
            return $out;
        }

        // Traversable (e.g. ArrayObject, generators) -> convert to array safely
        if ($v instanceof \Traversable) {
            $out = [];
            foreach ($v as $kk => $vv) {
                $out[$kk] = self::escapeValueRecursive($vv, $depth - 1, $visited);
            }
            return $out;
        }

        // stdClass -> cast to array and recurse
        if ($v instanceof \stdClass) {
            $arr = (array) $v;
            $out = [];
            foreach ($arr as $kk => $vv) {
                $out[$kk] = self::escapeValueRecursive($vv, $depth - 1, $visited);
            }
            return $out;
        }

        // JsonSerializable -> use jsonSerialize result
        if ($v instanceof \JsonSerializable) {
            try {
                $serial = $v->jsonSerialize();
            } catch (\Throwable $_) {
                return $v;
            }
            return self::escapeValueRecursive($serial, $depth - 1, $visited);
        }

        // protect against cycles for objects that we decide to traverse
        if (is_object($v)) {
            if (function_exists('spl_object_id')) {
                $oid = spl_object_id($v);
                if (isset($visited[$oid])) {
                    return $v; // already visited -> break cycle
                }
                // mark visited for potential future traversals
                $visited[$oid] = true;
            }
            // For other objects (models, domain objects) we do NOT mutate them.
            // If you want to allow traversing custom objects, add handling above.
            return $v;
        }

        // fallback: return as-is
        return $v;
    }

    /**
     * Resolve templates dir realpath from config (or fallback). Throws if not accessible.
     *
     * @return string
     */
    protected static function getViewsDirReal(): string
    {
        if (self::$config === null) {
            throw new \RuntimeException('Templates not initialized (Templates::init($config) required).');
        }

        $candidate = self::$config['paths']['templates'] ?? self::DEFAULT_VIEWS_DIR;
        return self::resolveDirReal($candidate, 'templates');
    }

    /**
     * Resolve email templates dir realpath.
     * Defaults to {templates}/emails if not configured explicitly.
     *
     * @return string
     */
    protected static function getEmailViewsDirReal(): string
    {
        if (self::$config === null) {
            throw new \RuntimeException('Templates not initialized (Templates::init($config) required).');
        }

        $candidate = self::$config['paths']['email_templates']
            ?? (self::$config['paths']['templates'] ?? self::DEFAULT_VIEWS_DIR) . DIRECTORY_SEPARATOR . self::DEFAULT_EMAIL_SUBDIR;

        return self::resolveDirReal($candidate, 'email templates');
    }

    /**
     * Resolve and cache realpath for directory.
     *
     * @param string $dir
     * @param string $label
     * @return string
     */
    protected static function resolveDirReal(string $dir, string $label): string
    {
        $key = md5($dir . '::' . $label);
        if (isset(self::$resolvedCache[$key])) {
            return self::$resolvedCache[$key];
        }

        // protect against null bytes and overly long input
        if (strpos($dir, "\0") !== false || strlen($dir) > 8192) {
            throw new \RuntimeException('Invalid configuration path.');
        }

        $real = realpath($dir);
        $debug = (bool) (self::$config['debug'] ?? false);
        if ($real === false || !is_dir($real) || !is_readable($real)) {
            if ($debug) {
                throw new \RuntimeException(sprintf('Templates directory "%s" (%s) not accessible.', $label, $dir));
            }
            throw new \RuntimeException('Templates directory not available.');
        }

        $real = rtrim($real, DIRECTORY_SEPARATOR);
        self::$resolvedCache[$key] = $real;
        return $real;
    }

    /**
     * Core renderer used by both Templates and EmailTemplates.
     *
     * @param string $template
     * @param array $data
     * @param string $viewsDirReal
     * @return string
     */
    protected static function renderInternal(string $template, array $data, string $viewsDirReal): string
    {
        // basic validation of template path
        if ($template === '') {
            throw new \InvalidArgumentException('Template name is empty.');
        }
        if (strpos($template, "\0") !== false) {
            throw new \InvalidArgumentException('Invalid template name.');
        }
        if (strlen($template) > self::MAX_TEMPLATE_PATH_LEN) {
            throw new \InvalidArgumentException('Template name too long.');
        }
        // disallow absolute paths and traversal
        if (preg_match('#^(?:[A-Za-z]:[\\\\/]|[\\\\/])#', $template) || strpos($template, '..') !== false) {
            throw new \InvalidArgumentException('Template path must be relative and not contain traversal sequences.');
        }

        // construct candidate path (no normalization yet)
        $candidate = $viewsDirReal . DIRECTORY_SEPARATOR . ltrim($template, '/\\');

        // only allow PHP templates
        $ext = strtolower(pathinfo($candidate, PATHINFO_EXTENSION));
        if ($ext !== 'php') {
            throw new \InvalidArgumentException('Only .php templates are allowed.');
        }

        $debug = (bool) (self::$config['debug'] ?? false);
        if (!file_exists($candidate) || !is_file($candidate) || !is_readable($candidate)) {
            if ($debug) {
                throw new \RuntimeException('Template not found or not readable: ' . $candidate);
            }
            throw new \RuntimeException('Template not found.');
        }

        // realpath containment check (prevents symlink escape)
        $real = realpath($candidate);
        if ($real === false) {
            if ($debug) {
                throw new \RuntimeException('Template outside views dir: ' . $candidate);
            }
            throw new \RuntimeException('Template path invalid.');
        }
        // ensure $real is inside $viewsDirReal precisely (avoid prefix collisions)
        $viewsPrefix = rtrim($viewsDirReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (strpos($real . DIRECTORY_SEPARATOR, $viewsPrefix) !== 0) {
            if ($debug) {
                throw new \RuntimeException('Template outside views dir: ' . $candidate);
            }
            throw new \RuntimeException('Template path invalid.');
        }

        // prepare escaped data
        $esc = [];
        foreach ($data as $k => $v) {
            if (!is_string($k) || !preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $k)) {
                continue;
            }
            if ($v instanceof SafeHtml) {
                $esc[$k] = $v;
            } else {
                $esc[$k] = self::escapeValueRecursive($v);
            }
        }

        try {
            return templates_internal_render($real, $esc);
        } catch (\Throwable $e) {
            if ($debug) {
                throw $e;
            }
            throw new \RuntimeException('Failed to render template.');
        }
    }
}

/**
 * EmailTemplates uses email templates directory (configurable).
 */
class EmailTemplates extends Templates
{
    /**
     * Render e-mail HTML template from configured email templates dir.
     *
     * @param string $template relative path
     * @param array $data
     * @return string
     */
    public static function render(string $template, array $data = []): string
    {
        $viewsDirReal = parent::getEmailViewsDirReal();
        return parent::renderInternal($template, $data, $viewsDirReal);
    }

    public static function renderWithText(string $templateHtml, array $data = [], ?string $textTemplate = null): array
    {
        $viewsDirReal = parent::getEmailViewsDirReal();
        $html = parent::renderInternal($templateHtml, $data, $viewsDirReal);
        if ($textTemplate !== null) {
            $text = parent::renderInternal($textTemplate, $data, $viewsDirReal);
        } else {
            $text = trim(html_entity_decode(strip_tags($html), ENT_QUOTES | ENT_SUBSTITUTE, parent::ENCODING));
        }
        return ['html' => $html, 'text' => $text];
    }
}

/**
 * SafeHtml - wrapper indicating content is safe HTML.
 * If HTMLPurifier is available it will sanitize the passed HTML.
 */
class SafeHtml
{
    private string $html;
    /** @var \HTMLPurifier|null */
    private static $purifier = null;

    public function __construct(string $html)
    {
        if (class_exists('\\HTMLPurifier')) {
            try {
                if (self::$purifier === null) {
                    $config = \HTMLPurifier_Config::createDefault();
                    self::$purifier = new \HTMLPurifier($config);
                }
                $this->html = self::$purifier->purify($html);
            } catch (\Throwable $e) {
                $this->html = $html;
            }
        } else {
            $this->html = $html;
        }
    }

    public function __toString(): string
    {
        return $this->html;
    }

    public function getHtml(): string
    {
        return $this->html;
    }
}