*** /dev/null
--- b/src/Core/Cache/NullCache.php
@@
+<?php
+declare(strict_types=1);
+
+namespace BlackCat\Core\Cache;
+
+use Psr\SimpleCache\CacheInterface;
+
+/** Jednoduchý no-op cache (praktické pro testy/feature flags). */
+final class NullCache implements CacheInterface
+{
+    public function get($key, $default = null)      { return $default; }
+    public function set($key, $value, $ttl = null)  { return true; }
+    public function delete($key)                    { return true; }
+    public function clear()                         { return true; }
+    public function getMultiple($keys, $default = null)
+    {
+        $out = [];
+        foreach ($keys as $k) { $out[$k] = $default; }
+        return $out;
+    }
+    public function setMultiple($values, $ttl = null) { return true; }
+    public function deleteMultiple($keys)             { return true; }
+    public function has($key)                         { return false; }
+}
*** /dev/null
--- b/src/Core/Cache/NullCache.php
@@
+<?php
+declare(strict_types=1);
+
+namespace BlackCat\Core\Cache;
+
+use Psr\SimpleCache\CacheInterface;
+
+final class NullCache implements CacheInterface
+{
+    public function get($key, $default = null)      { return $default; }
+    public function set($key, $value, $ttl = null)  { return true; }
+    public function delete($key)                    { return true; }
+    public function clear()                         { return true; }
+    public function getMultiple($keys, $default = null) {
+        $out = []; foreach ($keys as $k) { $out[$k] = $default; } return $out;
+    }
+    public function setMultiple($values, $ttl = null){ return true; }
+    public function deleteMultiple($keys)            { return true; }
+    public function has($key)                        { return false; }
+}
