<?php
// navigation.php -- HotCRP navigation helper functions
// HotCRP is Copyright (c) 2006-2016 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

class Navigation {
    private static $protocol;           // "http://" or "https://"
    private static $server;             // "PROTOCOL://SITE[:PORT]"
    private static $sitedir;            // "/PATH", does not include $page, ends in /
    private static $page;               // Name of page
    private static $path;
    private static $query;
    private static $sitedir_relative;
    private static $php_suffix;

    public static function analyze($index_name = "index") {
        if (PHP_SAPI == "cli")
            return;

        if (isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] != "off")
            list($x, $xport) = array("https://", 443);
        else
            list($x, $xport) = array("http://", 80);
        self::$protocol = $x;
        $x .= self::host() ? : "localhost";
        if (($port = $_SERVER["SERVER_PORT"])
            && $port != $xport
            && strpos($x, ":", 6) === false)
            $x .= ":" . $port;
        self::$server = $x;

        // detect $sitedir
        $sfilename = $_SERVER["SCRIPT_FILENAME"]; // pathname
        $sfile = substr($sfilename, strrpos($sfilename, "/") + 1);

        $sname = $_SERVER["SCRIPT_NAME"]; // URL-decoded
        $sname_slash = strrpos($sname, "/");
        if (substr($sname, $sname_slash + 1) !== $sfile) {
            if ($sname === "" || $sname[strlen($sname) - 1] !== "/")
                $sname .= "/";
            $sname_slash = strlen($sname) - 1;
        }

        $uri = $_SERVER["REQUEST_URI"]; // URL-encoded
        if (substr($uri, 0, $sname_slash) === substr($sname, 0, $sname_slash))
            $uri_slash = $sname_slash;
        else {
            // URL-encoded prefix != URL-decoded prefix
            for ($nslash = substr_count(substr($sname, 0, $sname_slash), "/"),
                 $uri_slash = 0;
                 $nslash > 0; --$nslash)
                $uri_slash = strpos($uri, "/", $uri_slash + 1);
        }
        if ($uri_slash === false || $uri_slash > strlen($uri))
            $uri_slash = strlen($uri);

        self::$sitedir = substr($uri, 0, $uri_slash) . "/";

        // separate $page, $path, $query
        $uri_suffix = substr($uri, $uri_slash);
        preg_match(',\A(/[^/\?\#]*|)([^\?\#]*)(.*)\z,',
                   substr($uri, $uri_slash), $m);
        if ($m[1] !== "" && $m[1] !== "/")
            self::$page = urldecode(substr($m[1], 1));
        else
            self::$page = $index_name;
        if (($pagelen = strlen(self::$page)) > 4
            && substr(self::$page, $pagelen - 4) === ".php")
            self::$page = substr(self::$page, 0, $pagelen - 4);
        self::$path = urldecode($m[2]);
        self::$query = $m[3];

        // detect $sitedir_relative
        $path_slash = substr_count(self::$path, "/");
        if ($path_slash)
            self::$sitedir_relative = str_repeat("../", $path_slash);
        else if ($uri_slash >= strlen($uri))
            self::$sitedir_relative = self::$sitedir;
        else
            self::$sitedir_relative = "";

        self::$php_suffix = ".php";
        if ((isset($_SERVER["SERVER_SOFTWARE"])
             && substr($_SERVER["SERVER_SOFTWARE"], 0, 5) === "nginx")
            || (function_exists("apache_get_modules")
                && array_search("mod_rewrite", apache_get_modules()) !== false))
            self::$php_suffix = "";
    }

    public static function self() {
        return self::$server . self::$sitedir . self::$page . self::$path . self::$query;
    }

    public static function host() {
        $host = null;
        if (isset($_SERVER["HTTP_HOST"]))
            $host = $_SERVER["HTTP_HOST"];
        if (!$host && isset($_SERVER["SERVER_NAME"]))
            $host = $_SERVER["SERVER_NAME"];
        return $host;
    }

    public static function site_absolute($downcase_host = false) {
        $x = $downcase_host ? strtolower(self::$server) : self::$server;
        return $x . self::$sitedir;
    }

    public static function site_path() {
        return self::$sitedir;
    }

    public static function siteurl($url = null) {
        $x = self::$sitedir_relative;
        if (!$url)
            return $x;
        else if (substr($url, 0, 5) !== "index" || substr($url, 5, 1) === "/")
            return $x . $url;
        else
            return ($x ? : self::$sitedir) . substr($url, 5);
    }

    public static function siteurl_path($url = null) {
        $x = self::$sitedir;
        if (!$url)
            return $x;
        else if (substr($url, 0, 5) !== "index" || substr($url, 5, 1) === "/")
            return $x . $url;
        else
            return $x . substr($url, 5);
    }

    public static function set_siteurl($url) {
        if ($url !== "" && $url[strlen($url) - 1] !== "/")
            $url .= "/";
        return (self::$sitedir_relative = $url);
    }

    public static function page() {
        return self::$page;
    }

    public static function path() {
        return self::$path;
    }

    public static function path_component($n, $decoded = false) {
        if (self::$path !== "") {
            $p = explode("/", substr(self::$path, 1));
            if ($n + 1 < count($p) || ($n + 1 == count($p) && $p[$n] !== ""))
                return $decoded ? urldecode($p[$n]) : $p[$n];
        }
        return null;
    }

    public static function path_suffix($n) {
        if (self::$path !== "") {
            $p = 0;
            while ($n > 0 && ($p = strpos(self::$path, "/", $p + 1)))
                --$n;
            if ($p !== false)
                return substr(self::$path, $p);
        }
        return "";
    }

    public static function set_page($page) {
        return (self::$page = $page);
    }

    public static function set_path($path) {
        return (self::$path = $path);
    }

    public static function php_suffix() {
        return self::$php_suffix;
    }

    public static function make_absolute($url) {
        if ($url === false)
            return self::$server . self::$sitedir;
        preg_match(',\A((?:https?://[^/]+)?)(/*)((?:[.][.]/)*)(.*)\z,i', $url, $m);
        if ($m[1] !== "")
            return $url;
        else if (strlen($m[2]) > 1)
            return self::$protocol . substr($url, 2);
        else if ($m[2] === "/")
            return self::$server . $url;
        else {
            $site = substr($_SERVER["REQUEST_URI"], 0, strlen($_SERVER["REQUEST_URI"]) - strlen(self::$query));
            $site = preg_replace(',/[^/]+\z,', "/", $site);
            for (; $m[3]; $m[3] = substr($m[3], 3))
                $site = preg_replace(',/[^/]+/\z,', "/", $site);
            return self::$server . $site . $m[3] . $m[4];
        }
    }

    public static function redirect($url) {
        $url = self::make_absolute($url);
        // Might have an HTML-encoded URL; decode at least &amp;.
        $url = str_replace("&amp;", "&", $url);

        if (preg_match('|\A[a-z]+://|', $url))
            header("Location: $url");

        echo "<!DOCTYPE html><html lang=\"en\"><head>
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />
<meta http-equiv=\"Content-Script-Type\" content=\"text/javascript\" />
<title>Redirection</title>
<script>location=\"$url\";</script></head>
<body>
<p>You should be redirected <a href=\"", htmlspecialchars($url), "\">to here</a>.</p>
</body></html>\n";
        exit();
    }

    public static function redirect_site($site_url) {
        self::redirect(self::siteurl($site_url));
    }

    public static function redirect_http_to_https($allow_http_if_localhost = false) {
        if ((!isset($_SERVER["HTTPS"]) || $_SERVER["HTTPS"] == "off")
            && self::$protocol == "http://"
            && (!$allow_http_if_localhost
                || ($_SERVER["REMOTE_ADDR"] !== "127.0.0.1"
                    && $_SERVER["REMOTE_ADDR"] !== "::1")))
            self::redirect("https://" . (self::host() ? : "localhost")
                           . self::siteurl_path(self::$page . self::$php_suffix . self::$path . self::$query));
    }
}

Navigation::analyze();
