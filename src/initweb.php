<?php
// initweb.php -- HotCRP initialization for web scripts
// Copyright (c) 2006-2019 Eddie Kohler; see LICENSE.

require_once("init.php");
global $Conf, $Me, $Qreq;

// Check method: GET/HEAD/POST only, except OPTIONS is allowed for API calls
if ($_SERVER["REQUEST_METHOD"] !== "GET"
    && $_SERVER["REQUEST_METHOD"] !== "HEAD"
    && $_SERVER["REQUEST_METHOD"] !== "POST"
    && (Navigation::page() !== "api"
        || $_SERVER["REQUEST_METHOD"] !== "OPTIONS")) {
    header("HTTP/1.0 405 Method Not Allowed");
    exit;
}

// Check for PHP suffix
if ($Conf->opt("phpSuffix") !== null)
    Navigation::get()->php_suffix = $Conf->opt("phpSuffix");

// Collect $Qreq
$Qreq = make_qreq();

// Check for redirect to https
if ($Conf->opt("redirectToHttps"))
    Navigation::redirect_http_to_https($Conf->opt("allowLocalHttp"));

// Check and fix zlib output compression
global $zlib_output_compression;
$zlib_output_compression = false;
if (function_exists("zlib_get_coding_type"))
    $zlib_output_compression = zlib_get_coding_type();
if ($zlib_output_compression) {
    header("Content-Encoding: $zlib_output_compression");
    header("Vary: Accept-Encoding", false);
}

// Mark as already expired to discourage caching, but allow the browser
// to cache for history buttons
header("Cache-Control: max-age=0,must-revalidate,private");

// Set up Content-Security-Policy if appropriate
$Conf->prepare_content_security_policy();

// Don't set up a session if $Me is false
if ($Me === false) {
    return;
}


// Initialize user
function initialize_user() {
    global $Conf, $Me, $Now, $Qreq;
    $nav = Navigation::get();

    // set up session
    if (isset($Conf->opt["sessionHandler"])) {
        $sh = $Conf->opt["sessionHandler"];
        $Conf->_session_handler = new $sh($Conf);
        session_set_save_handler($Conf->_session_handler, true);
    }
    set_session_name($Conf);
    $sn = session_name();

    // check CSRF token, using old value of session ID
    if ($Qreq->post && $sn) {
        if (isset($_COOKIE[$sn])) {
            $sid = $_COOKIE[$sn];
            $l = strlen($Qreq->post);
            if ($l >= 8 && $Qreq->post === substr($sid, strlen($sid) > 16 ? 8 : 0, $l))
                $Qreq->approve_post();
            else
                error_log("{$Conf->dbname}: bad post={$Qreq->post}, cookie={$sid}, url=" . $_SERVER["REQUEST_URI"]);
        } else if ($Qreq->post === "<empty-session>"
                   || $Qreq->post === ".empty") {
            $Qreq->approve_post();
        }
    }
    ensure_session(ENSURE_SESSION_ALLOW_EMPTY);

    // upgrade session format
    if (!isset($_SESSION["u"]) && isset($_SESSION["trueuser"])) {
        $_SESSION["u"] = $_SESSION["trueuser"]->email;
    }

    // determine user
    $trueemail = isset($_SESSION["u"]) ? $_SESSION["u"] : null;
    if (isset($_SESSION["us"])) {
        $uindex = false;
        if ($nav->shifted_path !== ""
            && substr($nav->shifted_path, 0, 2) === "u/") {
            $uindex = (int) substr($nav->shifted_path, 2);
        } else if ($nav->shifted_path === ""
                   && isset($_GET["i"])
                   && $_SERVER["REQUEST_METHOD"] === "GET") {
            $uindex = Contact::session_user_index($_GET["i"]);
        }
        if ($uindex !== false
            && $uindex >= 0
            && $uindex < count($_SESSION["us"])) {
            $trueemail = $_SESSION["us"][$uindex];
        } else {
            $uindex = (int) Contact::session_user_index($trueemail);
        }
        if ($nav->shifted_path === ""
            && $_SERVER["REQUEST_METHOD"] === "GET") {
            $page = "u/" . $uindex . "/";
            if ($nav->page !== "index" || $nav->path !== "") {
                $page .= $nav->page . $nav->php_suffix . $nav->path;
            }
            Navigation::redirect_base($page . $nav->query);
        }
    }
    if (isset($_GET["i"])
        && $_SERVER["REQUEST_METHOD"] === "GET"
        && $trueemail
        && strcasecmp($_GET["i"], $trueemail) !== 0) {
        Conf::msg_error("You are not signed in as " . htmlspecialchars($_GET["i"]) . ". <a href=\"" . $Conf->hoturl("index", ["signin" => 1, "email" => $_GET["i"]]) . "\">Sign in</a>");
    }

    // look up and activate user
    $Me = null;
    if ($trueemail) {
        $Me = $Conf->user_by_email($trueemail);
    }
    if (!$Me) {
        $Me = new Contact($trueemail ? (object) ["email" => $trueemail] : null);
    }
    $Me = $Me->activate($Qreq, true);

    // redirect if disabled
    if ($Me->is_disabled()) {
        if ($nav->page === "api") {
            json_exit(["ok" => false, "error" => "Your account is disabled."]);
        } else if ($nav->page !== "index" && $nav->page !== "resetpassword") {
            Navigation::redirect_site($Conf->hoturl_site_relative_raw("index"));
        }
    }

    // if bounced through login, add post data
    if (isset($_SESSION["login_bounce"][4])
        && $_SESSION["login_bounce"][4] <= $Now) {
        unset($_SESSION["login_bounce"]);
    }

    if (!$Me->is_empty()
        && isset($_SESSION["login_bounce"])
        && !isset($_SESSION["testsession"])) {
        $lb = $_SESSION["login_bounce"];
        if ($lb[0] == $Conf->dsn
            && $lb[2] !== "index"
            && $lb[2] == Navigation::page()) {
            foreach ($lb[3] as $k => $v)
                if (!isset($Qreq[$k]))
                    $Qreq[$k] = $v;
            $Qreq->set_annex("after_login", true);
        }
        unset($_SESSION["login_bounce"]);
    }

    // set $_SESSION["addrs"]
    if ($_SERVER["REMOTE_ADDR"]
        && (!$Me->is_empty()
            || isset($_SESSION["addrs"]))
        && (!isset($_SESSION["addrs"])
            || !is_array($_SESSION["addrs"])
            || $_SESSION["addrs"][0] !== $_SERVER["REMOTE_ADDR"])) {
        $as = [$_SERVER["REMOTE_ADDR"]];
        if (isset($_SESSION["addrs"]) && is_array($_SESSION["addrs"])) {
            foreach ($_SESSION["addrs"] as $a)
                if ($a !== $_SERVER["REMOTE_ADDR"] && count($as) < 5)
                    $as[] = $a;
        }
        $_SESSION["addrs"] = $as;
    }
}

initialize_user();
