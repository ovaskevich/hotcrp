<?php
// helpers.php -- HotCRP non-class helper functions
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

/** @return array */
function mkarray($value) {
    if (is_array($value)) {
        return $value;
    } else {
        return array($value);
    }
}


// string helpers

/** @param null|int|string $value
 * @return int */
function cvtint($value, $default = -1) {
    $v = trim((string) $value);
    if (is_numeric($v)) {
        $ival = intval($v);
        if ($ival == floatval($v))
            return $ival;
    }
    return $default;
}

/** @param null|int|float|string $value
 * @return int|float */
function cvtnum($value, $default = -1) {
    $v = trim((string) $value);
    if (is_numeric($v)) {
        return floatval($v);
    }
    return $default;
}


// web helpers

/** @param int|float $n
 * @return string */
function unparse_number_pm_html($n) {
    if ($n < 0) {
        return "−" . (-$n); // U+2212 MINUS
    } else if ($n > 0) {
        return "+" . $n;
    } else {
        return "0";
    }
}

/** @param int|float $n
 * @return string */
function unparse_number_pm_text($n) {
    if ($n < 0) {
        return "-" . (-$n);
    } else if ($n > 0) {
        return "+" . $n;
    } else {
        return "0";
    }
}

function hoturl_add_raw($url, $component) {
    if (($pos = strpos($url, "#")) !== false) {
        $component .= substr($url, $pos);
        $url = substr($url, 0, $pos);
    }
    return $url . (strpos($url, "?") === false ? "?" : "&") . $component;
}

function hoturl($page, $param = null) {
    global $Conf;
    return $Conf->hoturl($page, $param);
}

function hoturl_post($page, $param = null) {
    global $Conf;
    return $Conf->hoturl($page, $param, Conf::HOTURL_POST);
}


class JsonResult {
    /** @var ?int */
    public $status;
    /** @var array<string,mixed> */
    public $content;

    function __construct($values = null) {
        if (is_int($values)) {
            $this->status = $values;
            if (func_num_args() === 2) {
                $values = func_get_arg(1);
            } else {
                $values = null;
            }
        }
        if ($values === true || $values === false) {
            $this->content = ["ok" => $values];
        } else if ($values === null) {
            $this->content = [];
        } else if (is_object($values)) {
            assert(!($values instanceof JsonResult));
            $this->content = (array) $values;
        } else if (is_string($values)) {
            assert($this->status && $this->status > 299);
            $this->content = ["ok" => false, "error" => $values];
        } else {
            assert(is_associative_array($values));
            $this->content = $values;
        }
    }
    static function make($jr, $arg2 = null) {
        if (is_int($jr)) {
            $jr = new JsonResult($jr, $arg2);
        } else if (!($jr instanceof JsonResult)) {
            $jr = new JsonResult($jr);
        }
        return $jr;
    }
    function export_errors() {
        if (isset($this->content["error"])) {
            Conf::msg_error($this->content["error"]);
        }
        if (isset($this->content["errf"])) {
            foreach ($this->content["errf"] as $f => $x) {
                Ht::error_at((string) $f);
            }
        }
    }
    function emit($validated) {
        if ($this->status) {
            if (!isset($this->content["ok"])) {
                $this->content["ok"] = $this->status <= 299;
            }
            if (!isset($this->content["status"])) {
                $this->content["status"] = $this->status;
            }
        } else if (isset($this->content["status"])) {
            $this->status = $this->content["status"];
        }
        if ($validated) {
            // Don’t set status on unvalidated requests, since that can leak
            // information (e.g. via <link prefetch onerror>).
            if ($this->status) {
                http_response_code($this->status);
            }
            header("Access-Control-Allow-Origin: *");
        }
        header("Content-Type: application/json; charset=utf-8");
        echo json_encode_browser($this->content);
    }
}

class JsonResultException extends Exception {
    /** @var JsonResult */
    public $result;
    /** @var bool */
    static public $capturing = false;
    /** @param JsonResult $j */
    function __construct($j) {
        $this->result = $j;
    }
}

function json_exit($json, $arg2 = null) {
    global $Qreq;
    $json = JsonResult::make($json, $arg2);
    if (JsonResultException::$capturing) {
        throw new JsonResultException($json);
    } else {
        $json->emit($Qreq && $Qreq->post_ok());
        exit;
    }
}

function csv_exit(CsvGenerator $csv) {
    $csv->download_headers();
    $csv->download();
    exit;
}

function foldupbutton($foldnum = 0, $content = "", $js = null) {
    if ($foldnum) {
        $js["data-fold-target"] = $foldnum;
    }
    $js["class"] = "ui q js-foldup";
    return Ht::link(expander(null, $foldnum) . $content, "#", $js);
}

/** @param ?bool $open
 * @param ?int $foldnum
 * @return string */
function expander($open, $foldnum = null) {
    $f = $foldnum !== null;
    $foldnum = ($foldnum !== 0 ? $foldnum : "");
    $t = '<span class="expander">';
    if ($open !== true) {
        $t .= '<span class="in0' . ($f ? " fx$foldnum" : "") . '">' . Icons::ui_triangle(2) . '</span>';
    }
    if ($open !== false) {
        $t .= '<span class="in1' . ($f ? " fn$foldnum" : "") . '">' . Icons::ui_triangle(1) . '</span>';
    }
    return $t . '</span>';
}


/** @param Contact|Author|ReviewInfo|CommentInfo $userlike
 * @return string */
function actas_link($userlike) {
    global $Conf;
    return '<a href="' . $Conf->selfurl(null, ["actas" => $userlike->email])
        . '" tabindex="-1">' . Ht::img("viewas.png", "[Act as]", ["title" => "Act as " . Text::nameo($userlike, NAME_P)])
        . '</a>';
}


function _one_quicklink($id, $baseUrl, $urlrest, $listtype, $isprev) {
    if ($listtype == "u") {
        $result = Dbl::ql("select email from ContactInfo where contactId=?", $id);
        $row = $result->fetch_row();
        Dbl::free($result);
        $paperText = htmlspecialchars($row ? $row[0] : $id);
        $urlrest["u"] = urlencode((string) $id);
    } else {
        $paperText = "#$id";
        $urlrest["p"] = $id;
    }
    return "<a id=\"quicklink-" . ($isprev ? "prev" : "next")
        . "\" class=\"x pnum\" href=\"" . hoturl($baseUrl, $urlrest) . "\">"
        . ($isprev ? Icons::ui_linkarrow(3) : "")
        . $paperText
        . ($isprev ? "" : Icons::ui_linkarrow(1))
        . "</a>";
}

function goPaperForm($baseUrl = null, $args = array()) {
    global $Conf, $Me;
    if ($Me->is_empty()) {
        return "";
    }
    $list = $Conf->active_list();
    $x = Ht::form($Conf->hoturl($baseUrl ? : "paper"), ["method" => "get", "class" => "gopaper"]);
    if ($baseUrl == "profile") {
        $x .= Ht::entry("u", "", array("id" => "quicklink-search", "size" => 15, "placeholder" => "User search", "aria-label" => "User search", "class" => "usersearch need-autogrow"));
    } else {
        $x .= Ht::entry("p", "", array("id" => "quicklink-search", "size" => 10, "placeholder" => "(All)", "aria-label" => "Search", "class" => "papersearch need-suggest need-autogrow"));
    }
    foreach ($args as $k => $v) {
        $x .= Ht::hidden($k, $v);
    }
    $x .= "&nbsp; " . Ht::submit("Search") . "</form>";
    return $x;
}

function rm_rf_tempdir($tempdir) {
    assert(substr($tempdir, 0, 1) === "/");
    exec("/bin/rm -rf " . escapeshellarg($tempdir));
}

function clean_tempdirs() {
    $dir = sys_get_temp_dir() ? : "/";
    while (substr($dir, -1) === "/") {
        $dir = substr($dir, 0, -1);
    }
    $dirh = opendir($dir);
    $now = time();
    while (($fname = readdir($dirh)) !== false) {
        if (preg_match('/\Ahotcrptmp\d+\z/', $fname)
            && is_dir("$dir/$fname")
            && ($mtime = @filemtime("$dir/$fname")) !== false
            && $mtime < $now - 1800)
            rm_rf_tempdir("$dir/$fname");
    }
    closedir($dirh);
}

function tempdir($mode = 0700) {
    $dir = sys_get_temp_dir() ? : "/";
    while (substr($dir, -1) === "/") {
        $dir = substr($dir, 0, -1);
    }
    for ($i = 0; $i !== 100; $i++) {
        $path = $dir . "/hotcrptmp" . mt_rand(0, 9999999);
        if (mkdir($path, $mode)) {
            register_shutdown_function("rm_rf_tempdir", $path);
            return $path;
        }
    }
    return false;
}


// text helpers
function commajoin($what, $joinword = "and") {
    $what = array_values($what);
    $c = count($what);
    if ($c == 0) {
        return "";
    } else if ($c == 1) {
        return $what[0];
    } else if ($c == 2) {
        return $what[0] . " " . $joinword . " " . $what[1];
    } else {
        return join(", ", array_slice($what, 0, -1)) . ", " . $joinword . " " . $what[count($what) - 1];
    }
}

function prefix_commajoin($what, $prefix, $joinword = "and") {
    return commajoin(array_map(function ($x) use ($prefix) {
        return $prefix . $x;
    }, $what), $joinword);
}

function numrangejoin($range) {
    $a = [];
    $format = $first = $last = null;
    $intval = $plen = 0;
    foreach ($range as $current) {
        if ($format !== null) {
            if (sprintf($format, $intval + 1) === (string) $current) {
                ++$intval;
                $last = $current;
                continue;
            } else if ($first === $last) {
                $a[] = $first;
            } else {
                $a[] = $first . "–" . substr($last, $plen);
            }
        }
        if ($current !== "" && ctype_digit($current)) {
            $format = "%0" . strlen((string) $current) . "d";
            $plen = 0;
            $first = $last = $current;
            $intval = intval($current);
        } else if (preg_match('/\A(\D*)(\d+)\z/', $current, $m)) {
            $format = str_replace("%", "%%", $m[1]) . "%0" . strlen($m[2]) . "d";
            $plen = strlen($m[1]);
            $first = $last = $current;
            $intval = intval($m[2]);
        } else {
            $format = null;
            $a[] = $current;
        }
    }
    if ($format !== null && $first === $last) {
        $a[] = $first;
    } else if ($format !== null) {
        $a[] = $first . "–" . substr($last, $plen);
    }
    return commajoin($a);
}

function pluralx($n, $what) {
    if (is_array($n)) {
        $n = count($n);
    }
    return $n == 1 ? $what : pluralize($what);
}

function pluralize($what) {
    if ($what == "this") {
        return "these";
    } else if ($what == "has") {
        return "have";
    } else if ($what == "is") {
        return "are";
    } else if (str_ends_with($what, ")") && preg_match('/\A(.*?)(\s*\([^)]*\))\z/', $what, $m)) {
        return pluralize($m[1]) . $m[2];
    } else if (preg_match('/\A.*?(?:s|sh|ch|[bcdfgjklmnpqrstvxz]y)\z/', $what)) {
        if (substr($what, -1) == "y") {
            return substr($what, 0, -1) . "ies";
        } else {
            return $what . "es";
        }
    } else {
        return $what . "s";
    }
}

function plural($n, $what) {
    return (is_array($n) ? count($n) : $n) . ' ' . pluralx($n, $what);
}

function ordinal($n) {
    $x = $n;
    if ($x > 100) {
        $x = $x % 100;
    }
    if ($x > 20) {
        $x = $x % 10;
    }
    return $n . ($x < 1 || $x > 3 ? "th" : ($x == 1 ? "st" : ($x == 2 ? "nd" : "rd")));
}

function tabLength($text, $all) {
    $len = 0;
    for ($i = 0; $i < strlen($text); ++$i) {
        if ($text[$i] == ' ') {
            $len++;
        } else if ($text[$i] == '\t') {
            $len += 8 - ($len % 8);
        } else if (!$all) {
            break;
        } else {
            $len++;
        }
    }
    return $len;
}

/** @param string $varname */
function ini_get_bytes($varname, $value = null) {
    $val = trim($value !== null ? $value : ini_get($varname));
    $last = strlen($val) ? strtolower($val[strlen($val) - 1]) : ".";
    /** @phan-suppress-next-line PhanParamSuspiciousOrder */
    return (int) ceil(floatval($val) * (1 << (+strpos(".kmg", $last) * 10)));
}

/** @param int|float $n
 * @return non-empty-string */
function unparse_byte_size($n) {
    if ($n > 999499)
        return (round($n / 100000) / 10) . "MB";
    else if ($n > 9949)
        return round($n / 1000) . "kB";
    else if ($n > 0)
        return (max(round($n / 100), 1) / 10) . "kB";
    else
        return "0B";
}

/** @param int|float $n
 * @return non-empty-string */
function unparse_byte_size_binary($n) {
    if ($n > 996147) {
        return (round($n / 104857.6) / 10) . "MiB";
    } else if ($n > 10188) {
        return round($n / 1024) . "KiB";
    } else if ($n > 0) {
        return (max(round($n / 102.4), 1) / 10) . "KiB";
    } else {
        return "0B";
    }
}

function filter_whynot($whyNot, $keys) {
    $revWhyNot = [];
    foreach ($whyNot as $k => $v) {
        if ($k === "fail" || $k === "paperId" || $k === "conf" || in_array($k, $keys))
            $revWhyNot[$k] = $v;
    }
    return $revWhyNot;
}

/** @param array{conf:Conf,paperId?:int,reviewId?:int,option?:PaperOption} $whyNot */
function whyNotText($whyNot, $text_only = false) {
    global $Conf, $Now;
    if (is_string($whyNot)) {
        $whyNot = array($whyNot => 1);
    }
    $conf = $whyNot["conf"] ?? $Conf;
    $paperId = $whyNot["paperId"] ?? -1;
    $reviewId = $whyNot["reviewId"] ?? -1;
    $option = $whyNot["option"] ?? null;
    $ms = [];
    $quote = $text_only ? function ($x) { return $x; } : "htmlspecialchars";
    if (isset($whyNot["invalidId"])) {
        $x = $whyNot["invalidId"] . "Id";
        if (isset($whyNot[$x])) {
            $ms[] = $conf->_("Invalid " . $whyNot["invalidId"] . " number “%s”.", $quote($whyNot[$x]));
        } else {
            $ms[] = $conf->_("Invalid " . $whyNot["invalidId"] . " number.");
        }
    }
    if (isset($whyNot["noPaper"])) {
        $ms[] = $conf->_("Submission #%d does not exist.", $paperId);
    }
    if (isset($whyNot["dbError"])) {
        $ms[] = $whyNot["dbError"];
    }
    if (isset($whyNot["administer"])) {
        $ms[] = $conf->_("You can’t administer submission #%d.", $paperId);
    }
    if (isset($whyNot["permission"])) {
        if ($whyNot["permission"] === "view_option") {
            $ms[] = $conf->_c("eperm", "Permission error.", $whyNot["permission"], $paperId, $quote($option->title()));
        } else {
            $ms[] = $conf->_c("eperm", "Permission error.", $whyNot["permission"], $paperId);
        }
    }
    if (isset($whyNot["optionNotAccepted"])) {
        $ms[] = $conf->_("The %2\$s field is reserved for accepted submissions.", $paperId, $quote($option->title()));
    }
    if (isset($whyNot["documentNotFound"])) {
        $ms[] = $conf->_("No such document “%s”.", $quote($whyNot["documentNotFound"]));
    }
    if (isset($whyNot["signin"])) {
        $ms[] = $conf->_c("eperm", "You have been signed out.", $whyNot["signin"], $paperId);
    }
    if (isset($whyNot["withdrawn"])) {
        $ms[] = $conf->_("Submission #%d has been withdrawn.", $paperId);
    }
    if (isset($whyNot["notWithdrawn"])) {
        $ms[] = $conf->_("Submission #%d is not withdrawn.", $paperId);
    }
    if (isset($whyNot["notSubmitted"])) {
        $ms[] = $conf->_("Submission #%d is only a draft.", $paperId);
    }
    if (isset($whyNot["rejected"])) {
        $ms[] = $conf->_("Submission #%d was not accepted for publication.", $paperId);
    }
    if (isset($whyNot["reviewsSeen"])) {
        $ms[] = $conf->_("You can’t withdraw a submission after seeing its reviews.", $paperId);
    }
    if (isset($whyNot["decided"])) {
        $ms[] = $conf->_("The review process for submission #%d has completed.", $paperId);
    }
    if (isset($whyNot["updateSubmitted"])) {
        $ms[] = $conf->_("Submission #%d can no longer be updated.", $paperId);
    }
    if (isset($whyNot["notUploaded"])) {
        $ms[] = $conf->_("A PDF upload is required to submit.");
    }
    if (isset($whyNot["reviewNotSubmitted"])) {
        $ms[] = $conf->_("This review is not yet ready for others to see.");
    }
    if (isset($whyNot["reviewNotComplete"])) {
        $ms[] = $conf->_("Your own review for #%d is not complete, so you can’t view other people’s reviews.", $paperId);
    }
    if (isset($whyNot["responseNotReady"])) {
        $ms[] = $conf->_("The authors’ response is not yet ready for reviewers to view.");
    }
    if (isset($whyNot["reviewsOutstanding"])) {
        $ms[] = $conf->_("You will get access to the reviews once you complete your assigned reviews. If you can’t complete your reviews, please let the organizers know via the “Refuse review” links.");
        if (!$text_only) {
            $ms[] = $conf->_("<a href=\"%s\">List assigned reviews</a>", $conf->hoturl("search", "q=&amp;t=r"));
        }
    }
    if (isset($whyNot["reviewNotAssigned"])) {
        $ms[] = $conf->_("You are not assigned to review submission #%d.", $paperId);
    }
    if (isset($whyNot["deadline"])) {
        $dname = $whyNot["deadline"];
        if ($dname[0] === "s") {
            $open_dname = "sub_open";
        } else if ($dname[0] === "p" || $dname[0] === "e") {
            $open_dname = "rev_open";
        } else {
            $open_dname = false;
        }
        $start = $open_dname ? $conf->setting($open_dname, -1) : 1;
        if ($dname === "extrev_chairreq") {
            $end_dname = $conf->review_deadline(get($whyNot, "reviewRound"), false, true);
        } else {
            $end_dname = $dname;
        }
        $end = $conf->setting($end_dname, -1);
        if ($dname == "au_seerev") {
            if ($conf->au_seerev == Conf::AUSEEREV_UNLESSINCOMPLETE) {
                $ms[] = $conf->_("You will get access to the reviews for this submission when you have completed your own reviews.");
                if (!$text_only) {
                    $ms[] = $conf->_("<a href=\"%s\">List your incomplete reviews</a>", $conf->hoturl("search", "t=rout&amp;q="));
                }
            } else {
                $ms[] = $conf->_c("etime", "Action not available.", $dname, $paperId);
            }
        } else if ($start <= 0 || $start == $end) {
            $ms[] = $conf->_c("etime", "Action not available.", $open_dname, $paperId);
        } else if ($start > 0 && $Now < $start) {
            $ms[] = $conf->_c("etime", "Action not available until %3\$s.", $open_dname, $paperId, $conf->unparse_time($start));
        } else if ($end > 0 && $Now > $end) {
            $ms[] = $conf->_c("etime", "Deadline passed.", $dname, $paperId, $conf->unparse_time($end));
        } else {
            $ms[] = $conf->_c("etime", "Action not available.", $dname, $paperId);
        }
    }
    if (isset($whyNot["override"])) {
        $ms[] = $conf->_("“Override deadlines” can override this restriction.");
    }
    if (isset($whyNot["blindSubmission"])) {
        $ms[] = $conf->_("Submission to this conference is blind.");
    }
    if (isset($whyNot["author"])) {
        $ms[] = $conf->_("You aren’t a contact for #%d.", $paperId);
    }
    if (isset($whyNot["conflict"])) {
        $ms[] = $conf->_("You have a conflict with #%d.", $paperId);
    }
    if (isset($whyNot["externalReviewer"])) {
        $ms[] = $conf->_("External reviewers cannot view other reviews.");
    }
    if (isset($whyNot["differentReviewer"])) {
        $ms[] = $conf->_("You didn’t write this review, so you can’t change it.");
    }
    if (isset($whyNot["unacceptableReviewer"])) {
        $ms[] = $conf->_("That user can’t be assigned to review #%d.", $paperId);
    }
    if (isset($whyNot["clickthrough"])) {
        $ms[] = $conf->_("You can’t do that until you agree to the terms.");
    }
    if (isset($whyNot["otherTwiddleTag"])) {
        $ms[] = $conf->_("Tag “#%s” doesn’t belong to you.", $quote($whyNot["tag"]));
    }
    if (isset($whyNot["chairTag"])) {
        $ms[] = $conf->_("Tag “#%s” can only be changed by administrators.", $quote($whyNot["tag"]));
    }
    if (isset($whyNot["voteTag"])) {
        $ms[] = $conf->_("The voting tag “#%s” shouldn’t be changed directly. To vote for this paper, change the “#~%1\$s” tag.", $quote($whyNot["tag"]));
    }
    if (isset($whyNot["voteTagNegative"])) {
        $ms[] = $conf->_("Negative votes aren’t allowed.");
    }
    if (isset($whyNot["autosearchTag"])) {
        $ms[] = $conf->_("Tag “#%s” cannot be changed since the system sets it automatically.", $quote($whyNot["tag"]));
    }
    if (empty($ms) && isset($whyNot["fail"])) {
        $ms[] = $conf->_c("eperm", "Permission error.", "unknown", $paperId);
    }
    // finish it off
    if (isset($whyNot["forceShow"]) && !$text_only) {
        $ms[] = $conf->_("<a class=\"nw\" href=\"%s\">Override conflict</a>", $conf->selfurl(null, ["forceShow" => 1]));
    }
    if (!empty($ms) && isset($whyNot["listViewable"]) && !$text_only) {
        $ms[] = $conf->_("<a href=\"%s\">List the submissions you can view</a>", $conf->hoturl("search", "q="));
    }
    return join(" ", $ms);
}

function actionBar($mode = null, $qreq = null) {
    global $Me, $Conf;
    if ($Me->is_disabled()) {
        return "";
    }
    $forceShow = ($Me->is_admin_force() ? "&amp;forceShow=1" : "");

    $paperArg = "p=*";
    $xmode = array();
    $listtype = "p";

    $goBase = "paper";
    if ($mode == "assign") {
        $goBase = "assign";
    } else if ($mode == "re") {
        $goBase = "review";
    } else if ($mode == "account") {
        $listtype = "u";
        if ($Me->privChair) {
            $goBase = "profile";
            $xmode["search"] = 1;
        }
    } else if ($qreq && ($qreq->m || $qreq->mode)) {
        $xmode["m"] = $qreq->m ? : $qreq->mode;
    }

    // quicklinks
    $x = "";
    if (($list = $Conf->active_list())) {
        $x .= '<td class="vbar quicklinks">';
        if (($prev = $list->neighbor_id(-1)) !== false)
            $x .= _one_quicklink($prev, $goBase, $xmode, $listtype, true) . " ";
        if ($list->description) {
            $url = $list->full_site_relative_url();
            if ($url) {
                $x .= '<a id="quicklink-list" class="x" href="' . htmlspecialchars(Navigation::siteurl() . $url) . "\">" . $list->description . "</a>";
            } else {
                $x .= '<span id="quicklink-list">' . $list->description . '</span>';
            }
        }
        if (($next = $list->neighbor_id(1)) !== false)
            $x .= " " . _one_quicklink($next, $goBase, $xmode, $listtype, false);
        $x .= '</td>';

        if ($Me->is_track_manager() && $listtype == "p") {
            $x .= '<td id="tracker-connect" class="vbar"><a id="tracker-connect-btn" class="ui js-tracker tbtn need-tooltip" href="" aria-label="Start meeting tracker">&#9759;</a><td>';
        }
    }

    // paper search form
    if ($Me->isPC || $Me->is_reviewer() || $Me->is_author()) {
        $x .= '<td class="vbar gopaper">' . goPaperForm($goBase, $xmode) . '</td>';
    }

    return $x ? '<table class="vbar"><tr>' . $x . '</tr></table>' : '';
}

function parseReviewOrdinal($t) {
    $t = strtoupper($t);
    if (!ctype_alpha($t))
        return -1;
    $l = strlen($t) - 1;
    $ord = 0;
    $base = 1;
    while (true) {
        $ord += (ord($t[$l]) - 64) * $base;
        if ($l === 0) {
            break;
        }
        --$l;
        $base *= 26;
    }
    return $ord;
}

/** @param null|ReviewInfo|int $ord
 * @return string */
function unparseReviewOrdinal($ord) {
    if (!$ord) {
        return ".";
    } else if (is_object($ord)) {
        if ($ord->reviewOrdinal) {
            return $ord->paperId . unparseReviewOrdinal($ord->reviewOrdinal);
        } else {
            return (string) $ord->reviewId;
        }
    } else if ($ord <= 26) {
        return chr($ord + 64);
    } else {
        $t = "";
        while (true) {
            $t = chr((($ord - 1) % 26) + 65) . $t;
            if ($ord <= 26) {
                return $t;
            }
            $ord = intval(($ord - 1) / 26);
        }
    }
}

function downloadText($text, $filename, $inline = false) {
    global $Conf;
    $csvg = new CsvGenerator(CsvGenerator::TYPE_TAB);
    $csvg->set_filename($Conf->download_prefix . $filename . $csvg->extension());
    $csvg->set_inline($inline);
    $csvg->download_headers();
    if ($text !== false) {
        $csvg->add_string($text);
        $csvg->download();
        exit;
    }
}

/** @param ?int $expertise
 * @return string */
function unparse_expertise($expertise) {
    if ($expertise === null) {
        return "";
    } else {
        return $expertise > 0 ? "X" : ($expertise == 0 ? "Y" : "Z");
    }
}

/** @param array{int,?int} $preference
 * @return string */
function unparse_preference($preference) {
    assert(is_array($preference)); // XXX remove
    $pv = $preference[0];
    $ev = $preference[1];
    if ($pv === null || $pv === false) {
        $pv = "0";
    }
    return $pv . unparse_expertise($ev);
}

/** @param array{int,?int} $preference
 * @return string */
function unparse_preference_span($preference, $always = false) {
    assert(is_array($preference)); // XXX remove
    $pv = (int) $preference[0];
    $ev = $preference[1];
    $tv = (int) ($preference[2] ?? null);
    if ($pv > 0 || (!$pv && $tv > 0)) {
        $type = 1;
    } else if ($pv < 0 || $tv < 0) {
        $type = -1;
    } else {
        $type = 0;
    }
    $t = "";
    if ($pv || $ev !== null || $always) {
        $t .= "P" . unparse_number_pm_html($pv) . unparse_expertise($ev);
    }
    if ($tv && !$pv) {
        $t .= ($t ? " " : "") . "T" . unparse_number_pm_html($tv);
    }
    if ($t !== "") {
        $t = " <span class=\"asspref$type\">$t</span>";
    }
    return $t;
}

function review_type_icon($revtype, $unfinished = null, $classes = null) {
    // see also script.js:review_form
    assert(!!$revtype);
    return '<span class="rto rt' . $revtype
        . ($revtype > 0 && $unfinished ? " rtinc" : "")
        . ($classes ? " " . $classes : "")
        . '" title="' . ReviewForm::$revtype_names_full[$revtype]
        . '"><span class="rti">' . ReviewForm::$revtype_icon_text[$revtype] . '</span></span>';
}

function review_lead_icon() {
    return '<span class="rto rtlead" title="Lead"><span class="rti">L</span></span>';
}

function review_shepherd_icon() {
    return '<span class="rto rtshep" title="Shepherd"><span class="rti">S</span></span>';
}


// Aims to return a random password string with at least
// `$length * 5` bits of entropy.
function hotcrp_random_password($length = 14) {
    // XXX it is possible to correctly account for loss of entropy due
    // to use of consonant pairs; I have only estimated
    $bytes = random_bytes($length + 12);
    $blen = strlen($bytes) * 8;
    $bneed = $length * 5;
    $pw = "";
    for ($b = 0; $bneed > 0 && $b + 8 <= $blen; ) {
        $bidx = $b >> 3;
        $codeword = (ord($bytes[$bidx]) << ($b & 7)) & 255;
        if (($b & 7) > 0) {
            $codeword |= ord($bytes[$bidx + 1]) >> (8 - ($b & 7));
        }
        if ($codeword < 0x60) {
            $t = "aeiouy";
            $pw .= $t[($codeword >> 4) & 0x7];
            $bneed -= 4; // log2(3/8 * 1/6)
            $b += 4;
        } else if ($codeword < 0xC0) {
            $t = "bcdghjklmnprstvw";
            $pw .= $t[($codeword >> 1) & 0xF];
            $bneed -= 5.415; // log2(3/8 * 1/16)
            $b += 7;
        } else if ($codeword < 0xE0) {
            $t = "trcrbrfrthdrchphwrstspswprslclz";
            $pw .= substr($t, $codeword & 0x1E, 2);
            $bneed -= 6.415; // log2(1/8 * 1/16 * [fudge] ~1.5)
            $b += 7;
        } else {
            $t = "23456789";
            $pw .= $t[($codeword >> 2) & 0x7];
            $bneed -= 6; // log2(1/8 * 1/8)
            $b += 6;
        }
    }
    return $pw;
}


function encode_token($x, $format = "") {
    $s = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    $t = "";
    if (is_int($x)) {
        $format = "V";
    }
    if ($format) {
        $x = pack($format, $x);
    }
    $i = 0;
    $have = 0;
    $n = 0;
    while ($have > 0 || $i < strlen($x)) {
        if ($have < 5 && $i < strlen($x)) {
            $n += ord($x[$i]) << $have;
            $have += 8;
            ++$i;
        }
        $t .= $s[$n & 31];
        $n >>= 5;
        $have -= 5;
    }
    if ($format === "V") {
        return preg_replace('/(\AA|[^A])A*\z/', '$1', $t);
    } else {
        return $t;
    }
}

function decode_token($x, $format = "") {
    $map = "//HIJKLMNO///////01234567/89:;</=>?@ABCDEFG";
    $t = "";
    $n = $have = 0;
    $x = trim(strtoupper($x));
    for ($i = 0; $i < strlen($x); ++$i) {
        $o = ord($x[$i]);
        if ($o >= 48 && $o <= 90 && ($out = ord($map[$o - 48])) >= 48) {
            $o = $out - 48;
        } else if ($o === 46 /*.*/ || $o === 34 /*"*/) {
            continue;
        } else {
            return false;
        }
        $n += $o << $have;
        $have += 5;
        while ($have >= 8 || ($n && $i === strlen($x) - 1)) {
            $t .= chr($n & 255);
            $n >>= 8;
            $have -= 8;
        }
    }
    if ($format == "V") {
        $x = unpack("Vx", $t . "\x00\x00\x00\x00\x00\x00\x00");
        return $x["x"];
    } else if ($format) {
        return unpack($format, $t);
    } else {
        return $t;
    }
}

/** @param string $bytes
 * @return string */
function base48_encode($bytes) {
    $convtab = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV";
    $bi = 0;
    $blen = strlen($bytes);
    $have = $w = 0;
    $t = "";
    while ($bi !== $blen || $have > 0) {
        while ($have < 11 && $bi !== $blen) {
            $w |= ord($bytes[$bi]) << $have;
            $have += 8;
            ++$bi;
        }
        $x = $w & 0x7FF;
        $t .= $convtab[$x % 48];
        if ($have > 5) {
            $t .= $convtab[(int) ($x / 48)];
        }
        $w >>= 11;
        $have -= 11;
    }
    return $t;
}

/** @param string $text
 * @return string|false */
function base48_decode($text) {
    $ti = 0;
    $tlen = strlen($text);
    $have = $w = 0;
    $b = "";
    while ($ti !== $tlen) {
        $chunk = $idx = 0;
        while ($ti !== $tlen && $idx !== 2) {
            $ch = ord($text[$ti]);
            if ($ch >= 97 && $ch <= 122) {
                $n = $ch - 97;
            } else if ($ch >= 65 && $ch <= 86) {
                $n = $ch - 39;
            } else {
                return false;
            }
            ++$ti;
            $chunk += $idx ? $n * 48 : $n;
            ++$idx;
        }
        if ($idx !== 0) {
            $w |= $chunk << $have;
            $have += $idx === 1 ? 5 : 11;
        }
        while ($have >= 8) {
            $b .= chr($w & 255);
            $w >>= 8;
            $have -= 8;
        }
    }
    return $b;
}
