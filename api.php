<?php
// api.php -- HotCRP JSON API access page
// HotCRP is Copyright (c) 2006-2017 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

// argument cleaning
require_once("lib/navigation.php");
if (!isset($_GET["fn"])) {
    $fn = Navigation::path_component(0, true);
    if ($fn && ctype_digit($fn)) {
        if (!isset($_GET["p"]))
            $_GET["p"] = $fn;
        $fn = Navigation::path_component(1, true);
    }
    if ($fn)
        $_GET["fn"] = $fn;
    else if (isset($_GET["track"]))
        $_GET["fn"] = "track";
    else
        $_GET["fn"] = "status";
}
if ($_GET["fn"] === "deadlines")
    $_GET["fn"] = "status";
if (!isset($_GET["p"])
    && ($p = Navigation::path_component(1, true))
    && ctype_digit($p))
    $_GET["p"] = $p;

// trackerstatus is a special case: prevent session creation
global $Me;
if ($_GET["fn"] === "trackerstatus") {
    $Me = false;
    require_once("src/initweb.php");
    MeetingTracker::trackerstatus_api(new Contact(null, $Conf));
    exit;
}

// initialization
require_once("src/initweb.php");

$qreq = make_qreq();
if ($qreq->base !== null)
    $Conf->set_siteurl($qreq->base);
if (!$Me->has_database_account()
    && ($key = $Me->capability("tracker_kiosk"))) {
    $kiosks = $Conf->setting_json("__tracker_kiosk") ? : (object) array();
    if (isset($kiosks->$key) && $kiosks->$key->update_at >= $Now - 172800) {
        if ($kiosks->$key->update_at < $Now - 3600) {
            $kiosks->$key->update_at = $Now;
            $Conf->save_setting("__tracker_kiosk", 1, $kiosks);
        }
        $Me->tracker_kiosk_state = $kiosks->$key->show_papers ? 2 : 1;
    }
}
if ($qreq->p && ctype_digit($qreq->p)) {
    $Conf->paper = $Conf->paperRow(array("paperId" => intval($qreq->p)), $Me);
    if ($Conf->paper && !$Me->can_view_paper($Conf->paper))
        $Conf->paper = null;
}

// requests
if ($Conf->has_api($qreq->fn))
    $Conf->call_api_exit($qreq->fn, $Me, $qreq, $Conf->paper);

if ($qreq->fn === "jserror") {
    $url = (string) $qreq->url;
    if (preg_match(',[/=]((?:script|jquery)[^/&;]*[.]js),', $url, $m))
        $url = $m[1];
    if (($n = $qreq->lineno))
        $url .= ":" . $n;
    if (($n = $qreq->colno))
        $url .= ":" . $n;
    if ($url !== "")
        $url .= ": ";
    $errormsg = trim((string) $qreq->error);
    if ($errormsg) {
        $suffix = "";
        if ($Me->email)
            $suffix .= ", user " . $Me->email;
        if (isset($_SERVER["REMOTE_ADDR"]))
            $suffix .= ", host " . $_SERVER["REMOTE_ADDR"];
        error_log("JS error: $url$errormsg$suffix");
        if (($stacktext = $qreq->stack)) {
            $stack = array();
            foreach (explode("\n", $stacktext) as $line) {
                $line = trim($line);
                if ($line === "" || $line === $errormsg || "Uncaught $line" === $errormsg)
                    continue;
                if (preg_match('/\Aat (\S+) \((\S+)\)/', $line, $m))
                    $line = $m[1] . "@" . $m[2];
                else if (substr($line, 0, 1) === "@")
                    $line = substr($line, 1);
                else if (substr($line, 0, 3) === "at ")
                    $line = substr($line, 3);
                $stack[] = $line;
            }
            error_log("JS error: {$url}via " . join(" ", $stack));
        }
    }
    json_exit(["ok" => true]);
}

if ($qreq->fn === "setsession") {
    if (preg_match('/\A(foldpaper[abpt]|foldpscollab|foldhomeactivity|(?:pl|pf|ul)display|scoresort)(|\..*)\z/', (string) $qreq->var, $m)) {
        $val = $qreq->val;
        if ($m[2]) {
            $on = !($val !== null && intval($val) > 0);
            if ($m[1] === "pldisplay" || $m[1] === "pfdisplay")
                PaperList::change_display($Me, substr($m[1], 0, 2), substr($m[2], 1), $on);
            else if (preg_match('/\A\.[-a-zA-Z0-9_:]+\z/', $m[2]))
                displayOptionsSet($m[1], substr($m[2], 1), $on);
            else
                json_exit(["ok" => false]);
        } else
            $Conf->save_session($m[1], $val !== null ? intval($val) : null);
        json_exit(["ok" => true]);
    } else
        json_exit(["ok" => false]);
}

if ($qreq->fn === "events" && $Me->is_reviewer()) {
    $from = $qreq->from;
    if (!$from || !ctype_digit($from))
        $from = $Now;
    $when = $from;
    $rf = $Conf->review_form();
    $events = new PaperEvents($Me, false);
    $rows = [];
    foreach ($events->events($when, 10) as $xr) {
        if ($xr->crow)
            $rows[] = $xr->crow->unparse_flow_entry($Me);
        else
            $rows[] = $rf->unparse_flow_entry($xr->prow, $xr->rrow, $Me);
        $when = $xr->eventTime;
    }
    json_exit(["ok" => true, "from" => (int) $from, "to" => (int) $when - 1,
               "rows" => $rows]);
} else if ($qreq->fn === "events")
    json_exit(["ok" => false]);

if ($qreq->fn === "searchcompletion") {
    $s = new PaperSearch($Me, "");
    json_exit(["ok" => true, "searchcompletion" => $s->search_completion()]);
}


// from here on: `status` and `track` requests
if ($qreq->fn === "track")
    MeetingTracker::track_api($Me, $qreq); // may fall through to act like `status`

$j = $Me->my_deadlines($Conf->paper);

if ($qreq->conflist && $Me->has_email() && ($cdb = Contact::contactdb())) {
    $j->conflist = array();
    $result = Dbl::ql($cdb, "select c.confid, siteclass, shortName, url
        from Roles r join Conferences c on (c.confid=r.confid)
        join ContactInfo u on (u.contactDbId=r.contactDbId)
        where u.email=? order by r.updated_at desc", $Me->email);
    while (($row = edb_orow($result))) {
        $row->confid = (int) $row->confid;
        $j->conflist[] = $row;
    }
}

if ($Conf->paper && $Me->can_view_tags($Conf->paper)) {
    $pj = (object) ["pid" => $Conf->paper->paperId];
    $Conf->paper->add_tag_info_json($pj, $Me);
    if (count((array) $pj) > 1)
        $j->p = [$Conf->paper->paperId => $pj];
}

$j->ok = true;
json_exit($j);
