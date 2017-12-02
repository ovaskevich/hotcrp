<?php // -*- mode: php -*-
// doc -- HotCRP paper download page
// HotCRP is Copyright (c) 2006-2017 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

require_once("src/initweb.php");

function document_error($status, $msg) {
    global $Conf, $Me;
    if (str_starts_with($status, "403") && $Me->is_empty()) {
        $Me->escape();
        exit;
    }

    $navpath = Navigation::path();
    error_log($Conf->dbname . ": bad doc $status $msg " . json_encode(make_qreq()) . ($navpath ? " @$navpath" : "") . ($Me ? " {$Me->email}" : ""));
    header("HTTP/1.1 $status");
    if (isset($_GET["fn"]))
        json_exit(["ok" => false, "error" => $msg ? : "Internal error."]);
    else {
        $Conf->header("Download", null, actionBar());
        $msg && Conf::msg_error($msg);
        $Conf->footer();
        exit;
    }
}

// Determine the intended paper
class DocumentRequest {
    public $paperId;
    public $dtype;
    public $opt;
    public $attachment;
    public $filters = [];
    public $req_filename;

    private function set_paperid($pid) {
        if (preg_match('/\A[-+]?\d+\z/', $pid))
            $this->paperId = intval($pid);
        else
            document_error("404 Not Found", "No such document [paper " . htmlspecialchars($pid) . "].");
    }

    function parse($req, $path, Conf $conf) {
        $want_path = false;
        if (isset($req["p"]))
            $this->set_paperid($req["p"]);
        else if (isset($req["paperId"]))
            $this->set_paperid($req["paperId"]);
        else
            $want_path = true;

        $dtname = null;
        $base_dtname = "paper";
        if (isset($req["dt"]))
            $dtname = $req["dt"];
        else if (isset($req["final"]))
            $base_dtname = "final";

        if (isset($req["attachment"]))
            $this->attachment = $req["attachment"];

        if ($want_path) {
            $s = $this->req_filename = preg_replace(',\A/*,', "", $path);
            $dtname = null;
            if (str_starts_with($s, $conf->download_prefix))
                $s = substr($s, strlen($conf->download_prefix));
            if (preg_match(',\A(?:p|paper|)(\d+)/+(.*)\z,', $s, $m)) {
                $this->paperId = intval($m[1]);
                if (preg_match(',\A([^/]+)\.[^/]+\z,', $m[2], $mm))
                    $dtname = urldecode($mm[1]);
                else if (preg_match(',\A([^/]+)/+(.*)\z,', $m[2], $mm)) {
                    $dtname = urldecode($mm[1]);
                    $this->attachment = urldecode($mm[2]);
                } else if (isset($req["dt"]))
                    $dtname = $req["dt"];
            } else if (preg_match(',\A(p|paper|final|)(\d+)-?([-A-Za-z0-9_]*)(?:|\.[^/]+|/+(.*))\z,', $s, $m)) {
                $this->paperId = intval($m[2]);
                $dtname = $m[3];
                if ($dtname === "" && $m[1] === "" && isset($req["dt"]))
                    $dtname = $req["dt"];
                if (isset($m[4]))
                    $this->attachment = urldecode($m[4]);
                if ($m[1] !== "")
                    $base_dtname = $m[1] === "final" ? "final" : "paper";
            } else if (preg_match(',\A([A-Za-z_][-A-Za-z0-9_]*?)?-?(\d+)(?:|\.[^/]+|/+(.*))\z,', $s, $m)) {
                $this->paperId = intval($m[2]);
                $dtname = $m[1];
                if (isset($m[3]))
                    $this->attachment = urldecode($m[3]);
            } else if (preg_match(',\A([^/]+?)(?:|\.[^/]+|/+(.*)|)\z,', $s, $m)) {
                $this->paperId = -2;
                $dtname = $m[1];
                if (isset($m[2]))
                    $this->attachment = urldecode($m[2]);
            } else
                document_error("404 Not Found", "No such document " . htmlspecialchars($this->req_filename) . ".");
        }

        $this->opt = null;
        while ((string) $dtname !== "" && $this->opt === null) {
            if (($dtnum = cvtint($dtname, null)) !== null)
                $this->opt = $conf->paper_opts->get($dtnum);
            else
                $this->opt = $conf->paper_opts->find($dtname, $this->paperId < 0);
            if ($this->opt !== null) {
                $dtname = "";
                break;
            }
            $filter = null;
            foreach (FileFilter::all_by_name() as $ff)
                if (str_ends_with($dtname, "-" . $ff->name) || $dtname === $ff->name) {
                    $filter = $ff;
                    break;
                }
            if (!$filter)
                break;
            array_unshift($this->filters, $filter);
            $dtname = substr($dtname, 0, strlen($dtname) - strlen($ff->name));
            if (str_ends_with($dtname, "-"))
                $dtname = substr($dtname, 0, strlen($dtname) - 1);
        }
        if ((string) $dtname !== "")
            document_error("404 Not Found", "No such document type “" . htmlspecialchars($dtname) . "”.");
        else if ($this->opt === null)
            $this->opt = $conf->paper_opts->find($base_dtname);
        $this->dtype = $this->opt->id;

        if (isset($req["filter"])) {
            foreach (explode(" ", $req["filter"]) as $filtername)
                if ($filtername !== "") {
                    if (($filter = FileFilter::find_by_name($filtername)))
                        $this->filters[] = $filter;
                    else
                        document_error("404 Not Found", "No such filter “" . htmlspecialchars($filter) . "”.");
                }
        }

        if (!$want_path) {
            $dtype_name = $this->opt->dtype_name();
            if ($this->paperId < 0)
                $this->req_filename = "[$dtype_name";
            else if ($this->dtype === DTYPE_SUBMISSION)
                $this->req_filename = "[paper #{$this->paperId}";
            else if ($this->dtype === DTYPE_FINAL)
                $this->req_filename = "[paper #{$this->paperId} final version";
            else
                $this->req_filename = "[#{$this->paperId} $dtype_name";
            if ($this->attachment)
                $this->req_filename .= " attachment " . $this->attachment;
            $this->req_filename .= "]";
        }

        return true;
    }
}

function document_history_element(DocumentInfo $doc) {
    $pj = ["hash" => $doc->text_hash(), "at" => $doc->timestamp, "mimetype" => $doc->mimetype];
    if ($doc->size)
        $pj["size"] = $doc->size;
    if ($doc->filename)
        $pj["filename"] = $doc->filename;
    return (object) $pj;
}

function document_history(PaperInfo $prow, $dtype) {
    global $Me;
    $docs = $prow->documents($dtype);

    $pjs = $actives = [];
    foreach ($docs as $doc) {
        $pj = document_history_element($doc);
        $pj->active = true;
        $actives[$doc->paperStorageId] = true;
        $pjs[] = $pj;
    }

    if ($Me->can_view_document_history($prow)) {
        $result = $prow->conf->qe("select paperStorageId, paperId, timestamp, mimetype, sha1, filename, infoJson, size from PaperStorage where paperId=? and documentType=? and filterType is null order by paperStorageId desc", $prow->paperId, $dtype);
        while (($doc = DocumentInfo::fetch($result, $prow->conf, $prow))) {
            if (!get($actives, $doc->paperStorageId))
                $pjs[] = document_history_element($doc);
        }
        Dbl::free($result);
    }

    return $pjs;
}

function document_download() {
    global $Conf, $Me;

    $dr = new DocumentRequest;
    $dr->parse($_GET, Navigation::path(), $Conf);

    $docid = null;

    if ($dr->dtype === null
        || $dr->opt->nonpaper !== ($dr->paperId < 0))
        document_error("404 Not Found", "No such document “" . htmlspecialchars($dr->req_filename) . "”.");

    if ($dr->opt->nonpaper) {
        $prow = new PaperInfo(["paperId" => -2], null, $Conf);
        if (($dr->opt->visibility === "admin" && !$Me->privChair)
            || ($dr->opt->visibility !== "all" && !$Me->isPC))
            document_error("403 Forbidden", "You don’t have permission to view this document.");
    } else {
        $prow = $Conf->paperRow($dr->paperId, $Me, $whyNot);
        if (!$prow)
            document_error("404 Not Found", whyNotText($whyNot, "view"));
        else if (($whyNot = $Me->perm_view_pdf($prow)))
            document_error("403 Forbidden", whyNotText($whyNot, "view"));
        else if ($dr->dtype > 0
                 && !$Me->can_view_paper_option($prow, $dr->dtype, true))
            document_error("403 Forbidden", "You don’t have permission to view this document.");
    }

    // history
    if (isset($_GET["fn"]) && $_GET["fn"] === "history")
        json_exit(["ok" => true, "result" => document_history($prow, $dr->dtype)]);

    if (!isset($_GET["version"]) && isset($_GET["hash"]))
        $_GET["version"] = $_GET["hash"];

    // time
    if (isset($_GET["at"]) && !isset($_GET["version"])) {
        if (ctype_digit($_GET["at"]))
            $time = intval($_GET["at"]);
        else if (!($time = $Conf->parse_time($_GET["at"])))
            $time = $Now;
        $want_pj = null;
        foreach (document_history($prow, $dr->dtype) as $pj) {
            if ($want_pj && $want_pj->at <= $time && $pj->at < $want_pj->at)
                break;
            else
                $want_pj = $pj;
        }
        if ($want_pj)
            $_GET["version"] = $want_pj->hash;
    }

    // version
    $want_docid = $request_docid = 0;
    if (isset($_GET["version"])) {
        $version_hash = Filer::hash_as_binary(trim($_GET["version"]));
        if (!$version_hash)
            document_error("404 Not Found", "No such version.");
        $want_docid = $Conf->fetch_ivalue("select max(paperStorageId) from PaperStorage where paperId=? and documentType=? and sha1=? and filterType is null", $dr->paperId, $dr->dtype, $version_hash);
        if ($want_docid !== null && $Me->can_view_document_history($prow))
            $request_docid = $want_docid;
    }

    if ($dr->attachment && !$request_docid)
        $doc = $prow->attachment($dr->dtype, $dr->attachment);
    else
        $doc = $prow->document($dr->dtype, $request_docid);
    if ($want_docid !== 0 && (!$doc || $doc->paperStorageId != $want_docid))
        document_error("404 Not Found", "No such version.");
    else if (!$doc)
        document_error("404 Not Found", "No such " . ($dr->attachment ? "attachment" : "document") . " “" . htmlspecialchars($dr->req_filename) . "”.");

    // pass through filters
    foreach ($dr->filters as $filter)
        $doc = $filter->apply($doc, $prow) ? : $doc;

    // check for contents request
    if (isset($_GET["fn"]) && ($_GET["fn"] === "listing" || $_GET["fn"] === "consolidatedlisting")) {
        if (!$doc->docclass->is_archive($doc))
            json_exit(["ok" => false, "error" => "That file is not an archive."]);
        else if (($listing = $doc->docclass->archive_listing($doc, 65536)) === false)
            json_exit(["ok" => false, "error" => isset($doc->error) ? $doc->error_text : "Internal error."]);
        else {
            $listing = $doc->docclass->clean_archive_listing($listing);
            if ($_GET["fn"] == "consolidatedlisting")
                $listing = join(", ", $doc->docclass->consolidate_archive_listing($listing));
            json_exit(["ok" => true, "result" => $listing]);
        }
    }

    // check for If-Not-Modified
    if ($doc->has_hash()) {
        $ifnonematch = null;
        if (function_exists("getallheaders")) {
            foreach (getallheaders() as $k => $v)
                if (strcasecmp($k, "If-None-Match") == 0)
                    $ifnonematch = $v;
        } else
            $ifnonematch = get($_SERVER, "HTTP_IF_NONE_MATCH");
        if ($ifnonematch && $ifnonematch === "\"" . $doc->text_hash() . "\"") {
            header("HTTP/1.1 304 Not Modified");
            exit;
        }
    }

    // Actually download paper.
    session_write_close();      // to allow concurrent clicks
    $opts = ["attachment" => cvtint(req("save")) > 0];
    if ($doc->has_hash() && ($x = req("hash")) && $doc->check_text_hash($x))
        $opts["cacheable"] = true;
    if ($Conf->download_documents([$doc], $opts))
        exit;

    document_error("500 Server Error", null);
}

document_download();
