<?php
// conference.php -- HotCRP central helper class (singleton)
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class Track {
    const VIEW = 0;
    const VIEWPDF = 1;
    const VIEWREV = 2;
    const VIEWREVID = 3;
    const ASSREV = 4;
    const UNASSREV = 5;
    const VIEWTRACKER = 6;
    const ADMIN = 7;
    const HIDDENTAG = 8;
    const VIEWALLREV = 9;

    const BITS_VIEW = 0x1;    // 1 << VIEW
    const BITS_REVIEW = 0x30; // (1 << ASSREV) | (1 << UNASSREV)
    const BITS_ADMIN = 0x80;  // 1 << ADMIN
    const BITS_VIEWADMIN = 0x81;  // (1 << VIEW) | (1 << ADMIN)

    static public $map = [
        "view" => 0, "viewpdf" => 1, "viewrev" => 2, "viewrevid" => 3,
        "assrev" => 4, "unassrev" => 5, "viewtracker" => 6, "admin" => 7,
        "hiddentag" => 8, "viewallrev" => 9
    ];
    static public $zero = [null, null, null, null, null, null, null, null, null, null];
    static function permission_required($perm) {
        return $perm === self::ADMIN || $perm === self::HIDDENTAG;
    }
}

class ResponseRound {
    /** @var string */
    public $name;
    /** @var int */
    public $number;
    /** @var int */
    public $open;
    /** @var ?int */
    public $done;
    /** @var ?int */
    public $grace;
    /** @var ?int */
    public $words;
    /** @var ?PaperSearch */
    public $search;
    function relevant(Contact $user, PaperInfo $prow = null) {
        global $Now;
        if ($user->allow_administer($prow)
            && ($this->done || $this->search || $this->name !== "1")) {
            return true;
        } else if ($user->isPC) {
            return $this->open > 0;
        } else {
            return $this->open > 0
                && $this->open < $Now
                && (!$this->search || $this->search->filter($prow ? [$prow] : $user->authored_papers()));
        }
    }
    function time_allowed($with_grace) {
        global $Now;
        if ($this->open === null || $this->open <= 0 || $this->open > $Now) {
            return false;
        }
        $t = $this->done;
        if ($t !== null && $t > 0 && $with_grace && $this->grace) {
            $t += $this->grace;
        }
        return $t === null || $t <= 0 || $t >= $Now;
    }
    function instructions(Conf $conf) {
        $m = $conf->_i("resp_instrux_$this->number", false, $this->words);
        if ($m === false) {
            $m = $conf->_i("resp_instrux", false, $this->words);
        }
        return $m;
    }
}

class Conf {
    /** @var ?mysqli */
    public $dblink;

    /** @var array<string,int> */
    public $settings;
    /** @var array<string,?string> */
    private $settingTexts;
    public $sversion;
    private $_pc_seeall_cache = null;
    private $_pc_see_pdf = false;

    public $dbname;
    public $dsn = null;

    /** @var string */
    public $short_name;
    /** @var string */
    public $long_name;
    /** @var int */
    public $default_format;
    /** @var string */
    public $download_prefix;
    /** @var int */
    public $au_seerev;
    /** @var ?list<string> */
    public $tag_au_seerev;
    /** @var bool */
    public $tag_seeall;
    /** @var int */
    public $ext_subreviews;
    /** @var int */
    public $any_response_open;
    /** @var bool */
    public $sort_by_last;
    /** @var array<string,mixed> */
    public $opt;
    public $opt_override;
    private $_opt_timestamp;
    public $paper_opts;

    public $headerPrinted = false;
    private $_save_logs = false;
    public $_session_handler;
    private $_initial_msg_count;

    /** @var ?Collator */
    private $_collator;
    /** @var list<string> */
    private $rounds;
    /** @var ?array<int,string> */
    private $_defined_rounds;
    private $_round_settings;
    /** @var ?list<ResponseRound> */
    private $_resp_rounds;
    /** @var ?array<string,list<?string>> */
    private $_tracks;
    /** @var ?TagMap */
    private $_taginfo;
    private $_track_tags;
    private $_track_sensitivity = 0;
    /** @var ?array<int,string> */
    private $_decisions;
    /** @var ?AbbreviationMatcher<int> */
    private $_decision_matcher;
    /** @var ?array<int,array{string,string}> */
    private $_decision_status_info;
    /** @var ?TopicSet */
    private $_topic_set;
    /** @var ?Conflict */
    private $_conflict_types;
    /** @var ?array<int,Contact> */
    private $_pc_members_cache;
    private $_pc_tags_cache;
    /** @var ?array<int,Contact> */
    private $_pc_users_cache;
    /** @var ?array<int,Contact> */
    private $_pc_chairs_cache;
    private $_pc_members_fully_loaded = false;
    private $_unslice = false;
    /** @var ?array<int,?Contact> */
    private $_user_cache;
    /** @var ?list<int> */
    private $_user_cache_missing;
    /** @var ?array<string,Contact> */
    private $_user_email_cache;
    /** @var ?Contact */
    private $_site_contact;
    /** @var ?Contact */
    private $_root_user;
    /** @var ?ReviewForm */
    private $_review_form_cache;
    /** @var ?AbbreviationMatcher<PaperOption|ReviewField|Formula> */
    private $_abbrev_matcher;
    private $_date_format_initialized = false;
    private $_formatspec_cache = [];
    /** @var ?non-empty-string */
    private $_docstore;
    /** @var array<int,Formula> */
    private $_defined_formulas = null;
    private $_emoji_codes = null;
    /** @var S3Document|null|false */
    private $_s3_document = false;
    /** @var ?IntlMsgSet */
    private $_ims;
    private $_format_info;
    private $_updating_autosearch_tags = false;
    private $_cdb = false;

    public $xt_context;
    private $_xt_allow_checkers;
    private $_xt_allow_callback;

    /** @var ?array<string,list<object>> */
    private $_formula_functions;
    /** @var ?array<string,list<object>> */
    private $_search_keyword_base;
    /** @var ?list<object> */
    private $_search_keyword_factories;
    /** @var ?array<string,list<object>> */
    private $_assignment_parsers;
    /** @var ?array<string,list<object>> */
    private $_api_map;
    /** @var ?array<string,list<object>> */
    private $_list_action_map;
    /** @var ?array<string,list<object>> */
    private $_list_action_renderers;
    /** @var ?list<object> */
    private $_list_action_factories;
    /** @var ?array<string,list<object>> */
    private $_paper_column_map;
    /** @var ?list<object> */
    private $_paper_column_factories;
    /** @var ?array<string,list<object>> */
    private $_option_type_map;
    private $_option_type_factories;
    private $_capability_factories;
    private $_capability_types;
    private $_hook_map;
    private $_hook_factories;
    /** @var ?array<string,FileFilter> */
    public $_file_filters; // maintained externally
    /** @var array<string,Si> */
    public $_setting_info = []; // maintained externally
    /** @var ?GroupedExtensions */
    public $_setting_groups; // maintained externally
    private $_mail_keyword_map;
    private $_mail_keyword_factories;
    private $_mail_template_map;
    private $_page_partials;

    /** @var ?PaperInfo */
    public $paper; // current paper row
    private $_active_list = false;

    /** @var Conf */
    static public $g;
    static public $no_invalidate_caches = false;
    static public $next_xt_subposition = 0;
    static private $xt_require_resolved = [];

    const BLIND_NEVER = 0;         // these values are used in `msgs.json`
    const BLIND_OPTIONAL = 1;
    const BLIND_ALWAYS = 2;
    const BLIND_UNTILREVIEW = 3;

    const SEEDEC_ADMIN = 0;
    const SEEDEC_REV = 1;
    const SEEDEC_ALL = 2;
    const SEEDEC_NCREV = 3;

    const AUSEEREV_NO = 0;
    const AUSEEREV_UNLESSINCOMPLETE = 1;
    const AUSEEREV_YES = 2;
    const AUSEEREV_TAGS = 3;

    const PCSEEREV_IFCOMPLETE = 0;
    const PCSEEREV_YES = 1;
    const PCSEEREV_UNLESSINCOMPLETE = 3;
    const PCSEEREV_UNLESSANYINCOMPLETE = 4;

    static public $review_deadlines = array("pcrev_soft", "pcrev_hard", "extrev_soft", "extrev_hard");

    static public $hoturl_defaults = null;

    function __construct($options, $make_dsn) {
        // unpack dsn, connect to database, load current settings
        $this->dsn = Dbl::make_dsn($options);
        list($this->dblink, $this->dbname) = Dbl::connect_dsn($this->dsn, !$make_dsn);
        $this->opt = $options;
        $this->opt["dbName"] = $this->dbname;
        $this->opt["confid"] = $this->opt["confid"] ?? $this->dbname;
        $this->paper_opts = new PaperOptionList($this);
        if ($this->dblink && !Dbl::$default_dblink) {
            Dbl::set_default_dblink($this->dblink);
            Dbl::set_error_handler(array($this, "query_error_handler"));
        }
        if ($this->dblink) {
            Dbl::$landmark_sanitizer = "/^(?:Dbl::|Conf::q|Conf::fetch|call_user_func)/";
            $this->load_settings();
        } else {
            $this->crosscheck_options();
        }
    }


    //
    // Initialization functions
    //

    function load_settings() {
        global $Now;

        // load settings from database
        $this->settings = array();
        $this->settingTexts = array();
        foreach ($this->opt_override ? : [] as $k => $v) {
            if ($v === null) {
                unset($this->opt[$k]);
            } else {
                $this->opt[$k] = $v;
            }
        }
        $this->opt_override = [];

        $result = $this->q_raw("select name, value, data from Settings");
        while (($row = $result->fetch_row())) {
            $this->settings[$row[0]] = (int) $row[1];
            if ($row[2] !== null) {
                $this->settingTexts[$row[0]] = $row[2];
            }
            if (substr($row[0], 0, 4) == "opt.") {
                $okey = substr($row[0], 4);
                $this->opt_override[$okey] = $this->opt[$okey] ?? null;
                $this->opt[$okey] = ($row[2] === null ? (int) $row[1] : $row[2]);
            }
        }
        Dbl::free($result);

        // update schema
        $this->sversion = $this->settings["allowPaperOption"];
        if ($this->sversion < 235) {
            require_once("updateschema.php");
            $old_nerrors = Dbl::$nerrors;
            updateSchema($this);
            Dbl::$nerrors = $old_nerrors;
        }
        if ($this->sversion < 200) {
            self::msg_error("Warning: The database could not be upgraded to the current version; expect errors. A system administrator must solve this problem.");
        }

        // invalidate all caches after loading from backup
        if (isset($this->settings["frombackup"])
            && $this->invalidate_caches()) {
            $this->qe_raw("delete from Settings where name='frombackup' and value=" . $this->settings["frombackup"]);
            unset($this->settings["frombackup"]);
        }

        // update options
        if (isset($this->opt["ldapLogin"]) && !$this->opt["ldapLogin"]) {
            unset($this->opt["ldapLogin"]);
        }
        if (isset($this->opt["httpAuthLogin"]) && !$this->opt["httpAuthLogin"]) {
            unset($this->opt["httpAuthLogin"]);
        }

        // GC old capabilities
        if (($this->settings["__capability_gc"] ?? 0) < $Now - 86400) {
            $this->cleanup_capabilities();
        }

        $this->crosscheck_settings();
        $this->crosscheck_options();
    }

    private function crosscheck_settings() {
        global $Now;

        // enforce invariants
        foreach (["pcrev_any", "extrev_view"] as $x) {
            if (!isset($this->settings[$x])) {
                $this->settings[$x] = 0;
            }
        }
        if (!isset($this->settings["sub_blind"])) {
            $this->settings["sub_blind"] = self::BLIND_ALWAYS;
        }
        if (!isset($this->settings["rev_blind"])) {
            $this->settings["rev_blind"] = self::BLIND_ALWAYS;
        }
        if (!isset($this->settings["seedec"])) {
            if ($this->settings["au_seedec"] ?? null) {
                $this->settings["seedec"] = self::SEEDEC_ALL;
            } else if ($this->settings["rev_seedec"] ?? null) {
                $this->settings["seedec"] = self::SEEDEC_REV;
            }
        }
        if (($this->settings["pc_seeallrev"] ?? null) == 2) {
            $this->settings["pc_seeblindrev"] = 1;
            $this->settings["pc_seeallrev"] = self::PCSEEREV_YES;
        }
        if (($sub_update = $this->settings["sub_update"] ?? -1) > 0
            && ($sub_reg = $this->settings["sub_reg"] ?? -1) <= 0) {
            $this->settings["sub_reg"] = $sub_update;
            $this->settings["__sub_reg"] = $sub_reg;
        }

        // rounds
        $this->crosscheck_round_settings();

        // S3 settings
        foreach (array("s3_bucket", "s3_key", "s3_secret") as $k) {
            if (!($this->settingTexts[$k] ?? null)
                && ($x = $this->opt[$k] ?? null)) {
                $this->settingTexts[$k] = $x;
            }
        }
        if (!($this->settingTexts["s3_key"] ?? null)
            || !($this->settingTexts["s3_secret"] ?? null)
            || !($this->settingTexts["s3_bucket"] ?? null)) {
            unset($this->settingTexts["s3_key"], $this->settingTexts["s3_secret"],
                  $this->settingTexts["s3_bucket"]);
        }
        if (($this->opt["dbNoPapers"] ?? null)
            && !($this->opt["docstore"] ?? null)
            && !($this->opt["filestore"] ?? null)
            && !($this->settingTexts["s3_bucket"] ?? null)) {
            unset($this->opt["dbNoPapers"]);
        }
        if ($this->_s3_document
            && (!isset($this->settingTexts["s3_bucket"])
                || !$this->_s3_document->check_key_secret_bucket($this->settingTexts["s3_key"], $this->settingTexts["s3_secret"], $this->settingTexts["s3_bucket"]))) {
            $this->_s3_document = false;
        }

        // tracks settings
        $this->_tracks = $this->_track_tags = null;
        $this->_track_sensitivity = 0;
        if (($j = $this->settingTexts["tracks"] ?? null))
            $this->crosscheck_track_settings($j);

        // clear caches
        $this->_decisions = $this->_decision_matcher = null;
        $this->_decision_status_info = null;
        $this->_pc_seeall_cache = null;
        $this->_defined_rounds = null;
        $this->_resp_rounds = null;
        // digested settings
        $this->_pc_see_pdf = true;
        if (($this->settings["sub_freeze"] ?? 0) <= 0
            && ($so = $this->settings["sub_open"] ?? 0) > 0
            && $so < $Now
            && ($ss = $this->settings["sub_sub"] ?? 0) > 0
            && $ss > $Now
            && (($this->settings["pc_seeallpdf"] ?? 0) <= 0
                || !$this->can_pc_see_active_submissions())) {
            $this->_pc_see_pdf = false;
        }

        $this->au_seerev = $this->settings["au_seerev"] ?? 0;
        $this->tag_au_seerev = null;
        if ($this->au_seerev == self::AUSEEREV_TAGS) {
            $this->tag_au_seerev = explode(" ", $this->settingTexts["tag_au_seerev"] ?? "");
        }
        $this->tag_seeall = ($this->settings["tag_seeall"] ?? 0) > 0;
        $this->ext_subreviews = $this->settings["pcrev_editdelegate"] ?? 0;

        $this->any_response_open = 0;
        if (($this->settings["resp_active"] ?? 0) > 0) {
            foreach ($this->resp_rounds() as $rrd) {
                if ($rrd->time_allowed(true)) {
                    if ($rrd->search) {
                        $this->any_response_open = 1;
                    } else {
                        $this->any_response_open = 2;
                        break;
                    }
                }
            }
        }
    }

    private function crosscheck_round_settings() {
        $this->rounds = [""];
        if (isset($this->settingTexts["tag_rounds"])) {
            foreach (explode(" ", $this->settingTexts["tag_rounds"]) as $r) {
                if ($r != "")
                    $this->rounds[] = $r;
            }
        }
        $this->_round_settings = null;
        if (isset($this->settingTexts["round_settings"])) {
            $this->_round_settings = json_decode($this->settingTexts["round_settings"]);
            $max_rs = [];
            foreach ($this->_round_settings as $rs) {
                if ($rs
                    && isset($rs->pc_seeallrev)
                    && self::pcseerev_compare($rs->pc_seeallrev, $max_rs["pc_seeallrev"] ?? 0) > 0) {
                    $max_rs["pc_seeallrev"] = $rs->pc_seeallrev;
                }
                if ($rs && isset($rs->extrev_view)
                    && $rs->extrev_view > ($max_rs["extrev_view"] ?? 0)) {
                    $max_rs["extrev_view"] = $rs->extrev_view;
                }
            }
            $this->_round_settings["max"] = (object) $max_rs;
        }

        // review times
        foreach ($this->rounds as $i => $rname) {
            $suf = $i ? "_$i" : "";
            if (!isset($this->settings["extrev_soft$suf"])
                && isset($this->settings["pcrev_soft$suf"])) {
                $this->settings["extrev_soft$suf"] = $this->settings["pcrev_soft$suf"];
            }
            if (!isset($this->settings["extrev_hard$suf"])
                && isset($this->settings["pcrev_hard$suf"])) {
                $this->settings["extrev_hard$suf"] = $this->settings["pcrev_hard$suf"];
            }
        }
    }

    private function crosscheck_track_settings($j) {
        if (is_string($j) && !($j = json_decode($j))) {
            return;
        }
        $this->_tracks = [];
        $default_track = Track::$zero;
        $this->_track_tags = [];
        foreach ((array) $j as $k => $v) {
            if ($k !== "_") {
                $this->_track_tags[] = $k;
            }
            if (!isset($v->viewpdf) && isset($v->view)) {
                $v->viewpdf = $v->view;
            }
            $t = Track::$zero;
            foreach (Track::$map as $tname => $idx) {
                if (isset($v->$tname)) {
                    $t[$idx] = $v->$tname;
                    $this->_track_sensitivity |= 1 << $idx;
                }
            }
            if ($k === "_") {
                $default_track = $t;
            } else {
                $this->_tracks[$k] = $t;
            }
        }
        $this->_tracks["_"] = $default_track;
    }

    function crosscheck_options() {
        global $ConfSitePATH;

        // set longName, downloadPrefix, etc.
        $confid = $this->opt["confid"];
        if ((!isset($this->opt["longName"]) || $this->opt["longName"] == "")
            && (!isset($this->opt["shortName"]) || $this->opt["shortName"] == "")) {
            $this->opt["shortNameDefaulted"] = true;
            $this->opt["longName"] = $this->opt["shortName"] = $confid;
        } else if (!isset($this->opt["longName"]) || $this->opt["longName"] == "") {
            $this->opt["longName"] = $this->opt["shortName"];
        } else if (!isset($this->opt["shortName"]) || $this->opt["shortName"] == "") {
            $this->opt["shortName"] = $this->opt["longName"];
        }
        if (!isset($this->opt["downloadPrefix"]) || $this->opt["downloadPrefix"] == "") {
            $this->opt["downloadPrefix"] = $confid . "-";
        }
        $this->short_name = $this->opt["shortName"];
        $this->long_name = $this->opt["longName"];

        // expand ${confid}, ${confshortname}
        foreach (["sessionName", "downloadPrefix", "conferenceSite",
                  "paperSite", "defaultPaperSite", "contactName",
                  "contactEmail", "docstore"] as $k) {
            if (isset($this->opt[$k]) && is_string($this->opt[$k])
                && strpos($this->opt[$k], "\$") !== false) {
                $this->opt[$k] = preg_replace(',\$\{confid\}|\$confid\b,', $confid, $this->opt[$k]);
                $this->opt[$k] = preg_replace(',\$\{confshortname\}|\$confshortname\b,', $this->short_name, $this->opt[$k]);
            }
        }
        $this->download_prefix = $this->opt["downloadPrefix"];

        foreach (["emailFrom", "emailSender", "emailCc", "emailReplyTo"] as $k) {
            if (isset($this->opt[$k]) && is_string($this->opt[$k])
                && strpos($this->opt[$k], "\$") !== false) {
                $this->opt[$k] = preg_replace('/\$\{confid\}|\$confid\b/', $confid, $this->opt[$k]);
                if (strpos($this->opt[$k], "confshortname") !== false) {
                    $v = rfc2822_words_quote($this->short_name);
                    if ($v[0] === "\"" && strpos($this->opt[$k], "\"") !== false) {
                        $v = substr($v, 1, strlen($v) - 2);
                    }
                    $this->opt[$k] = preg_replace('/\$\{confshortname\}|\$confshortname\b/', $v, $this->opt[$k]);
                }
            }
        }

        // remove final slash from $Opt["paperSite"]
        if (!isset($this->opt["paperSite"]) || $this->opt["paperSite"] === "") {
            $this->opt["paperSite"] = Navigation::base_absolute();
        }
        if ($this->opt["paperSite"] == "" && isset($this->opt["defaultPaperSite"])) {
            $this->opt["paperSite"] = $this->opt["defaultPaperSite"];
        }
        while (str_ends_with($this->opt["paperSite"], "/")) {
            $this->opt["paperSite"] = substr($this->opt["paperSite"], 0, -1);
        }

        // option name updates (backwards compatibility)
        foreach (["assetsURL" => "assetsUrl",
                  "jqueryURL" => "jqueryUrl", "jqueryCDN" => "jqueryCdn",
                  "disableCSV" => "disableCsv"] as $kold => $knew) {
            if (isset($this->opt[$kold]) && !isset($this->opt[$knew])) {
                $this->opt[$knew] = $this->opt[$kold];
            }
        }

        // set assetsUrl and scriptAssetsUrl
        if (!isset($this->opt["scriptAssetsUrl"])
            && isset($_SERVER["HTTP_USER_AGENT"])
            && strpos($_SERVER["HTTP_USER_AGENT"], "MSIE") !== false) {
            $this->opt["scriptAssetsUrl"] = Navigation::siteurl();
        }
        if (!isset($this->opt["assetsUrl"])) {
            $this->opt["assetsUrl"] = (string) Navigation::siteurl();
        }
        if ($this->opt["assetsUrl"] !== ""
            && !str_ends_with($this->opt["assetsUrl"], "/")) {
            $this->opt["assetsUrl"] .= "/";
        }
        if (!isset($this->opt["scriptAssetsUrl"])) {
            $this->opt["scriptAssetsUrl"] = $this->opt["assetsUrl"];
        }
        Ht::$img_base = $this->opt["assetsUrl"] . "images/";

        // set docstore
        $docstore = $this->opt["docstore"] ?? null;
        $dpath = "";
        $dpsubdir = $this->opt["docstoreSubdir"] ?? null;
        if (is_string($docstore)) {
            $dpath = $docstore;
        } else if ($docstore === true) {
            $dpath = "docs";
        } else if ($docstore === null && isset($this->opt["filestore"])) {
            if (is_string($this->opt["filestore"])) {
                $dpath = $this->opt["filestore"];
            } else if ($this->opt["filestore"] === true) {
                $dpath = "filestore";
            }
            $dpsubdir = $this->opt["filestoreSubdir"] ?? null;
        }
        if ($dpath !== "") {
            if ($dpath[0] !== "/") {
                $dpath = $ConfSitePATH . "/" . $dpath;
            }
            if (strpos($dpath, "%") === false) {
                $dpath .= ($dpath[strlen($dpath) - 1] === "/" ? "" : "/");
                if ($dpsubdir && ($dpsubdir === true || $dpsubdir > 0)) {
                    $dpath .= "%" . ($dpsubdir === true ? 2 : $dpsubdir) . "h/";
                }
                $dpath .= "%h%x";
            }
            $this->_docstore = $dpath;
        } else {
            $this->_docstore = null;
        }

        // handle timezone
        if (function_exists("date_default_timezone_set")) {
            if (isset($this->opt["timezone"])) {
                if (!date_default_timezone_set($this->opt["timezone"])) {
                    self::msg_error("Timezone option “" . htmlspecialchars($this->opt["timezone"]) . "” is invalid; falling back to “America/New_York”.");
                    date_default_timezone_set("America/New_York");
                }
            } else if (!ini_get("date.timezone") && !getenv("TZ")) {
                date_default_timezone_set("America/New_York");
            }
        }
        $this->_date_format_initialized = false;

        // set defaultFormat
        $this->default_format = (int) ($this->opt["defaultFormat"] ?? 0);
        $this->_format_info = null;

        // other caches
        $sort_by_last = !!($this->opt["sortByLastName"] ?? false);
        if (!$this->sort_by_last != !$sort_by_last) {
            $this->invalidate_caches("pc");
        }
        $this->sort_by_last = $sort_by_last;

        $this->_api_map = null;
        $this->_list_action_map = $this->_list_action_renderers = $this->_list_action_factories = null;
        $this->_file_filters = null;
        $this->_site_contact = null;
    }

    private function cleanup_capabilities() {
        global $Now;
        $ctmap = $this->capability_type_map();
        $ct_cleanups = [];
        foreach ($ctmap as $ctj) {
            if ($ctj->cleanup_callback ?? null)
                $ct_cleanups[] = $ctj->type;
        }
        if (!empty($ct_cleanups)) {
            $result = $this->ql("select * from Capability where timeExpires>0 and timeExpires<$Now and capabilityType?a", $ct_cleanups);
            while (($cap = CapabilityInfo::fetch($result, $this, false))) {
                call_user_func($ctmap[$cap->capabilityType]->cleanup_callback, $cap);
            }
            Dbl::free($result);
        }
        $this->ql("delete from Capability where timeExpires>0 and timeExpires<$Now");
        $this->ql("insert into Settings set name='__capability_gc', value=$Now on duplicate key update value=values(value)");
        $this->settings["__capability_gc"] = $Now;
    }


    /** @return bool */
    function has_setting($name) {
        return isset($this->settings[$name]);
    }

    /** @param string $name
     * @return ?int */
    function setting($name, $defval = null) {
        return $this->settings[$name] ?? $defval;
    }

    /** @param string $name
     * @return ?string */
    function setting_data($name, $defval = null) {
        return $this->settingTexts[$name] ?? $defval;
    }

    function setting_json($name, $defval = null) {
        $x = $this->settingTexts[$name] ?? $defval;
        return is_string($x) ? json_decode($x) : $x;
    }

    /** @param string $name
     * @param ?int $value */
    function __save_setting($name, $value, $data = null) {
        $change = false;
        if ($value === null && $data === null) {
            $result = $this->qe("delete from Settings where name=?", $name);
            if (!Dbl::is_error($result)) {
                unset($this->settings[$name], $this->settingTexts[$name]);
                $change = true;
            }
        } else {
            $value = (int) $value;
            $dval = $data;
            if (is_array($dval) || is_object($dval)) {
                $dval = json_encode_db($dval);
            }
            $result = $this->qe("insert into Settings set name=?, value=?, data=? on duplicate key update value=values(value), data=values(data)", $name, $value, $dval);
            if (!Dbl::is_error($result)) {
                $this->settings[$name] = $value;
                $this->settingTexts[$name] = $data;
                $change = true;
            }
        }
        if ($change && str_starts_with($name, "opt.")) {
            $oname = substr($name, 4);
            if ($value === null && $data === null) {
                $this->opt[$oname] = $this->opt_override[$oname] ?? null;
            } else {
                $this->opt[$oname] = $data === null ? $value : $data;
            }
        }
        return $change;
    }

    /** @param string $name
     * @param ?int $value */
    function save_setting($name, $value, $data = null) {
        $change = $this->__save_setting($name, $value, $data);
        if ($change) {
            $this->crosscheck_settings();
            if (str_starts_with($name, "opt.")) {
                $this->crosscheck_options();
            }
            if (str_starts_with($name, "tag_") || $name === "tracks") {
                $this->invalidate_caches(["taginfo" => true, "tracks" => true]);
            }
        }
        return $change;
    }


    /** @param string $name
     * @return mixed */
    function opt($name, $defval = null) {
        return $this->opt[$name] ?? $defval;
    }

    /** @param string $name
     * @param mixed $value */
    function set_opt($name, $value) {
        global $Opt;
        $Opt[$name] = $this->opt[$name] = $value;
    }

    /** @return int */
    function opt_timestamp() {
        if ($this->_opt_timestamp === null) {
            $this->_opt_timestamp = 1;
            foreach ($this->opt["loaded"] ?? [] as $fn) {
                $this->_opt_timestamp = max($this->_opt_timestamp, +@filemtime($fn));
            }
        }
        return $this->_opt_timestamp;
    }


    static function pcseerev_compare($sr1, $sr2) {
        if ($sr1 == $sr2) {
            return 0;
        } else if ($sr1 == self::PCSEEREV_YES || $sr2 == self::PCSEEREV_YES) {
            return $sr1 == self::PCSEEREV_YES ? 1 : -1;
        } else {
            return $sr1 > $sr2 ? 1 : -1;
        }
    }


    // database

    /** @return Dbl_Result */
    function q(/* $qstr, ... */) {
        return Dbl::do_query_on($this->dblink, func_get_args(), 0);
    }
    /** @return Dbl_Result */
    function q_raw(/* $qstr */) {
        return Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_RAW);
    }
    /** @return Dbl_Result */
    function q_apply(/* $qstr, $args */) {
        return Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_APPLY);
    }

    /** @return Dbl_Result */
    function ql(/* $qstr, ... */) {
        return Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_LOG);
    }
    /** @return Dbl_Result */
    function ql_raw(/* $qstr */) {
        return Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_RAW | Dbl::F_LOG);
    }
    /** @return Dbl_Result */
    function ql_apply(/* $qstr, $args */) {
        return Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_APPLY | Dbl::F_LOG);
    }
    /** @return ?Dbl_Result */
    function ql_ok(/* $qstr, ... */) {
        $result = Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_LOG);
        return Dbl::is_error($result) ? null : $result;
    }

    /** @return Dbl_Result */
    function qe(/* $qstr, ... */) {
        return Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_ERROR);
    }
    /** @return Dbl_Result */
    function qe_raw(/* $qstr */) {
        return Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_RAW | Dbl::F_ERROR);
    }
    /** @return Dbl_Result */
    function qe_apply(/* $qstr, $args */) {
        return Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_APPLY | Dbl::F_ERROR);
    }

    /** @return list<list<?string>> */
    function fetch_rows(/* $qstr, ... */) {
        return Dbl::fetch_rows(Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_ERROR));
    }
    /** @return ?list<?string> */
    function fetch_first_row(/* $qstr, ... */) {
        return Dbl::fetch_first_row(Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_ERROR));
    }
    /** @return ?object */
    function fetch_first_object(/* $qstr, ... */) {
        return Dbl::fetch_first_object(Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_ERROR));
    }
    /** @return ?string */
    function fetch_value(/* $qstr, ... */) {
        return Dbl::fetch_value(Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_ERROR));
    }
    /** @return ?int */
    function fetch_ivalue(/* $qstr, ... */) {
        return Dbl::fetch_ivalue(Dbl::do_query_on($this->dblink, func_get_args(), Dbl::F_ERROR));
    }

    function db_error_html($getdb = true) {
        $text = "<p>Database error";
        if ($getdb) {
            $text .= ": " . htmlspecialchars($this->dblink->error);
        }
        return $text . "</p>";
    }

    function db_error_text($getdb = true) {
        $text = "Database error";
        if ($getdb) {
            $text .= ": " . $this->dblink->error;
        }
        return $text;
    }

    function query_error_handler($dblink, $query) {
        $landmark = caller_landmark(1, "/^(?:Dbl::|Conf::q|call_user_func)/");
        if (PHP_SAPI == "cli") {
            fwrite(STDERR, "$landmark: database error: $dblink->error in $query\n");
        } else {
            error_log("$landmark: database error: $dblink->error in $query");
            self::msg_error("<p>" . htmlspecialchars($landmark) . ": database error: " . htmlspecialchars($this->dblink->error) . " in " . Ht::pre_text_wrap($query) . "</p>");
        }
    }


    /** @return Collator */
    function collator() {
        if (!$this->_collator) {
            $this->_collator = new Collator("en_US.utf8");
            $this->_collator->setAttribute(Collator::NUMERIC_COLLATION, Collator::ON);
        }
        return $this->_collator;
    }

    /** @return callable(string,string):int */
    function user_comparator() {
        return function ($a, $b) {
            $sortspec = $this->sort_by_last ? 0312 : 0321;
            $as = Contact::get_sorter($a, $sortspec);
            $bs = Contact::get_sorter($b, $sortspec);
            return $this->collator()->compare($as, $bs);
        };
    }


    // name

    /** @return string */
    function full_name() {
        if ($this->short_name && $this->short_name != $this->long_name) {
            return $this->long_name . " (" . $this->short_name . ")";
        } else {
            return $this->long_name;
        }
    }


    /** @return FormatSpec */
    function format_spec($dtype) {
        if (!isset($this->_formatspec_cache[$dtype])) {
            $o = $this->option_by_id($dtype);
            $spec = $o ? $o->format_spec() : null;
            $this->_formatspec_cache[$dtype] = $spec ? : new FormatSpec;
        }
        return $this->_formatspec_cache[$dtype];
    }

    /** @return ?non-empty-string */
    function docstore() {
        return $this->_docstore;
    }

    /** @return ?S3Document */
    function s3_docstore() {
        global $Now;
        if ($this->_s3_document === false) {
            if ($this->setting_data("s3_bucket")) {
                $opts = [
                    "key" => $this->setting_data("s3_key"),
                    "secret" => $this->setting_data("s3_secret"),
                    "bucket" => $this->setting_data("s3_bucket"),
                    "setting_cache" => $this,
                    "setting_cache_prefix" => "__s3"
                ];
                $this->_s3_document = S3Document::make($opts);
            } else {
                $this->_s3_document = null;
            }
        }
        return $this->_s3_document;
    }


    static function xt_priority($xt) {
        return $xt ? $xt->priority ?? 0 : -PHP_INT_MAX;
    }
    static function xt_priority_compare($xta, $xtb) {
        $ap = self::xt_priority($xta);
        $bp = self::xt_priority($xtb);
        if ($ap == $bp) {
            $ap = $xta ? $xta->__subposition ?? 0 : -PHP_INT_MAX;
            $bp = $xtb ? $xtb->__subposition ?? 0 : -PHP_INT_MAX;
        }
        return $ap < $bp ? 1 : ($ap == $bp ? 0 : -1);
    }
    static function xt_position_compare($xta, $xtb) {
        $ap = $xta->position ?? 0;
        $ap = $ap !== false ? $ap : PHP_INT_MAX;
        $bp = $xtb->position ?? 0;
        $bp = $bp !== false ? $bp : PHP_INT_MAX;
        if ($ap == $bp) {
            if (isset($xta->name)
                && isset($xtb->name)
                && ($namecmp = strcmp($xta->name, $xtb->name)) !== 0) {
                return $namecmp;
            }
            $ap = $xta->__subposition ?? 0;
            $bp = $xtb->__subposition ?? 0;
        }
        return $ap < $bp ? -1 : ($ap == $bp ? 0 : 1);
    }
    /** @param array<string|int,list<object>> &$a
     * @param object $xt */
    static function xt_add(&$a, $name, $xt) {
        $a[$name][] = $xt;
        return true;
    }
    static private function xt_combine($xt1, $xt2) {
        foreach (get_object_vars($xt2) as $k => $v) {
            if (!property_exists($xt1, $k)
                && $k !== "match"
                && $k !== "expand_callback")
                $xt1->$k = $v;
        }
    }
    static function xt_enabled($xt) {
        return $xt && (!isset($xt->disabled) || !$xt->disabled);
    }
    static function xt_disabled($xt) { // XXX delete this
        return !$xt || (isset($xt->disabled) && $xt->disabled);
    }
    static function xt_resolve_require($xt) {
        if ($xt
            && isset($xt->require)
            && !isset(self::$xt_require_resolved[$xt->require])) {
            foreach (expand_includes($xt->require, ["autoload" => true]) as $f) {
                require_once($f);
            }
            self::$xt_require_resolved[$xt->require] = true;
        }
        return $xt && (!isset($xt->disabled) || !$xt->disabled) ? $xt : null;
    }
    function xt_swap_context($context) {
        $old = $this->xt_context;
        $this->xt_context = $context;
        return $old;
    }
    function xt_add_allow_checker($checker) {
        $this->_xt_allow_checkers[] = $checker;
        return count($this->_xt_allow_checkers) - 1;
    }
    function xt_remove_allow_checker($checker_index) {
        unset($this->_xt_allow_checkers[$checker_index]);
    }
    private function xt_check_allow_checkers($e, $xt, $user) {
        foreach ($this->_xt_allow_checkers as $ch) {
            if (($x = call_user_func($ch, $e, $xt, $user, $this)) !== null) {
                return $x;
            }
        }
        return null;
    }
    function xt_check($expr, $xt, Contact $user = null) {
        foreach (is_array($expr) ? $expr : [$expr] as $e) {
            $not = false;
            if (is_string($e)
                && strlen($e) > 0
                && ($e[0] === "!" || $e[0] === "-")) {
                $e = substr($e, 1);
                $not = true;
            }
            if (!is_string($e)) {
                $b = $e;
            } else if ($this->_xt_allow_checkers
                       && ($x = $this->xt_check_allow_checkers($e, $xt, $user)) !== null) {
                $b = $x;
            } else if ($e === "chair" || $e === "admin") {
                $b = !$user || $user->privChair;
            } else if ($e === "manager") {
                $b = !$user || $user->is_manager();
            } else if ($e === "pc") {
                $b = !$user || $user->isPC;
            } else if ($e === "reviewer") {
                $b = !$user || $user->is_reviewer();
            } else if ($e === "view_review") {
                $b = !$user || $user->can_view_some_review();
            } else if ($e === "lead" || $e === "shepherd") {
                $b = $this->has_any_lead_or_shepherd();
            } else if ($e === "empty") {
                $b = $user && $user->is_empty();
            } else if (strpos($e, "::") !== false) {
                self::xt_resolve_require($xt);
                $b = call_user_func($e, $xt, $user, $this);
            } else if (str_starts_with($e, "opt.")) {
                $b = !!$this->opt(substr($e, 4));
            } else if (str_starts_with($e, "setting.")) {
                $b = !!$this->setting(substr($e, 8));
            } else if (str_starts_with($e, "conf.")) {
                $f = substr($e, 5);
                $b = !!$this->$f();
            } else if (str_starts_with($e, "user.")) {
                $f = substr($e, 5);
                $b = !$user || $user->$f();
            } else {
                error_log("unknown xt_check $e");
                $b = !!$this->setting($e);
            }
            if ($not ? $b : !$b) {
                return false;
            }
        }
        return true;
    }
    /** @param object $xt */
    function xt_allowed($xt, Contact $user = null) {
        return $xt && (!isset($xt->allow_if)
                       || $this->xt_check($xt->allow_if, $xt, $user));
    }
    /** @param object $xt */
    static function xt_allow_list($xt) {
        if ($xt && isset($xt->allow_if)) {
            return is_array($xt->allow_if) ? $xt->allow_if : [$xt->allow_if];
        } else {
            return [];
        }
    }
    /** @param object $xt
     * @param ?Contact $user */
    function xt_checkf($xt, $user) {
        if ($this->_xt_allow_callback !== null) {
            return call_user_func($this->_xt_allow_callback, $xt, $user);
        } else {
            return !isset($xt->allow_if)
                || $this->xt_check($xt->allow_if, $xt, $user);
        }
    }
    /** @param array<string,list<object>> $map
     * @param string $name
     * @return ?object */
    function xt_search_name($map, $name, $user, $found = null, $noalias = false) {
        for ($aliases = 0;
             $aliases < 5 && $name !== null && isset($map[$name]);
             ++$aliases) {
            $list = $map[$name];
            $nlist = count($list);
            if ($nlist > 1) {
                usort($list, "Conf::xt_priority_compare");
            }
            $name = null;
            for ($i = 0; $i < $nlist; ++$i) {
                $xt = $list[$i];
                while ($i + 1 < $nlist
                       && isset($xt->merge)
                       && $xt->merge) {
                    ++$i;
                    $overlay = $xt;
                    unset($overlay->merge, $overlay->__subposition);
                    $xt = $list[$i];
                    object_replace_recursive($xt, $overlay);
                    $overlay->priority = -PHP_INT_MAX;
                }
                if (self::xt_priority_compare($xt, $found) <= 0) {
                    if (isset($xt->alias) && is_string($xt->alias) && !$noalias) {
                        $name = $xt->alias;
                        break;
                    } else if ($this->xt_checkf($xt, $user)) {
                        return $xt;
                    }
                }
            }
        }
        return $found;
    }
    /** @param list<object> $factories
     * @param string $name
     * @return list<object> */
    function xt_search_factories($factories, $name, $user, $found = null, $reflags = "", $options = null) {
        $xts = [$found];
        foreach ($factories as $fxt) {
            if (empty($xts)
                ? self::xt_priority_compare($fxt, $found) >= 0
                : self::xt_priority_compare($fxt, $xts[0]) > 0) {
                break;
            }
            if ($fxt->match === ".*") {
                $m = [$name];
            } else if (!preg_match("\1\\A(?:{$fxt->match})\\z\1{$reflags}", $name, $m)) {
                continue;
            }
            if (!$this->xt_checkf($fxt, $user)) {
                continue;
            }
            self::xt_resolve_require($fxt);
            if (!$user) {
                $user = $this->root_user();
            }
            if ($options || isset($fxt->options)) {
                $fxt->options = $options;
            }
            if (isset($fxt->expand_callback)) {
                $r = call_user_func($fxt->expand_callback, $name, $user, $fxt, $m);
            } else {
                $r = (object) ["name" => $name, "match_data" => $m, "options" => $options];
            }
            if (is_object($r)) {
                $r = [$r];
            }
            foreach ($r ? : [] as $xt) {
                self::xt_combine($xt, $fxt);
                $prio = self::xt_priority_compare($xt, $found);
                if ($prio <= 0 && $this->xt_checkf($xt, $user)) {
                    if ($prio < 0) {
                        $xts = [];
                    }
                    $xts[] = $found = $xt;
                }
            }
        }
        return $xts;
    }


    // emoji codes
    function _add_emoji_code($val, $key) {
        if (is_string($val) && str_starts_with($key, ":") && str_ends_with($key, ":")) {
            $this->_emoji_codes->emoji[$key] = $val;
            return true;
        } else {
            return false;
        }
    }
    function emoji_code_map() {
        global $ConfSitePATH;
        if ($this->_emoji_codes === null) {
            $this->_emoji_codes = json_decode(file_get_contents("$ConfSitePATH/scripts/emojicodes.json"));
            $this->_emoji_codes->emoji = (array) $this->_emoji_codes->emoji;
            if (($olist = $this->opt("emojiCodes")))
                expand_json_includes_callback($olist, [$this, "_add_emoji_code"]);
        }
        return $this->_emoji_codes->emoji;
    }


    /** @param int $id
     * @return ?PaperOption */
    function option_by_id($id) {
        return $this->paper_opts->option_by_id($id);
    }

    /** @param int $id
     * @return PaperOption */
    function checked_option_by_id($id) {
        return $this->paper_opts->checked_option_by_id($id);
    }


    /** @return array<int,Formula> */
    function named_formulas() {
        if ($this->_defined_formulas === null) {
            $this->_defined_formulas = [];
            if ($this->setting("formulas")) {
                $result = $this->q("select * from Formula");
                while ($result && ($f = Formula::fetch($this, $result))) {
                    $this->_defined_formulas[$f->formulaId] = $f;
                }
                Dbl::free($result);
                uasort($this->_defined_formulas, function ($a, $b) {
                    return strnatcasecmp($a->name, $b->name);
                });
            }
        }
        return $this->_defined_formulas;
    }

    /** @param array<int,Formula> $formula_map */
    function replace_named_formulas($formula_map) {
        $this->_defined_formulas = $formula_map;
        $this->_abbrev_matcher = null;
    }

    /** @return ?Formula */
    function find_named_formula($text) {
        return $this->abbrev_matcher()->find1($text, self::FSRCH_FORMULA);
    }

    /** @return array<int,Formula> */
    function viewable_named_formulas(Contact $user) {
        return array_filter($this->named_formulas(), function ($f) use ($user) {
            return $user->can_view_formula($f);
        });
    }


    /** @return array<int,string> */
    function decision_map() {
        if ($this->_decisions === null) {
            $dmap = [];
            if (($j = $this->settingTexts["outcome_map"] ?? null)
                && ($j = json_decode($j, true))
                && is_array($j)) {
                $dmap = $j;
            }
            $dmap[0] = "Unspecified";
            $this->_decisions = $dmap;
            uksort($this->_decisions, function ($ka, $kb) use ($dmap) {
                if ($ka == 0 || $kb == 0) {
                    return $ka == 0 ? -1 : 1;
                } else if (($ka > 0) !== ($kb > 0)) {
                    return $ka > 0 ? 1 : -1;
                } else {
                    return strcasecmp($dmap[$ka], $dmap[$kb]);
                }
            });
        }
        return $this->_decisions;
    }

    /** @param int $dnum
     * @return string|false */
    function decision_name($dnum) {
        return ($this->decision_map())[$dnum] ?? false;
    }

    /** @param string $dname
     * @return string|false */
    static function decision_name_error($dname) {
        $dname = simplify_whitespace($dname);
        if ((string) $dname === "") {
            return "Empty decision name.";
        } else if (preg_match('/\A(?:yes|no|any|none|unknown|unspecified|undecided|\?)\z/i', $dname)) {
            return "Decision name “{$dname}” is reserved.";
        } else {
            return false;
        }
    }

    /** @return AbbreviationMatcher<int> */
    function decision_matcher() {
        if ($this->_decision_matcher === null) {
            $this->_decision_matcher = new AbbreviationMatcher;
            foreach ($this->decision_map() as $d => $dname) {
                $this->_decision_matcher->add($dname, $d);
            }
            foreach (["none", "unknown", "undecided", "?"] as $dname) {
                $this->_decision_matcher->add($dname, 0);
            }
        }
        return $this->_decision_matcher;
    }

    /** @param string $dname
     * @return list<int> */
    function find_all_decisions($dname) {
        return $this->decision_matcher()->find_all($dname);
    }

    /** @param int $dnum
     * @return array{string,string} */
    function decision_status_info($dnum) {
        if ($this->_decision_status_info === null) {
            $this->_decision_status_info = [];
        }
        $s = $this->_decision_status_info[$dnum] ?? null;
        if (!$s) {
            $decclass = $dnum > 0 ? "pstat_decyes" : "pstat_decno";
            if (($decname = $this->decision_name($dnum))) {
                if (($trdecname = preg_replace('/[^-.\w]/', '', $decname)) !== "") {
                    $decclass .= " pstat_" . strtolower($trdecname);
                }
            } else {
                $decname = "Unknown decision #" . $dnum;
            }
            $s = $this->_decision_status_info[$dnum] = [$decclass, $decname];
        }
        return $s;
    }


    /** @return bool */
    function has_topics() {
        return ($this->settings["has_topics"] ?? 0) !== 0;
    }

    /** @return TopicSet */
    function topic_set() {
        if ($this->_topic_set === null) {
            $this->_topic_set = new TopicSet($this);
        }
        return $this->_topic_set;
    }

    /** @return AbbreviationMatcher<int> */
    function topic_abbrev_matcher() {
        return $this->topic_set()->abbrev_matcher();
    }

    function invalidate_topics() {
        $this->_topic_set = null;
        $this->paper_opts->invalidate_intrinsic_option(PaperOption::TOPICSID);
    }


    /** @return Conflict */
    function conflict_types() {
        if ($this->_conflict_types === null) {
            $this->_conflict_types = new Conflict($this);
        }
        return $this->_conflict_types;
    }


    const FSRCH_OPTION = 1;
    const FSRCH_REVIEW = 2;
    const FSRCH_FORMULA = 4;

    /** @return AbbreviationMatcher<PaperOption|ReviewField|Formula> */
    function abbrev_matcher() {
        if (!$this->_abbrev_matcher) {
            $this->_abbrev_matcher = new AbbreviationMatcher;
            $this->_abbrev_matcher->set_priority(self::FSRCH_FORMULA, -1);
            // XXX exposes invisible paper options, review fields
            $this->paper_opts->populate_abbrev_matcher($this->_abbrev_matcher);
            foreach ($this->all_review_fields() as $f) {
                $this->_abbrev_matcher->add($f->name, $f, self::FSRCH_REVIEW);
            }
            foreach ($this->named_formulas() as $f) {
                if ($f->name) {
                    $this->_abbrev_matcher->add($f->name, $f, self::FSRCH_FORMULA);
                }
            }
        }
        return $this->_abbrev_matcher;
    }

    /** @return list<PaperOption|ReviewField|Formula> */
    function find_all_fields($text, $tflags = 0) {
        return $this->abbrev_matcher()->find_all($text, $tflags);
    }


    function review_form_json() {
        $x = $this->settingTexts["review_form"] ?? null;
        if (is_string($x)) {
            $x = $this->settingTexts["review_form"] = json_decode($x);
        }
        return is_object($x) ? $x : null;
    }

    /** @return ReviewForm */
    function review_form() {
        if (!$this->_review_form_cache) {
            $this->_review_form_cache = new ReviewForm($this->review_form_json(), $this);
        }
        return $this->_review_form_cache;
    }

    /** @return array<string,ReviewField> */
    function all_review_fields() {
        return $this->review_form()->all_fields();
    }
    /** @param string $fid
     * @return ?ReviewField */
    function review_field($fid) {
        return $this->review_form()->field($fid);
    }
    /** @param string $text
     * @return ?ReviewField */
    function find_review_field($text) {
        return $this->abbrev_matcher()->find1($text, self::FSRCH_REVIEW);
    }
    /** @param string $fid
     * @return ReviewField */
    function checked_review_field($fid) {
        if (($f = $this->review_form()->field($fid))) {
            return $f;
        } else {
            throw new Exception("Unknown review field “{$fid}”");
        }
    }


    /** @return TagMap */
    function tags() {
        if (!$this->_taginfo) {
            $this->_taginfo = TagMap::make($this);
        }
        return $this->_taginfo;
    }


    /** @return bool */
    function has_tracks() {
        return $this->_tracks !== null;
    }

    /** @return bool */
    function has_track_tags() {
        return $this->_track_tags !== null;
    }

    /** @return list<string> */
    function track_tags() {
        return $this->_track_tags ?? [];
    }

    /** @return ?string */
    function permissive_track_tag_for(Contact $user, $perm) {
        foreach ($this->_tracks ? : [] as $t => $tr) {
            if ($user->has_permission($tr[$perm])) {
                return $t;
            }
        }
        return null;
    }

    /** @return bool */
    function check_tracks(PaperInfo $prow, Contact $user, $ttype) {
        $unmatched = true;
        if ($this->_tracks) {
            foreach ($this->_tracks as $t => $tr) {
                if ($t === "_" ? $unmatched : $prow->has_tag($t)) {
                    $unmatched = false;
                    if ($user->has_permission($tr[$ttype])) {
                        return true;
                    }
                }
            }
        }
        return $unmatched;
    }

    /** @return bool */
    function check_required_tracks(PaperInfo $prow, Contact $user, $ttype) {
        if ($this->_track_sensitivity & (1 << $ttype)) {
            $unmatched = true;
            foreach ($this->_tracks as $t => $tr) {
                if ($t === "_" ? $unmatched : $prow->has_tag($t)) {
                    $unmatched = false;
                    if ($tr[$ttype] && $user->has_permission($tr[$ttype])) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /** @return bool */
    function check_admin_tracks(PaperInfo $prow, Contact $user) {
        return $this->check_required_tracks($prow, $user, Track::ADMIN);
    }

    /** @return bool */
    function check_default_track(Contact $user, $ttype) {
        return !$this->_tracks
            || $user->has_permission($this->_tracks["_"][$ttype]);
    }

    /** @return bool */
    function check_any_tracks(Contact $user, $ttype) {
        if ($this->_tracks) {
            foreach ($this->_tracks as $t => $tr) {
                if (($ttype === Track::VIEW
                     || $user->has_permission($tr[Track::VIEW]))
                    && $user->has_permission($tr[$ttype])) {
                    return true;
                }
            }
        }
        return !$this->_tracks;
    }

    /** @return bool */
    function check_any_admin_tracks(Contact $user) {
        if ($this->_track_sensitivity & Track::BITS_ADMIN) {
            foreach ($this->_tracks as $t => $tr) {
                if ($tr[Track::ADMIN]
                    && $user->has_permission($tr[Track::ADMIN])) {
                    return true;
                }
            }
        }
        return false;
    }

    /** @return bool */
    function check_all_tracks(Contact $user, $ttype) {
        if ($this->_tracks) {
            foreach ($this->_tracks as $t => $tr) {
                if (!(($ttype === Track::VIEW
                       || $user->has_permission($tr[Track::VIEW]))
                      && $user->has_permission($tr[$ttype]))) {
                    return false;
                }
            }
        }
        return true;
    }

    /** @return bool */
    function check_track_sensitivity($ttype) {
        return ($this->_track_sensitivity & (1 << $ttype)) !== 0;
    }
    /** @return bool */
    function check_track_view_sensitivity() {
        return ($this->_track_sensitivity & Track::BITS_VIEW) !== 0;
    }
    /** @return bool */
    function check_track_review_sensitivity() {
        return ($this->_track_sensitivity & Track::BITS_REVIEW) !== 0;
    }
    /** @return bool */
    function check_track_admin_sensitivity() {
        return ($this->_track_sensitivity & Track::BITS_ADMIN) !== 0;
    }

    /** @return bool */
    function check_paper_track_sensitivity(PaperInfo $prow, $ttype) {
        if ($this->_track_sensitivity & (1 << $ttype)) {
            $unmatched = true;
            foreach ($this->_tracks as $t => $tr) {
                if ($t === "_" ? $unmatched : $prow->has_tag($t)) {
                    $unmatched = false;
                    if ($tr[$ttype]) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /** @return ?string */
    function track_permission($tag, $ttype) {
        if ($this->_tracks) {
            foreach ($this->_tracks as $t => $tr) {
                if (strcasecmp($t, $tag) === 0) {
                    return $tr[$ttype];
                }
            }
        }
        return null;
    }

    /** @return int */
    function dangerous_track_mask(Contact $user) {
        $m = 0;
        if ($this->_tracks && $user->contactTags) {
            foreach ($this->_tracks as $t => $tr) {
                foreach ($tr as $i => $perm) {
                    if ($perm
                        && $perm[0] === "-"
                        && !$user->has_permission($perm)) {
                        $m |= 1 << $i;
                    }
                }
            }
        }
        return $m;
    }


    /** @return bool */
    function has_rounds() {
        return count($this->rounds) > 1;
    }

    /** @return list<string> */
    function round_list() {
        return $this->rounds;
    }

    /** @return bool */
    function round0_defined() {
        return isset($this->defined_round_list()[0]);
    }

    /** @return array<int,string> */
    function defined_round_list() {
        if ($this->_defined_rounds === null) {
            $dl = [];
            foreach ($this->rounds as $i => $rname) {
                if (!$i || $rname !== ";") {
                    foreach (self::$review_deadlines as $rd) {
                        if (($dl[$i] = $this->settings[$rd . ($i ? "_$i" : "")] ?? 0))
                            break;
                    }
                }
            }
            if (!$dl[0]
                && !$this->fetch_ivalue("select exists (select * from PaperReview where reviewRound=0)")) {
                unset($dl[0]);
            }
            $r = [];
            foreach ($this->rounds as $i => $rname) {
                if (isset($dl[$i])) {
                    $r[$i] = $i ? $rname : "unnamed";
                }
            }
            uksort($r, function ($a, $b) use ($r, $dl) {
                $adl = $dl[$a] ?? null;
                $bdl = $dl[$b] ?? null;
                if ($adl && $bdl && $adl != $bdl) {
                    return $adl < $bdl ? -1 : 1;
                } else if (!$adl != !$bdl) {
                    return $adl ? -1 : 1;
                } else {
                    return strcasecmp($a ? $r[$a] : "~", $b ? $r[$b] : "~");
                }
            });
            $this->_defined_rounds = $r;
        }
        return $this->_defined_rounds;
    }

    /** @param int $roundno
     * @return string */
    function round_name($roundno) {
        if ($roundno > 0) {
            if (($rname = $this->rounds[$roundno] ?? null) && $rname !== ";") {
                return $rname;
            }
            error_log($this->dbname . ": round #$roundno undefined");
        }
        return "";
    }

    /** @param int $roundno
     * @return string */
    function round_suffix($roundno) {
        if ($roundno > 0
            && ($rname = $this->rounds[$roundno] ?? null)
            && $rname !== ";") {
            return "_$rname";
        }
        return "";
    }

    /** @param string $rname
     * @return string|false */
    static function round_name_error($rname) {
        if ((string) $rname === "") {
            return "Empty round name.";
        } else if (!preg_match('/\A[a-zA-Z](?:|[-a-zA-Z0-9]*[a-zA-Z0-9])\z/', $rname)) {
            return "Round names must start with a letter and contain only letters, numbers, and dashes.";
        } else if (preg_match('/\A(?:none|any|all|default|unnamed|.*response|response.*|draft.*|pri(?:mary)|sec(?:ondary)|opt(?:ional)|pc(?:review)|ext(?:ernal)|meta(?:review))\z/i', $rname)) {
            return "Round name $rname is reserved.";
        } else {
            return false;
        }
    }

    /** @param ?string $rname
     * @return string|false */
    function sanitize_round_name($rname) {
        if ($rname === null) {
            return (string) ($this->settingTexts["rev_roundtag"] ?? null);
        } else if ($rname === ""
                   || !strcasecmp($rname, "(none)")
                   || !strcasecmp($rname, "none")
                   || !strcasecmp($rname, "unnamed")) {
            return "";
        } else if (self::round_name_error($rname)) {
            return false;
        } else {
            return $rname;
        }
    }

    /** @param bool $external
     * @return string */
    function assignment_round_option($external) {
        if (!$external
            || ($x = $this->settingTexts["extrev_roundtag"] ?? null) === null) {
            $x = (string) ($this->settingTexts["rev_roundtag"] ?? null);
        }
        return $x === "" ? "unnamed" : $x;
    }

    /** @param bool $external
     * @return int */
    function assignment_round($external) {
        return $this->round_number($this->assignment_round_option($external), false);
    }

    /** @param string $rname
     * @param bool $add
     * @return int|false */
    function round_number($rname, $add) {
        if (!$rname || !strcasecmp($rname, "none") || !strcasecmp($rname, "unnamed")) {
            return 0;
        }
        for ($i = 1; $i != count($this->rounds); ++$i) {
            if (!strcasecmp($this->rounds[$i], $rname)) {
                return $i;
            }
        }
        if ($add && !self::round_name_error($rname)) {
            $rtext = $this->setting_data("tag_rounds") ?? "";
            $rtext = ($rtext ? "$rtext$rname " : " $rname ");
            $this->__save_setting("tag_rounds", 1, $rtext);
            $this->crosscheck_round_settings();
            return $this->round_number($rname, false);
        } else {
            return false;
        }
    }

    /** @return array<string,string> */
    function round_selector_options($isexternal) {
        $opt = [];
        foreach ($this->defined_round_list() as $rname) {
            $opt[$rname] = $rname;
        }
        if (($isexternal === null || $isexternal === true)
            && ($r = $this->settingTexts["rev_roundtag"] ?? null) !== null
            && !isset($opt[$r ? : "unnamed"])) {
            $opt[$r ? : "unnamed"] = $r ? : "unnamed";
        }
        if (($isexternal === null || $isexternal === false)
            && ($r = $this->settingTexts["extrev_roundtag"] ?? null) !== null
            && !isset($opt[$r ? : "unnamed"])) {
            $opt[$r ? : "unnamed"] = $r ? : "unnamed";
        }
        return $opt;
    }

    /** @param string $name
     * @param ?int $round */
    function round_setting($name, $round, $defval = null) {
        if ($this->_round_settings !== null
            && $round !== null
            && isset($this->_round_settings[$round])
            && isset($this->_round_settings[$round]->$name)) {
            return $this->_round_settings[$round]->$name;
        } else {
            return $this->settings[$name] ?? $defval;
        }
    }



    /** @return list<ResponseRound> */
    function resp_rounds() {
        if ($this->_resp_rounds === null) {
            $this->_resp_rounds = [];
            $x = $this->settingTexts["resp_rounds"] ?? "1";
            foreach (explode(" ", $x) as $i => $rname) {
                $r = new ResponseRound;
                $r->number = $i;
                $r->name = $rname;
                $isuf = $i ? "_$i" : "";
                $r->open = $this->settings["resp_open$isuf"] ?? null;
                $r->done = $this->settings["resp_done$isuf"] ?? null;
                $r->grace = $this->settings["resp_grace$isuf"] ?? null;
                $r->words = $this->settings["resp_words$isuf"] ?? 500;
                if (($s = $this->settingTexts["resp_search$isuf"] ?? null)) {
                    $r->search = new PaperSearch($this->root_user(), $s);
                }
                $this->_resp_rounds[] = $r;
            }
        }
        return $this->_resp_rounds;
    }

    /** @param int $rnum
     * @return string */
    function resp_round_name($rnum) {
        $rrd = ($this->resp_rounds())[$rnum] ?? null;
        return $rrd ? $rrd->name : "1";
    }

    /** @param int $rnum
     * @return string */
    function resp_round_text($rnum) {
        $rname = $this->resp_round_name($rnum);
        return $rname == "1" ? "" : $rname;
    }

    /** @param string $rname
     * @return string|bool */
    static function resp_round_name_error($rname) {
        return self::round_name_error($rname);
    }

    /** @param string $rname
     * @return int|false */
    function resp_round_number($rname) {
        if (!$rname
            || $rname === 1
            || $rname === "1"
            || $rname === true
            || strcasecmp($rname, "none") === 0) {
            return 0;
        }
        foreach ($this->resp_rounds() as $rrd) {
            if (strcasecmp($rname, $rrd->name) === 0) {
                return $rrd->number;
            }
        }
        return false;
    }


    /** @return ?TextFormat */
    function format_info($format) {
        if ($this->_format_info === null) {
            $this->_format_info = [];
            if (!isset($this->opt["formatInfo"])) {
                // ok
            } else if (is_array($this->opt["formatInfo"])) {
                $this->_format_info = $this->opt["formatInfo"];
            } else if (is_string($this->opt["formatInfo"])) {
                $this->_format_info = json_decode($this->opt["formatInfo"], true);
            }
            foreach ($this->_format_info as $format => &$fi) {
                $fi = new TextFormat($format, $fi);
            }
        }
        if ($format === null) {
            $format = $this->default_format;
        }
        return $this->_format_info[$format] ?? null;
    }

    /** @param ?int $format
     * @param ?string $text
     * @return int */
    function check_format($format, $text = null) {
        if ($format === null) {
            $format = $this->default_format;
        }
        if ($format
            && $text !== null
            && ($f = $this->format_info($format))
            && $f->simple_regex
            && preg_match($f->simple_regex, $text)) {
            $format = 0;
        }
        return $format;
    }


    function saved_searches() {
        $ss = [];
        foreach ($this->settingTexts as $k => $v) {
            if (substr($k, 0, 3) === "ss:" && ($v = json_decode($v))) {
                $ss[substr($k, 3)] = $v;
            }
        }
        return $ss;
    }


    // users

    /** @return bool */
    function external_login() {
        return isset($this->opt["ldapLogin"]) || isset($this->opt["httpAuthLogin"]);
    }

    /** @return bool */
    function allow_user_self_register() {
        return !$this->external_login()
            && !$this->opt("disableNewUsers")
            && !$this->opt("disableNonPC");
    }

    /** @return Author */
    function default_site_contact() {
        $result = $this->ql("select firstName, lastName, email, affiliation from ContactInfo where roles!=0 and (roles&" . (Contact::ROLE_CHAIR | Contact::ROLE_ADMIN) . ")!=0 order by (roles&" . Contact::ROLE_CHAIR . ") desc, contactId asc limit 1");
        $chair = $result->fetch_object("Author");
        Dbl::free($result);
        return $chair;
    }

    /** @return Contact */
    function site_contact() {
        if (!$this->_site_contact) {
            $args = [
                "fullName" => $this->opt("contactName"),
                "email" => $this->opt("contactEmail"),
                "isChair" => 1, "isPC" => 1, "is_site_contact" => 1,
                "contactTags" => null
            ];
            if ((!$args["email"] || $args["email"] === "you@example.com")
                && ($row = $this->default_site_contact())) {
                $this->set_opt("defaultSiteContact", true);
                unset($args["fullName"]);
                $args["email"] = $row->email;
                $args["firstName"] = $row->firstName;
                $args["lastName"] = $row->lastName;
            }
            $this->_site_contact = new Contact($args, $this);
        }
        return $this->_site_contact;
    }

    /** @return Contact */
    function root_user() {
        if (!$this->_root_user) {
            $this->_root_user = new Contact([
                "email" => "rootuser",
                "isChair" => 1, "isPC" => 1, "is_site_contact" => 1,
                "contactTags" => null
            ], $this);
        }
        return $this->_root_user;
    }

    /** @param int $id
     * @return ?Contact */
    function user_by_id($id) {
        $result = $this->qe("select * from ContactInfo where contactId=?", $id);
        $acct = Contact::fetch($result, $this);
        Dbl::free($result);
        return $acct;
    }

    /** @return array<int,Contact> */
    function sliced_users(Contact $firstu) {
        $a = [$firstu->contactId => $firstu];
        if (!$this->_unslice) {
            $this->_unslice = true;
            foreach ($this->_user_cache ?? $this->_pc_users_cache ?? [] as $id => $u) {
                if ($u && $u->_slice)
                    $a[$id] = $u;
            }
        }
        return $a;
    }

    /** @param int $id */
    function request_cached_user_by_id($id) {
        global $Me;
        if ($id > 0
            && (!$Me || $Me->contactId !== $id)
            && !array_key_exists($id, $this->_user_cache ?? $this->_pc_users_cache ?? [])) {
            $this->_user_cache_missing[] = $id;
        }
    }

    /** @param int $id
     * @return ?Contact */
    function cached_user_by_id($id) {
        global $Me;
        $id = (int) $id;
        if ($id === 0) {
            return null;
        } else if ($id !== 0 && $Me && $Me->contactId === $id) {
            return $Me;
        }
        $this->_user_cache = $this->_user_cache ?? $this->pc_users();
        if (array_key_exists($id, $this->_user_cache)) {
            return $this->_user_cache[$id];
        } else {
            $this->_user_cache_missing[] = $id;
            $reqids = [];
            foreach ($this->_user_cache_missing as $reqid) {
                if (!array_key_exists($reqid, $this->_user_cache)) {
                    $this->_user_cache[$reqid] = null;
                    $reqids[] = $reqid;
                }
            }
            if (!empty($reqids)) {
                $result = $this->qe("select " . $this->_cached_user_query() . " from ContactInfo where contactId?a", $reqids);
                while (($u = Contact::fetch($result, $this))) {
                    $this->_user_cache[$u->contactId] = $u;
                    if ($this->_user_email_cache) {
                        $this->_user_email_cache[strtolower($u->email)] = $u;
                    }
                }
                Dbl::free($result);
            }
            $this->_user_cache_missing = null;
            return $this->_user_cache[$id] ?? null;
        }
    }

    /** @param string $email
     * @return ?Contact */
    function user_by_email($email) {
        $acct = null;
        if (($email = trim((string) $email)) !== "") {
            $result = $this->qe("select * from ContactInfo where email=?", $email);
            $acct = Contact::fetch($result, $this);
            Dbl::free($result);
        }
        return $acct;
    }

    /** @param string $email
     * @return Contact */
    function checked_user_by_email($email) {
        $acct = $this->user_by_email($email);
        if (!$acct) {
            throw new Exception("Contact::checked_user_by_email($email) failed");
        }
        return $acct;
    }

    /** @param string $email
     * @return false|int */
    function user_id_by_email($email) {
        $result = $this->qe("select contactId from ContactInfo where email=?", trim($email));
        $row = $result->fetch_row();
        Dbl::free($result);
        return $row ? (int) $row[0] : false;
    }

    /** @param string $email
     * @return ?Contact */
    function cached_user_by_email($email) {
        global $Me;
        $lemail = strtolower($email);
        if ($lemail && $Me && strcasecmp($Me->email, $lemail) === 0) {
            return $Me;
        }
        if ($this->_user_email_cache === null) {
            $this->_user_email_cache = [];
            foreach ($this->_user_cache ?? $this->pc_users() as $u) {
                $this->_user_email_cache[strtolower($u->email)] = $u;
            }
        }
        if (array_key_exists($lemail, $this->_user_email_cache)) {
            return $this->_user_email_cache[$lemail];
        } else {
            $u = $this->_user_email_cache[$lemail] = $this->user_by_email($lemail);
            if ($u) {
                $this->_user_cache[$u->contactId] = $u;
            }
            return $u;
        }
    }

    private function _cached_user_query() {
        if ($this->_pc_members_fully_loaded) {
            return "*";
        } else {
            return "contactId, firstName, lastName, unaccentedName, affiliation, email, roles, contactTags, disabled, 1 _slice";
        }
    }


    /** @return array<int,Contact> */
    function pc_members() {
        if ($this->_pc_members_cache === null) {
            $result = $this->q("select " . $this->_cached_user_query() . " from ContactInfo where roles!=0 and (roles&" . Contact::ROLE_PCLIKE . ")!=0");
            $pc = $by_name_text = [];
            $expected_by_name_count = 0;
            $this->_pc_tags_cache = ["pc" => "pc"];
            while ($result && ($u = Contact::fetch($result, $this))) {
                $pc[$u->contactId] = $u;
                if (($name = $u->name()) !== "") {
                    $by_name_text[$name][] = $u;
                    $expected_by_name_count += 1;
                }
                if ($u->contactTags) {
                    foreach (explode(" ", $u->contactTags) as $t) {
                        list($tag, $value) = Tagger::unpack($t);
                        if ($tag) {
                            $this->_pc_tags_cache[strtolower($tag)] = $tag;
                        }
                    }
                }
            }
            Dbl::free($result);

            if ($expected_by_name_count > count($by_name_text)) {
                foreach ($by_name_text as $us) {
                    if (count($us) > 1) {
                        $npcus = 0;
                        foreach ($us as $u) {
                            $npcus += ($u->roles & Contact::ROLE_PC ? 1 : 0);
                        }
                        foreach ($us as $u) {
                            if ($npcus > 1 || ($u->roles & Contact::ROLE_PC) == 0) {
                                $u->nameAmbiguous = true;
                            }
                        }
                    }
                }
            }

            uasort($pc, $this->user_comparator());
            $this->_pc_users_cache = $pc;

            $this->_pc_members_cache = $this->_pc_chairs_cache = [];
            foreach ($pc as $u) {
                if ($u->roles & Contact::ROLE_PC) {
                    $u->sort_position = count($this->_pc_members_cache);
                    $this->_pc_members_cache[$u->contactId] = $u;
                }
                if ($u->roles & Contact::ROLE_CHAIR) {
                    $this->_pc_chairs_cache[$u->contactId] = $u;
                }
            }

            $this->collator()->asort($this->_pc_tags_cache);
        }
        return $this->_pc_members_cache;
    }

    /** @return array<int,Contact> */
    function pc_chairs() {
        if ($this->_pc_chairs_cache === null) {
            $this->pc_members();
        }
        return $this->_pc_chairs_cache;
    }

    /** @return array<int,Contact> */
    function full_pc_members() {
        if (!$this->_pc_members_fully_loaded) {
            if ($this->_pc_members_cache !== null) {
                $result = $this->q("select * from ContactInfo where roles!=0 and (roles&" . Contact::ROLE_PCLIKE . ")!=0");
                while ($result && ($u = $result->fetch_object())) {
                    if (($pc = $this->_pc_users_cache[$u->contactId] ?? null))
                        $pc->unslice_using($u);
                }
                Dbl::free($result);
            }
            $this->_user_cache = $this->_user_email_cache = null;
            $this->_pc_members_fully_loaded = true;
        }
        return $this->pc_members();
    }

    /** @param int $cid
     * @return ?Contact */
    function pc_member_by_id($cid) {
        return ($this->pc_members())[$cid] ?? null;
    }

    /** @param string $email
     * @return ?Contact */
    function pc_member_by_email($email) {
        foreach ($this->pc_members() as $p) {
            if (strcasecmp($p->email, $email) == 0)
                return $p;
        }
        return null;
    }

    /** @return array<int,Contact> */
    function pc_users() {
        if ($this->_pc_users_cache === null) {
            $this->pc_members();
        }
        return $this->_pc_users_cache;
    }

    /** @param int $cid
     * @return ?Contact */
    function pc_user_by_id($cid) {
        return ($this->pc_users())[$cid] ?? null;
    }

    /** @return list<string> */
    function pc_tags() {
        if ($this->_pc_tags_cache === null) {
            $this->pc_members();
        }
        return array_values($this->_pc_tags_cache);
    }

    /** @return bool */
    function pc_tag_exists($tag) {
        if ($this->_pc_tags_cache === null) {
            $this->pc_members();
        }
        return isset($this->_pc_tags_cache[strtolower($tag)]);
    }

    /** @return array<string,Contact> */
    function pc_completion_map() {
        $map = $bylevel = [];
        foreach ($this->pc_users() as $pc) {
            if (!$pc->is_disabled()) {
                foreach ($pc->completion_items() as $k => $level) {
                    if (!isset($bylevel[$k])
                        || $bylevel[$k] < $level
                        || ($map[$k] ?? null) === $pc) {
                        $map[$k] = $pc;
                        $bylevel[$k] = $level;
                    } else {
                        unset($map[$k]);
                    }
                }
            }
        }
        return $map;
    }

    /** @return list<string> */
    function viewable_user_tags(Contact $viewer) {
        if ($viewer->privChair) {
            return $this->pc_tags();
        } else if ($viewer->can_view_user_tags()) {
            $t = " " . join("#0 ", $this->pc_tags()) . "#0";
            $t = $this->tags()->censor(TagMap::CENSOR_VIEW, $t, $viewer, null);
            return explode("#0 ", substr($t, 1, -2));
        } else {
            return [];
        }
    }


    // contactdb

    /** @return ?\mysqli */
    function contactdb() {
        if ($this->_cdb === false) {
            $this->_cdb = null;
            if (($dsn = $this->opt("contactdb_dsn")))
                list($this->_cdb, $dbname) = Dbl::connect_dsn($dsn);
        }
        return $this->_cdb;
    }

    /** @return ?Contact */
    private function contactdb_user_by_key($key, $value) {
        if (($cdb = $this->contactdb())) {
            $q = "select ContactInfo.*, roles, activity_at";
            $qv = [];
            if (($confid = $this->opt("contactdb_confid"))) {
                $q .= ", ? confid from ContactInfo left join Roles on (Roles.contactDbId=ContactInfo.contactDbId and Roles.confid=?)";
                array_push($qv, $confid, $confid);
            } else {
                $q .= ", Conferences.confid from ContactInfo left join Conferences on (Conferences.`dbname`=?) left join Roles on (Roles.contactDbId=ContactInfo.contactDbId and Roles.confid=Conferences.confid)";
                $qv[] = $this->dbname;
            }
            $qv[] = $value;
            $result = Dbl::ql_apply($cdb, "$q where ContactInfo.$key=?", $qv);
            $acct = Contact::fetch($result, $this);
            Dbl::free($result);
            return $acct;
        } else {
            return null;
        }
    }

    /** @return ?Contact */
    function contactdb_user_by_email($email) {
        return $this->contactdb_user_by_key("email", $email);
    }

    /** @return ?Contact */
    function contactdb_user_by_id($id) {
        return $this->contactdb_user_by_key("contactDbId", $id);
    }


    // session data

    /** @param string $name */
    function session($name, $defval = null) {
        if (isset($_SESSION[$this->dsn])
            && isset($_SESSION[$this->dsn][$name])) {
            return $_SESSION[$this->dsn][$name];
        } else {
            return $defval;
        }
    }

    /** @param string $name */
    function save_session($name, $value) {
        if ($value !== null) {
            if (empty($_SESSION)){
                ensure_session();
            }
            $_SESSION[$this->dsn][$name] = $value;
        } else if (isset($_SESSION[$this->dsn])) {
            unset($_SESSION[$this->dsn][$name]);
            if (empty($_SESSION[$this->dsn])) {
                unset($_SESSION[$this->dsn]);
            }
        }
    }


    // update the 'papersub' setting: are there any submitted papers?
    function update_papersub_setting($adding) {
        if ($this->setting("no_papersub", 0) > 0 ? $adding >= 0 : $adding <= 0) {
            $this->qe("delete from Settings where name='no_papersub'");
            $this->qe("insert into Settings (name, value) select 'no_papersub', 1 from dual where exists (select * from Paper where timeSubmitted>0) = 0");
            $this->settings["no_papersub"] = (int) $this->fetch_ivalue("select value from Settings where name='no_papersub'");
        }
    }

    function update_paperacc_setting($adding) {
        if ($this->setting("paperacc", 0) <= 0 ? $adding >= 0 : $adding <= 0) {
            $this->qe_raw("insert into Settings (name, value) select 'paperacc', exists (select * from Paper where outcome>0 and timeSubmitted>0) on duplicate key update value=values(value)");
            $this->settings["paperacc"] = (int) $this->fetch_ivalue("select value from Settings where name='paperacc'");
        }
    }

    function update_rev_tokens_setting($adding) {
        if ($this->setting("rev_tokens", 0) === -1)
            $adding = 0;
        if ($this->setting("rev_tokens", 0) <= 0 ? $adding >= 0 : $adding <= 0) {
            $this->qe_raw("insert into Settings (name, value) select 'rev_tokens', exists (select * from PaperReview where reviewToken!=0) on duplicate key update value=values(value)");
            $this->settings["rev_tokens"] = (int) $this->fetch_ivalue("select value from Settings where name='rev_tokens'");
        }
    }

    function update_paperlead_setting($adding) {
        if ($this->setting("paperlead", 0) <= 0 ? $adding >= 0 : $adding <= 0) {
            $this->qe_raw("insert into Settings (name, value) select 'paperlead', exists (select * from Paper where leadContactId>0 or shepherdContactId>0) on duplicate key update value=values(value)");
            $this->settings["paperlead"] = (int) $this->fetch_ivalue("select value from Settings where name='paperlead'");
        }
    }

    function update_papermanager_setting($adding) {
        if ($this->setting("papermanager", 0) <= 0 ? $adding >= 0 : $adding <= 0) {
            $this->qe_raw("insert into Settings (name, value) select 'papermanager', exists (select * from Paper where managerContactId>0) on duplicate key update value=values(value)");
            $this->settings["papermanager"] = (int) $this->fetch_ivalue("select value from Settings where name='papermanager'");
        }
    }

    function update_metareviews_setting($adding) {
        if ($this->setting("metareviews", 0) <= 0 ? $adding >= 0 : $adding <= 0) {
            $this->qe_raw("insert into Settings (name, value) select 'metareviews', exists (select * from PaperReview where reviewType=" . REVIEW_META . ") on duplicate key update value=values(value)");
            $this->settings["metareviews"] = (int) $this->fetch_ivalue("select value from Settings where name='metareviews'");
        }
    }

    /** @param null|int|list<int>|PaperInfo $paper */
    function update_autosearch_tags($paper = null) {
        if ((!$this->setting("tag_autosearch") && !$this->opt("definedTags"))
            || !$this->tags()->has_autosearch
            || $this->_updating_autosearch_tags) {
            return;
        }
        $csv = ["paper,tag"];
        if ($paper === null) {
            foreach ($this->tags()->filter("autosearch") as $dt) {
                $csv[] = CsvGenerator::quote("#{$dt->tag}") . "," . CsvGenerator::quote("{$dt->tag}#clear");
                $csv[] = CsvGenerator::quote($dt->autosearch) . "," . CsvGenerator::quote($dt->tag);
            }
        } else if (!empty($paper)) {
            if (is_int($paper)) {
                $pids = [$paper];
            } else if (is_object($paper)) {
                $pids = [$paper->paperId];
            } else {
                $pids = $paper;
            }
            $rowset = $this->paper_set(["paperId" => $pids]);
            foreach ($this->tags()->filter("autosearch") as $dt) {
                $search = new PaperSearch($this->root_user(), ["q" => $dt->autosearch, "t" => "all"]);
                foreach ($rowset as $prow) {
                    $want = $search->test($prow);
                    if ($prow->has_tag($dt->tag) !== $want)
                        $csv[] = "{$prow->paperId}," . CsvGenerator::quote($dt->tag . ($want ? "" : "#clear"));
                }
            }
        }
        $this->_update_autosearch_tags_csv($csv);
    }

    function _update_autosearch_tags_csv($csv) {
        if (count($csv) > 1) {
            $this->_updating_autosearch_tags = true;
            $aset = new AssignmentSet($this->root_user(), true);
            $aset->set_search_type("all");
            $aset->parse($csv);
            $aset->execute();
            $this->_updating_autosearch_tags = false;
        }
    }


    /** @var ?list<string> */
    static private $invariant_row = null;

    private function invariantq($q, $args = []) {
        $result = $this->ql_apply($q, $args);
        if (!Dbl::is_error($result)) {
            self::$invariant_row = $result->fetch_row();
            $result->close();
            return !!self::$invariant_row;
        } else {
            return null;
        }
    }

    private function invariant_error(&$problems, $abbrev, $text = null) {
        $problems[$abbrev] = true;
        if ((string) $text === "") {
            $text = $abbrev;
        }
        foreach (self::$invariant_row ?? [] as $i => $v) {
            $text = str_replace("{{$i}}", $v, $text);
        }
        trigger_error("$this->dbname invariant error: $text");
    }

    function check_invariants() {
        $ie = [];

        // local invariants
        $any = $this->invariantq("select paperId from Paper where timeSubmitted>0 and timeWithdrawn>0 limit 1");
        if ($any) {
            $this->invariant_error($ie, "submitted_withdrawn", "paper #{0} is both submitted and withdrawn");
        }

        // settings correctly materialize database facts
        $any = $this->invariantq("select paperId from Paper where timeSubmitted>0 limit 1");
        if ($any !== !($this->settings["no_papersub"] ?? false)) {
            $this->invariant_error($ie, "no_papersub");
        }

        $any = $this->invariantq("select paperId from Paper where outcome>0 and timeSubmitted>0 limit 1");
        if ($any !== !!($this->settings["paperacc"] ?? false)) {
            $this->invariant_error($ie, "paperacc");
        }

        $any = $this->invariantq("select reviewId from PaperReview where reviewToken!=0 limit 1");
        if ($any !== !!($this->settings["rev_tokens"] ?? false)) {
            $this->invariant_error($ie, "rev_tokens");
        }

        $any = $this->invariantq("select paperId from Paper where leadContactId>0 or shepherdContactId>0 limit 1");
        if ($any !== !!($this->settings["paperlead"] ?? false)) {
            $this->invariant_error($ie, "paperlead");
        }

        $any = $this->invariantq("select paperId from Paper where managerContactId>0 limit 1");
        if ($any !== !!($this->settings["papermanager"] ?? false)) {
            $this->invariant_error($ie, "papermanager");
        }

        $any = $this->invariantq("select paperId from PaperReview where reviewType=" . REVIEW_META . " limit 1");
        if ($any !== !!($this->settings["metareviews"] ?? false)) {
            $this->invariant_error($ie, "metareviews");
        }

        $result = $this->ql("select paperId, dataOverflow from Paper where dataOverflow is not null");
        while (($row = $result->fetch_row())) {
            if (json_decode($row[1]) === null) {
                $this->invariant_error($ie, "#{$row[0]}: invalid dataOverflow");
            }
        }
        Dbl::free($result);

        // no empty text options
        $text_options = array();
        foreach ($this->paper_opts->option_list() as $ox) {
            if ($ox->type === "text") {
                $text_options[] = $ox->id;
            }
        }
        if (count($text_options)) {
            $any = $this->invariantq("select paperId from PaperOption where optionId?a and data='' limit 1", [$text_options]);
            if ($any)
                $this->invariant_error($ie, "text_option_empty", "text option with empty text");
        }

        // no funky PaperConflict entries
        $any = $this->invariantq("select paperId from PaperConflict where conflictType<=0 limit 1");
        if ($any) {
            $this->invariant_error($ie, "PaperConflict_zero", "PaperConflict with zero conflictType");
        }

        // reviewNeedsSubmit is defined correctly
        $any = $this->invariantq("select r.paperId, r.reviewId from PaperReview r
            left join (select paperId, requestedBy, count(reviewId) ct, count(reviewSubmitted) cs
                       from PaperReview where reviewType<" . REVIEW_SECONDARY . "
                       group by paperId, requestedBy) q
                on (q.paperId=r.paperId and q.requestedBy=r.contactId)
            where r.reviewType=" . REVIEW_SECONDARY . " and reviewSubmitted is null
            and if(coalesce(q.ct,0)=0,1,if(q.cs=0,-1,0))!=r.reviewNeedsSubmit
            limit 1");
        if ($any) {
            $this->invariant_error($ie, "reviewNeedsSubmit", "bad reviewNeedsSubmit for review #{0}/{1}");
        }

        // review rounds are defined
        $result = $this->qe("select reviewRound, count(*) from PaperReview group by reviewRound");
        $defined_rounds = $this->defined_round_list();
        while ($result && ($row = $result->fetch_row())) {
            if (!isset($defined_rounds[$row[0]]))
                $this->invariant_error($ie, "undefined_review_round", "{$row[1]} PaperReviews for reviewRound {$row[0]}, which is not defined");
        }
        Dbl::free($result);

        // anonymous users are disabled
        $any = $this->invariantq("select email from ContactInfo where email regexp '^anonymous[0-9]*\$' and not disabled limit 1");
        if ($any) {
            $this->invariant_error($ie, "anonymous_user_enabled", "anonymous user is not disabled");
        }

        // check tag strings
        $result = $this->qe("select distinct contactTags from ContactInfo where contactTags is not null union select distinct commentTags from PaperComment where commentTags is not null");
        while (($row = $result->fetch_row())) {
            if ($row[0] === "" || !TagMap::is_tag_string($row[0], true)) {
                $this->invariant_error($ie, "tag_strings", "bad tag string “{$row[0]}”");
            }
        }
        Dbl::free($result);

        // paper denormalizations match
        $any = $this->invariantq("select p.paperId from Paper p join PaperStorage ps on (ps.paperStorageId=p.paperStorageId) where p.finalPaperStorageId<=0 and p.paperStorageId>1 and (p.sha1!=ps.sha1 or p.size!=ps.size or p.mimetype!=ps.mimetype or p.timestamp!=ps.timestamp) limit 1");
        if ($any) {
            $this->invariant_error($ie, "paper_denormalization", "bad Paper denormalization, paper #{0}");
        }
        $any = $this->invariantq("select p.paperId from Paper p join PaperStorage ps on (ps.paperStorageId=p.finalPaperStorageId) where p.finalPaperStorageId>1 and (p.sha1 != ps.sha1 or p.size!=ps.size or p.mimetype!=ps.mimetype or p.timestamp!=ps.timestamp) limit 1");
        if ($any) {
            $this->invariant_error($ie, "paper_final_denormalization", "bad Paper final denormalization, paper #{0}");
        }

        // filterType is never zero
        $any = $this->invariantq("select paperStorageId from PaperStorage where filterType=0 limit 1");
        if ($any) {
            $this->invariant_error($ie, "filterType", "bad PaperStorage filterType, id #{0}");
        }

        // has_colontag is defined
        $any = $this->invariantq("select tag from PaperTag where tag like '%:' limit 1");
        if ($any && !$this->setting("has_colontag")) {
            $this->invariant_error($ie, "has_colontag", "has tag {0} but no has_colontag");
        }

        // has_topics is defined
        $any = $this->invariantq("select topicId from TopicArea limit 1");
        if (!$any !== !$this->setting("has_topics")) {
            $this->invariant_error($ie, "has_topics");
        }

        $this->check_document_inactive_invariants();

        // autosearches are correct
        if ($this->tags()->has_autosearch) {
            $autosearch_dts = array_values($this->tags()->filter("autosearch"));
            $q = join(" THEN ", array_map(function ($dt) {
                return "((" . $dt->autosearch . ") XOR #" . $dt->tag . ")";
            }, $autosearch_dts));
            $search = new PaperSearch($this->root_user(), ["q" => $q, "t" => "all"]);
            $p = [];
            foreach ($search->paper_ids() as $pid) {
                $then = $search->thenmap[$pid] ?? 0;
                if (!isset($p[$then])) {
                    $dt = $autosearch_dts[$then];
                    $this->invariant_error($ie, "autosearch", "autosearch #" . $dt->tag . " disagrees with search " . $dt->autosearch . " on #" . $pid);
                    $p[$then] = true;
                }
            }
        }

        // comments are nonempty
        $any = $this->invariantq("select paperId, commentId from PaperComment where comment is null and commentOverflow is null and not exists (select * from DocumentLink where paperId=PaperComment.paperId and linkId=PaperComment.commentId and linkType>=0 and linkType<1024) limit 1");
        if ($any) {
            $this->invariant_error($ie, "empty comment #{0}/{1}");
        }

        // non-draft comments are displayed
        $any = $this->invariantq("select paperId, commentId from PaperComment where timeDisplayed=0 and (commentType&" . COMMENTTYPE_DRAFT . ")=0 limit 1");
        if ($any) {
            $this->invariant_error($ie, "submitted comment #{0}/{1} has no timeDisplayed");
        }

        // submitted and ordinaled reviews are displayed
        $any = $this->invariantq("select paperId, reviewId from PaperReview where timeDisplayed=0 and (reviewSubmitted is not null or reviewOrdinal>0) limit 1");
        if ($any) {
            $this->invariant_error($ie, "submitted/ordinal review #{0}/{1} has no timeDisplayed");
        }

        return $ie;
    }

    function check_document_inactive_invariants() {
        $ie = [];
        $result = $this->ql("select paperStorageId, finalPaperStorageId from Paper");
        $pids = [];
        while ($result && ($row = $result->fetch_row())) {
            if ($row[0] > 1) {
                $pids[] = (int) $row[0];
            }
            if ($row[1] > 1) {
                $pids[] = (int) $row[1];
            }
        }
        Dbl::free($result);
        sort($pids);
        $any = $this->invariantq("select s.paperId, s.paperStorageId from PaperStorage s where s.paperStorageId?a and s.inactive limit 1", [$pids]);
        if ($any) {
            $this->invariant_error($ie, "paper {0} document {1} is inappropriately inactive");
        }

        $oids = $nonempty_oids = [];
        foreach ($this->paper_opts->full_option_list() as $o) {
            if ($o->has_document()) {
                $oids[] = $o->id;
                if (!$o->allow_empty_document())
                    $nonempty_oids[] = $o->id;
            }
        }

        if (!empty($oids)) {
            $any = $this->invariantq("select o.paperId, o.optionId, s.paperStorageId from PaperOption o join PaperStorage s on (s.paperStorageId=o.value and s.inactive and s.paperStorageId>1) where o.optionId?a limit 1", [$oids]);
            if ($any) {
                $this->invariant_error($ie, "paper {0} option {1} document {2} is inappropriately inactive");
            }

            $any = $this->invariantq("select o.paperId, o.optionId, s.paperStorageId, s.paperId from PaperOption o join PaperStorage s on (s.paperStorageId=o.value and s.paperStorageId>1 and s.paperId!=o.paperId) where o.optionId?a limit 1", [$oids]);
            if ($any) {
                $this->invariant_error($ie, "paper {0} option {1} document {2} belongs to different paper {3}");
            }
        }

        if (!empty($nonempty_oids)) {
            $any = $this->invariantq("select o.paperId, o.optionId from PaperOption o where o.optionId?a and o.value<=1 limit 1", [$nonempty_oids]);
            if ($any) {
                $this->invariant_error($ie, "paper {0} option {1} links to empty document");
            }
        }

        $any = $this->invariantq("select l.paperId, l.linkId, s.paperStorageId from DocumentLink l join PaperStorage s on (l.documentId=s.paperStorageId and s.inactive) limit 1");
        if ($any) {
            $this->invariant_error($ie, "paper {0} link {1} document {2} is inappropriately inactive");
        }

        return empty($ie);
    }


    function update_schema_version($n) {
        if (!$n) {
            $n = $this->fetch_ivalue("select value from Settings where name='allowPaperOption'");
        }
        if ($n && $this->ql_ok("update Settings set value=? where name='allowPaperOption'", $n)) {
            $this->sversion = $this->settings["allowPaperOption"] = $n;
            return true;
        } else {
            return false;
        }
    }

    function invalidate_caches($caches = null) {
        if (!self::$no_invalidate_caches) {
            if (is_string($caches)) {
                $caches = [$caches => true];
            }
            if (!$caches || isset($caches["pc"])) {
                $this->_pc_members_cache = $this->_pc_tags_cache = $this->_pc_users_cache = $this->_pc_chairs_cache = null;
                $this->_user_cache = $this->_user_email_cache = null;
            }
            if (!$caches || isset($caches["options"])) {
                $this->paper_opts->invalidate_option_list();
                $this->_formatspec_cache = [];
                $this->_abbrev_matcher = null;
            }
            if (!$caches || isset($caches["rf"])) {
                $this->_review_form_cache = $this->_defined_rounds = null;
                $this->_abbrev_matcher = null;
            }
            if (!$caches || isset($caches["taginfo"]) || isset($caches["tracks"])) {
                $this->_taginfo = null;
            }
            if (!$caches || isset($caches["formulas"])) {
                $this->_formula_functions = null;
            }
            if (!$caches || isset($caches["assigners"])) {
                $this->_assignment_parsers = null;
            }
            if (!$caches || isset($caches["tracks"])) {
                Contact::update_rights();
            }
        }
    }


    // times

    private function _dateFormat($type) {
        if (!$this->_date_format_initialized) {
            if (!isset($this->opt["time24hour"]) && isset($this->opt["time24Hour"])) {
                $this->opt["time24hour"] = $this->opt["time24Hour"];
            }
            if (!isset($this->opt["dateFormatLong"]) && isset($this->opt["dateFormat"])) {
                $this->opt["dateFormatLong"] = $this->opt["dateFormat"];
            }
            if (!isset($this->opt["dateFormat"])) {
                $this->opt["dateFormat"] = ($this->opt["time24hour"] ?? false) ? "j M Y H:i:s" : "j M Y g:i:sa";
            }
            if (!isset($this->opt["dateFormatLong"])) {
                $this->opt["dateFormatLong"] = "l " . $this->opt["dateFormat"];
            }
            if (!isset($this->opt["dateFormatObscure"])) {
                $this->opt["dateFormatObscure"] = "j M Y";
            }
            if (!isset($this->opt["timestampFormat"])) {
                $this->opt["timestampFormat"] = $this->opt["dateFormat"];
            }
            if (!isset($this->opt["dateFormatSimplifier"])) {
                $this->opt["dateFormatSimplifier"] = ($this->opt["time24hour"] ?? false) ? "/:00(?!:)/" : "/:00(?::00|)(?= ?[ap]m)/";
            }
            if (!isset($this->opt["dateFormatTimezone"])) {
                $this->opt["dateFormatTimezone"] = null;
            }
            $this->_date_format_initialized = true;
        }
        if ($type === "timestamp") {
            return $this->opt["timestampFormat"];
        } else if ($type === "obscure") {
            return $this->opt["dateFormatObscure"];
        } else if ($type === "long") {
            return $this->opt["dateFormatLong"];
        } else {
            return $this->opt["dateFormat"];
        }
    }
    private function _unparse_timezone($value) {
        $z = $this->opt["dateFormatTimezone"];
        if ($z === null) {
            $z = date("T", $value);
            if ($z === "-12") {
                $z = "AoE";
            } else if ($z && ($z[0] === "+" || $z[0] === "-")) {
                $z = "UTC" . $z;
            }
        }
        return $z;
    }

    function parseableTime($value, $include_zone) {
        $f = $this->_dateFormat(false);
        $d = date($f, $value);
        if ($this->opt["dateFormatSimplifier"]) {
            $d = preg_replace($this->opt["dateFormatSimplifier"], "", $d);
        }
        if ($include_zone && ($z = $this->_unparse_timezone($value))) {
            $d .= " $z";
        }
        return $d;
    }
    function parse_time($d, $reference = null) {
        global $Now;
        if ($reference === null) {
            $reference = $Now;
        }
        if (!isset($this->opt["dateFormatTimezoneRemover"])) {
            $x = array();
            if (function_exists("timezone_abbreviations_list")) {
                $mytz = date_default_timezone_get();
                foreach (timezone_abbreviations_list() as $tzname => $tzinfo) {
                    foreach ($tzinfo as $tz) {
                        if ($tz["timezone_id"] == $mytz) {
                            $x[] = preg_quote($tzname);
                        }
                    }
                }
            }
            if (empty($x)) {
                $z = date("T", $reference);
                if ($z === "-12") {
                    $x[] = "AoE";
                }
                $x[] = preg_quote($z);
            }
            $this->opt["dateFormatTimezoneRemover"] =
                "/(?:\\s|\\A)(?:" . join("|", $x) . ")(?:\\s|\\z)/i";
        }
        if ($this->opt["dateFormatTimezoneRemover"]) {
            $d = preg_replace($this->opt["dateFormatTimezoneRemover"], " ", $d);
        }
        if (preg_match('/\A(.*)\b(utc(?=[-+])|aoe(?=\s|\z))(.*)\z/i', $d, $m)) {
            if (strcasecmp($m[2], "aoe") === 0) {
                $d = strtotime($m[1] . "GMT-1200" . $m[3], $reference);
                if ($d !== false
                    && $d % 86400 == 43200
                    && ($dx = strtotime($m[1] . " T23:59:59 GMT-1200" . $m[3], $reference)) === $d + 86399) {
                    return $dx;
                } else {
                    return $d;
                }
            } else {
                return strtotime($m[1] . "GMT" . $m[3], $reference);
            }
        } else {
            return strtotime($d, $reference);
        }
    }

    /** @param int $timestamp */
    private function _unparse_time($timestamp, $type, $useradjust, $preadjust = null) {
        if ($timestamp <= 0) {
            return "N/A";
        }
        $t = date($this->_dateFormat($type), $timestamp);
        if ($this->opt["dateFormatSimplifier"]) {
            $t = preg_replace($this->opt["dateFormatSimplifier"], "", $t);
        }
        if ($type !== "obscure" && ($z = $this->_unparse_timezone($timestamp))) {
            $t .= " $z";
        }
        if ($preadjust) {
            $t .= $preadjust;
        }
        if ($useradjust) {
            $sp = strpos($useradjust, " ");
            $t .= "<$useradjust class=\"usertime hidden need-usertime\" data-time=\"$timestamp\"></" . ($sp ? substr($useradjust, 0, $sp) : $useradjust) . ">";
        }
        return $t;
    }
    /** @param int|float|null $timestamp */
    function obscure_time($timestamp) {
        if ($timestamp !== null) {
            $timestamp = (int) ($timestamp + 0.5);
        }
        if ($timestamp > 0) {
            $offset = 0;
            if (($zone = timezone_open(date_default_timezone_get()))) {
                $offset = $zone->getOffset(new DateTime("@$timestamp"));
            }
            $timestamp += 43200 - ($timestamp + $offset) % 86400;
        }
        return $timestamp;
    }
    /** @param int $timestamp */
    function unparse_time_long($timestamp, $useradjust = false, $preadjust = null) {
        return $this->_unparse_time($timestamp, "long", $useradjust, $preadjust);
    }
    /** @param int $timestamp */
    function unparse_time($timestamp) {
        return $this->_unparse_time($timestamp, "timestamp", false, null);
    }
    /** @param int $timestamp */
    function unparse_time_obscure($timestamp) {
        return $this->_unparse_time($timestamp, "obscure", false, null);
    }
    /** @param int $timestamp */
    function unparse_time_point($timestamp) {
        return date("j M Y", $timestamp);
    }
    /** @param int $timestamp */
    function unparse_time_log($timestamp) {
        return date("d/M/Y:H:i:s O", $timestamp);
    }
    /** @param int $timestamp
     * @param int $now */
    function unparse_time_relative($timestamp, $now = 0, $format = 0) {
        global $Now;
        $d = abs($timestamp - ($now ? : $Now));
        if ($d >= 5227200) {
            if (!($format & 1)) {
                return ($format & 8 ? "on " : "") . date($this->_dateFormat("obscure"), $timestamp);
            }
            $unit = 5;
        } else if ($d >= 259200) {
            $unit = 4;
        } else if ($d >= 28800) {
            $unit = 3;
        } else if ($d >= 3630) {
            $unit = 2;
        } else if ($d >= 180.5) {
            $unit = 1;
        } else if ($d >= 1) {
            $unit = 0;
        } else {
            return "now";
        }
        $units = [1, 60, 1800, 3600, 86400, 604800];
        $x = $units[$unit];
        $d = ceil(($d - $x / 2) / $x);
        if ($unit === 2) {
            $d /= 2;
        }
        if ($format & 4) {
            $d .= substr("smhhdw", $unit, 1);
        } else {
            $unit_names = ["second", "minute", "hour", "hour", "day", "week"];
            $d .= " " . $unit_names[$unit] . ($d == 1 ? "" : "s");
        }
        if ($format & 2) {
            return $d;
        } else {
            return $timestamp < ($now ? : $Now) ? $d . " ago" : "in " . $d;
        }
    }

    function printableTimeSetting($what, $useradjust = false, $preadjust = null) {
        return $this->unparse_time_long($this->settings[$what] ?? 0, $useradjust, $preadjust);
    }
    function printableDeadlineSetting($what, $useradjust = false, $preadjust = null) {
        if (!isset($this->settings[$what]) || $this->settings[$what] <= 0) {
            return "No deadline";
        } else {
            return "Deadline: " . $this->unparse_time_long($this->settings[$what], $useradjust, $preadjust);
        }
    }

    function settingsAfter($name) {
        global $Now;
        $t = $this->settings[$name] ?? null;
        return $t !== null && $t > 0 && $t <= $Now;
    }
    function deadlinesAfter($name, $grace = null) {
        global $Now;
        $t = $this->settings[$name] ?? null;
        if ($t !== null && $t > 0 && $grace
            && ($g = $this->settings[$grace] ?? null)) {
            $t += $g;
        }
        return $t !== null && $t > 0 && $t <= $Now;
    }
    function deadlinesBetween($name1, $name2, $grace = null) {
        // see also ResponseRound::time_allowed
        global $Now;
        $t = $this->settings[$name1] ?? null;
        if (($t === null || $t <= 0 || $t > $Now) && $name1) {
            return false;
        }
        $t = $this->settings[$name2] ?? null;
        if ($t !== null && $t > 0 && $grace
            && ($g = $this->settings[$grace] ?? null)) {
            $t += $g;
        }
        return $t === null || $t <= 0 || $t >= $Now;
    }

    function timeStartPaper() {
        return $this->deadlinesBetween("sub_open", "sub_reg", "sub_grace");
    }
    function timeUpdatePaper($prow = null) {
        return $this->deadlinesBetween("sub_open", "sub_update", "sub_grace")
            && (!$prow || $prow->timeSubmitted <= 0 || $this->setting("sub_freeze") <= 0);
    }
    function timeFinalizePaper($prow = null) {
        return $this->deadlinesBetween("sub_open", "sub_sub", "sub_grace")
            && (!$prow || $prow->timeSubmitted <= 0 || $this->setting('sub_freeze') <= 0);
    }
    function allow_final_versions() {
        return $this->setting("final_open") > 0;
    }
    function time_submit_final_version() {
        return $this->deadlinesBetween("final_open", "final_done", "final_grace");
    }
    function can_some_author_view_review($reviewsOutstanding = false) {
        return $this->any_response_open
            || ($this->au_seerev > 0
                && ($this->au_seerev != self::AUSEEREV_UNLESSINCOMPLETE
                    || !$reviewsOutstanding));
    }
    function can_all_author_view_decision() {
        return $this->setting("seedec") == self::SEEDEC_ALL;
    }
    function can_some_author_view_decision() {
        return $this->setting("seedec") == self::SEEDEC_ALL;
    }
    function time_review_open() {
        global $Now;
        $rev_open = $this->settings["rev_open"] ?? 0;
        return 0 < $rev_open && $rev_open <= $Now;
    }
    function review_deadline($round, $isPC, $hard) {
        if ($round === null) {
            $round = $this->assignment_round(!$isPC);
        } else if (is_object($round)) {
            $round = $round->reviewRound ? : 0;
        }
        return ($isPC ? "pcrev_" : "extrev_") . ($hard ? "hard" : "soft")
            . ($round ? "_$round" : "");
    }
    function missed_review_deadline($round, $isPC, $hard) {
        global $Now;
        $rev_open = $this->settings["rev_open"] ?? 0;
        if (!(0 < $rev_open && $rev_open <= $Now)) {
            return "rev_open";
        }
        $dn = $this->review_deadline($round, $isPC, $hard);
        $dv = $this->settings[$dn] ?? 0;
        if ($dv > 0 && $dv < $Now) {
            return $dn;
        }
        return false;
    }
    function time_review($round, $isPC, $hard) {
        return !$this->missed_review_deadline($round, $isPC, $hard);
    }
    function timePCReviewPreferences() {
        return $this->can_pc_see_active_submissions() || $this->has_any_submitted();
    }
    function time_pc_view_decision($conflicted) {
        $s = $this->setting("seedec");
        if ($conflicted) {
            return $s == self::SEEDEC_ALL || $s == self::SEEDEC_REV;
        } else {
            return $s >= self::SEEDEC_REV;
        }
    }
    function time_reviewer_view_decision() {
        return $this->setting("seedec") >= self::SEEDEC_REV;
    }
    function time_reviewer_view_accepted_authors() {
        return $this->setting("seedec") == self::SEEDEC_ALL
            && !$this->setting("seedec_hideau");
    }
    function timePCViewPaper($prow, $pdf) {
        if ($prow->timeWithdrawn > 0) {
            return false;
        } else if ($prow->timeSubmitted > 0) {
            return !$pdf || $this->_pc_see_pdf;
        } else {
            return !$pdf && $this->can_pc_see_active_submissions();
        }
    }

    function submission_blindness() {
        return $this->settings["sub_blind"];
    }
    function subBlindAlways() {
        return $this->settings["sub_blind"] == self::BLIND_ALWAYS;
    }
    function subBlindNever() {
        return $this->settings["sub_blind"] == self::BLIND_NEVER;
    }
    function subBlindOptional() {
        return $this->settings["sub_blind"] == self::BLIND_OPTIONAL;
    }
    function subBlindUntilReview() {
        return $this->settings["sub_blind"] == self::BLIND_UNTILREVIEW;
    }

    function is_review_blind($rrow) {
        $rb = $this->settings["rev_blind"];
        if ($rb == self::BLIND_ALWAYS) {
            return true;
        } else if ($rb != self::BLIND_OPTIONAL) {
            return false;
        } else {
            if (is_object($rrow)) {
                $rrow = (bool) $rrow->reviewBlind;
            }
            return $rrow === null || $rrow;
        }
    }
    function review_blindness() {
        return $this->settings["rev_blind"];
    }
    function can_some_external_reviewer_view_comment() {
        return $this->settings["extrev_view"] == 2;
    }

    function has_any_submitted() {
        return !($this->settings["no_papersub"] ?? false);
    }
    function has_any_pc_visible_pdf() {
        return $this->has_any_submitted() && $this->_pc_see_pdf;
    }
    function has_any_accepted() {
        return !!($this->settings["paperacc"] ?? false);
    }

    function count_submitted_accepted() {
        $dlt = max($this->setting("sub_sub"), $this->setting("sub_close"));
        $result = $this->qe("select outcome, count(paperId) from Paper where timeSubmitted>0 " . ($dlt ? "or (timeSubmitted=-100 and timeWithdrawn>=$dlt) " : "") . "group by outcome");
        $n = $nyes = 0;
        while (($row = $result->fetch_row())) {
            $n += $row[1];
            if ($row[0] > 0) {
                $nyes += $row[1];
            }
        }
        Dbl::free($result);
        return [$n, $nyes];
    }

    function has_any_lead_or_shepherd() {
        return !!($this->settings["paperlead"] ?? false);
    }

    function has_any_manager() {
        return ($this->_track_sensitivity & Track::BITS_ADMIN)
            || !!($this->settings["papermanager"] ?? false);
    }

    function has_any_metareviews() {
        return !!($this->settings["metareviews"] ?? false);
    }

    function can_pc_see_active_submissions() {
        if ($this->_pc_seeall_cache === null) {
            $this->_pc_seeall_cache = $this->settings["pc_seeall"] ?? 0;
            if ($this->_pc_seeall_cache > 0 && !$this->timeFinalizePaper()) {
                $this->_pc_seeall_cache = 0;
            }
        }
        return $this->_pc_seeall_cache > 0;
    }


    function set_siteurl($base) {
        $old_siteurl = Navigation::siteurl();
        $base = Navigation::set_siteurl($base);
        if ($this->opt["assetsUrl"] === $old_siteurl) {
            $this->opt["assetsUrl"] = $base;
            Ht::$img_base = $this->opt["assetsUrl"] . "images/";
        }
        if ($this->opt["scriptAssetsUrl"] === $old_siteurl) {
            $this->opt["scriptAssetsUrl"] = $base;
        }
    }

    const HOTURL_RAW = 1;
    const HOTURL_POST = 2;
    const HOTURL_ABSOLUTE = 4;
    const HOTURL_SITE_RELATIVE = 8;
    const HOTURL_NO_DEFAULTS = 16;

    function hoturl($page, $param = null, $flags = 0) {
        global $Me;
        $nav = Navigation::get();
        $amp = ($flags & self::HOTURL_RAW ? "&" : "&amp;");
        $t = $page . $nav->php_suffix;
        $are = '/\A(|.*?(?:&|&amp;))';
        $zre = '(?:&(?:amp;)?|\z)(.*)\z/';
        // parse options, separate anchor
        $anchor = "";
        if (is_array($param)) {
            $x = "";
            foreach ($param as $k => $v) {
                if ($v === null || $v === false) {
                    // skip
                } else if ($k === "anchor") {
                    $anchor = "#" . urlencode($v);
                } else {
                    $x .= ($x === "" ? "" : $amp) . $k . "=" . urlencode($v);
                }
            }
            if (Conf::$hoturl_defaults && !($flags & self::HOTURL_NO_DEFAULTS)) {
                foreach (Conf::$hoturl_defaults as $k => $v) {
                    if (!array_key_exists($k, $param)) {
                        $x .= ($x === "" ? "" : $amp) . $k . "=" . $v;
                    }
                }
            }
            $param = $x;
        } else {
            $param = (string) $param;
            if (($pos = strpos($param, "#"))) {
                $anchor = substr($param, $pos);
                $param = substr($param, 0, $pos);
            }
            if (Conf::$hoturl_defaults && !($flags & self::HOTURL_NO_DEFAULTS)) {
                foreach (Conf::$hoturl_defaults as $k => $v) {
                    if (!preg_match($are . preg_quote($k) . '=/', $param)) {
                        $param .= ($param === "" ? "" : $amp) . $k . "=" . $v;
                    }
                }
            }
        }
        if ($flags & self::HOTURL_POST) {
            $param .= ($param === "" ? "" : $amp) . "post=" . post_value();
        }
        // append forceShow to links to same paper if appropriate
        $is_paper_page = preg_match('/\A(?:paper|review|comment|assign)\z/', $page);
        if ($is_paper_page
            && $this->paper
            && $Me->can_administer($this->paper)
            && $this->paper->has_conflict($Me)
            && $Me->conf === $this
            && preg_match($are . 'p=' . $this->paper->paperId . $zre, $param)
            && !preg_match($are . 'forceShow=/', $param)) {
            $param .= $amp . "forceShow=1";
        }
        // create slash-based URLs if appropriate
        if ($param) {
            $tp = "";
            if ($page === "review"
                && preg_match($are . 'r=(\d+[A-Z]+)' . $zre, $param, $m)) {
                $tp = "/" . $m[2];
                $param = $m[1] . $m[3];
                if (preg_match($are . 'p=\d+' . $zre, $param, $m)) {
                    $param = $m[1] . $m[2];
                }
            } else if (($is_paper_page
                        && preg_match($are . 'p=(\d+|%\w+%|new)' . $zre, $param, $m))
                       || ($page === "help"
                           && preg_match($are . 't=(\w+)' . $zre, $param, $m))
                       || ($page === "settings"
                           && preg_match($are . 'group=(\w+)' . $zre, $param, $m))) {
                $tp = "/" . $m[2];
                $param = $m[1] . $m[3];
                if ($param !== ""
                    && $page === "paper"
                    && preg_match($are . 'm=(\w+)' . $zre, $param, $m)) {
                    $tp .= "/" . $m[2];
                    $param = $m[1] . $m[3];
                }
            } else if (($page === "graph"
                        && preg_match($are . 'g=([^&?]+)' . $zre, $param, $m))
                       || ($page === "doc"
                           && preg_match($are . 'file=([^&]+)' . $zre, $param, $m))) {
                $tp = "/" . str_replace("%2F", "/", $m[2]);
                $param = $m[1] . $m[3];
            } else if ($page === "profile"
                       && preg_match($are . 'u=([^&?]+)' . $zre, $param, $m)) {
                $tp = "/" . str_replace("%2F", "/", $m[2]);
                $param = $m[1] . $m[3];
                if ($param !== ""
                    && preg_match($are . 't=(\w+)' . $zre, $param, $m)) {
                    $tp .= "/" . $m[2];
                    $param = $m[1] . $m[3];
                }
            } else if ($page === "profile"
                       && preg_match($are . 't=(\w+)' . $zre, $param, $m)) {
                $tp = "/" . $m[2];
                $param = $m[1] . $m[3];
            } else if (preg_match($are . '__PATH__=([^&]+)' . $zre, $param, $m)) {
                $tp = "/" . urldecode($m[2]);
                $param = $m[1] . $m[3];
            } else {
                $tp = "";
            }
            if ($tp !== "") {
                $t .= $tp;
                if (preg_match($are . '__PATH__=([^&]+)' . $zre, $param, $m)
                    && $tp === "/" . urldecode($m[2])) {
                    $param = $m[1] . $m[3];
                }
            }
            $param = preg_replace('/&(?:amp;)?\z/', "", $param);
        }
        if ($param !== "" && preg_match('/\A&(?:amp;)?(.*)\z/', $param, $m)) {
            $param = $m[1];
        }
        if ($param !== "") {
            $t .= "?" . $param;
        }
        if ($anchor !== "") {
            $t .= $anchor;
        }
        if ($flags & self::HOTURL_SITE_RELATIVE) {
            return $t;
        }
        $need_site_path = false;
        if ($page === "index") {
            $expect = "index" . $nav->php_suffix;
            $lexpect = strlen($expect);
            if (substr($t, 0, $lexpect) === $expect
                && ($t === $expect || $t[$lexpect] === "?" || $t[$lexpect] === "#")) {
                $need_site_path = true;
                $t = substr($t, $lexpect);
            }
        }
        if (($flags & self::HOTURL_ABSOLUTE) || $this !== Conf::$g) {
            return $this->opt("paperSite") . "/" . $t;
        } else {
            $siteurl = $nav->site_path_relative;
            if ($need_site_path && $siteurl === "") {
                $siteurl = $nav->site_path;
            }
            return $siteurl . $t;
        }
    }

    function hoturl_absolute($page, $param = null, $flags = 0) {
        return $this->hoturl($page, $param, self::HOTURL_ABSOLUTE | $flags);
    }

    function hoturl_site_relative_raw($page, $param = null) {
        return $this->hoturl($page, $param, self::HOTURL_SITE_RELATIVE | self::HOTURL_RAW);
    }

    function hoturl_post($page, $param = null) {
        return $this->hoturl($page, $param, self::HOTURL_POST);
    }

    function hoturl_raw($page, $param = null, $flags = 0) {
        return $this->hoturl($page, $param, self::HOTURL_RAW | $flags);
    }

    function hotlink($html, $page, $param = null, $js = null) {
        return Ht::link($html, $this->hoturl($page, $param), $js);
    }


    static $selfurl_safe = [
        "p" => true, "paperId" => "p", "pap" => "p",
        "r" => true, "reviewId" => "r",
        "c" => true, "commentId" => "c",
        "m" => true, "mode" => true, "u" => true, "g" => true,
        "q" => true, "t" => true, "qa" => true, "qo" => true, "qx" => true, "qt" => true,
        "fx" => true, "fy" => true,
        "forceShow" => true, "tab" => true, "atab" => true, "sort" => true,
        "group" => true, "monreq" => true, "noedit" => true,
        "contact" => true, "reviewer" => true,
        "editcomment" => true
    ];

    function selfurl(Qrequest $qreq = null, $params = [], $flags = 0) {
        global $Qreq;
        $qreq = $qreq ? : $Qreq;

        $x = [];
        foreach ($qreq as $k => $v) {
            $ak = self::$selfurl_safe[$k] ?? false;
            if ($ak === true) {
                $ak = $k;
            }
            if ($ak
                && ($ak === $k || !isset($qreq[$ak]))
                && !array_key_exists($ak, $params)
                && !is_array($v)) {
                $x[$ak] = $v;
            }
        }
        foreach ($params as $k => $v) {
            $x[$k] = $v;
        }
        return $this->hoturl(Navigation::page(), $x, $flags);
    }

    function self_redirect(Qrequest $qreq = null, $params = []) {
        Navigation::redirect($this->selfurl($qreq, $params, self::HOTURL_RAW));
    }


    //
    // Paper storage
    //

    function download_documents($docs, $attachment) {
        if (count($docs) == 1
            && $docs[0]->paperStorageId <= 1
            && (!isset($docs[0]->content) || $docs[0]->content === "")) {
            self::msg_error("Paper #" . $docs[0]->paperId . " hasn’t been uploaded yet.");
            return false;
        }

        foreach ($docs as $doc) {
            $doc->filename = $doc->export_filename();
        }
        $downloadname = false;
        if (count($docs) > 1) {
            $o = $this->option_by_id($docs[0]->documentType);
            $name = $o->dtype_name();
            if ($docs[0]->documentType <= 0) {
                $name = pluralize($name);
            }
            $downloadname = $this->download_prefix . "$name.zip";
        }
        $result = Filer::multidownload($docs, $downloadname, $attachment);
        if ($result->error) {
            self::msg_error($result->error_html);
            return false;
        } else {
            return true;
        }
    }

    /** @param string $basename
     * @param int $flags
     * @return CsvGenerator */
    function make_csvg($basename, $flags = 0) {
        $csv = new CsvGenerator($flags);
        $csv->set_filename($this->download_prefix . $basename . $csv->extension());
        return $csv;
    }


    //
    // Paper search
    //

    function query_ratings() {
        if ($this->setting("rev_ratings") != REV_RATINGS_NONE) {
            return "(select group_concat(contactId, ' ', rating) from ReviewRating where paperId=PaperReview.paperId and reviewId=PaperReview.reviewId)";
        } else {
            return "''";
        }
    }

    function query_all_reviewer_preference() {
        return "group_concat(contactId,' ',preference,' ',coalesce(expertise,'.'))";
    }

    /** @param array{paperId?:list<int>} $options
     * @return Dbl_Result */
    function paper_result($options, Contact $user = null) {
        // Options:
        //   "paperId" => $pids Only papers in list<int> $pids
        //   "finalized"        Only submitted papers
        //   "unsub"            Only unsubmitted papers
        //   "accepted"         Only accepted papers
        //   "active"           Only nonwithdrawn papers
        //   "author"           Only papers authored by $contactId
        //   "myReviewRequests" Only reviews requested by $contactId
        //   "myReviews"        All reviews authored by $contactId
        //   "myOutstandingReviews" All unsubmitted reviews auth by $contactId
        //   "myConflicts"      Only conflicted papers
        //   "commenterName"    Include commenter names
        //   "tags"             Include paperTags
        //   "minimal"          Only include minimal paper fields
        //   "topics"
        //   "options"
        //   "scores" => array(fields to score)
        //   "assignments"
        //   "order" => $sql    $sql is SQL 'order by' clause (or empty)

        $contactId = $user ? $user->contactId : 0;
        if (is_int($options)
            || (is_array($options) && !empty($options) && !is_associative_array($options))) {
            error_log("bad \$options to Conf::paper_result"); // XXX
            $options = ["paperId" => $options];
        }

        // paper selection
        $paperset = null;
        '@phan-var ?list<int> $paperset';
        if (isset($options["paperId"])) {
            if (!is_int_list($options["paperId"])) {
                throw new Exception("paperId argument should be list<int> in Conf::paper_result");
            }
            $paperset = $options["paperId"];
        }
        if (isset($options["reviewId"]) || isset($options["commentId"])) {
            throw new Exception("unexpected reviewId/commentId argument to Conf::paper_result");
        }

        // prepare query: basic tables
        // * Every table in `$joins` can have at most one row per paperId,
        //   except for `PaperReview`.
        $where = [];

        $joins = ["Paper"];

        if ($options["minimal"] ?? false) {
            $cols = ["Paper.paperId, Paper.timeSubmitted, Paper.timeWithdrawn, Paper.outcome, Paper.leadContactId"];
            if ($this->submission_blindness() === self::BLIND_OPTIONAL) {
                $cols[] = "Paper.blind";
            }
            if ($options["title"] ?? false) {
                $cols[] = "Paper.title";
            }
            if ($options["authorInformation"] ?? false) {
                $cols[] = "Paper.authorInformation";
            }
        } else {
            $cols = ["Paper.*"];
        }

        if ($user) {
            $aujoinwhere = null;
            if (($options["author"] ?? false)
                && ($aujoinwhere = $user->act_author_view_sql("PaperConflict", true))) {
                $where[] = $aujoinwhere;
            }
            if (($options["author"] ?? false) && !$aujoinwhere) {
                $joins[] = "join PaperConflict on (PaperConflict.paperId=Paper.paperId and PaperConflict.contactId=$contactId and PaperConflict.conflictType>=" . CONFLICT_AUTHOR . ")";
            } else {
                $joins[] = "left join PaperConflict on (PaperConflict.paperId=Paper.paperId and PaperConflict.contactId=$contactId)";
            }
            $cols[] = "PaperConflict.conflictType";
        } else if ($options["author"] ?? false) {
            $where[] = "false";
        }

        // my review
        $no_paperreview = $paperreview_is_my_reviews = false;
        $reviewjoin = "PaperReview.paperId=Paper.paperId and " . ($user ? $user->act_reviewer_sql("PaperReview") : "false");
        if ($options["myReviews"] ?? false) {
            $joins[] = "join PaperReview on ($reviewjoin)";
            $paperreview_is_my_reviews = true;
        } else if ($options["myOutstandingReviews"] ?? false) {
            $joins[] = "join PaperReview on ($reviewjoin and reviewNeedsSubmit!=0)";
        } else if ($options["myReviewRequests"] ?? false) {
            $joins[] = "join PaperReview on (PaperReview.paperId=Paper.paperId and requestedBy=" . ($contactId ? : -100) . " and reviewType=" . REVIEW_EXTERNAL . ")";
        } else {
            $no_paperreview = true;
        }

        // review signatures
        if (($options["reviewSignatures"] ?? false)
            || ($options["scores"] ?? null)
            || ($options["reviewWordCounts"] ?? false)) {
            $cols[] = "(select " . ReviewInfo::review_signature_sql($this, $options["scores"] ?? null) . " from PaperReview r where r.paperId=Paper.paperId) reviewSignatures";
            if ($options["reviewWordCounts"] ?? false) {
                $cols[] = "(select group_concat(coalesce(reviewWordCount,'.') order by reviewId) from PaperReview where PaperReview.paperId=Paper.paperId) reviewWordCountSignature";
            }
        } else if ($user) {
            // need myReviewPermissions
            if ($no_paperreview) {
                $joins[] = "left join PaperReview on ($reviewjoin)";
            }
            if ($no_paperreview || $paperreview_is_my_reviews) {
                $cols[] = PaperInfo::my_review_permissions_sql("PaperReview.") . " myReviewPermissions";
            } else {
                $cols[] = "(select " . PaperInfo::my_review_permissions_sql() . " from PaperReview where $reviewjoin group by paperId) myReviewPermissions";
            }
        }

        // fields
        if ($options["topics"] ?? false) {
            $cols[] = "(select group_concat(topicId) from PaperTopic where PaperTopic.paperId=Paper.paperId) topicIds";
        }

        if ($options["options"] ?? false) {
            if ((isset($this->settingTexts["options"]) || isset($this->opt["fixedOptions"]))
                && $this->paper_opts->count_option_list()) {
                $cols[] = "(select group_concat(PaperOption.optionId, '#', value) from PaperOption where paperId=Paper.paperId) optionIds";
            } else {
                $cols[] = "'' as optionIds";
            }
        }

        if (($options["tags"] ?? false)
            || ($user && $user->isPC)
            || $this->has_tracks()) {
            $cols[] = "(select group_concat(' ', tag, '#', tagIndex order by tag separator '') from PaperTag where PaperTag.paperId=Paper.paperId) paperTags";
        }

        if ($options["reviewerPreference"] ?? false) {
            $joins[] = "left join PaperReviewPreference on (PaperReviewPreference.paperId=Paper.paperId and PaperReviewPreference.contactId=$contactId)";
            $cols[] = "coalesce(PaperReviewPreference.preference, 0) as myReviewerPreference";
            $cols[] = "PaperReviewPreference.expertise as myReviewerExpertise";
        }

        if ($options["allReviewerPreference"] ?? false) {
            $cols[] = "(select " . $this->query_all_reviewer_preference() . " from PaperReviewPreference where PaperReviewPreference.paperId=Paper.paperId) allReviewerPreference";
        }

        if ($options["allConflictType"] ?? false) {
            // See also SearchQueryInfo::add_allConflictType_column
            $cols[] = "(select group_concat(contactId, ' ', conflictType) from PaperConflict where PaperConflict.paperId=Paper.paperId) allConflictType";
        }

        if (($options["watch"] ?? false) && $contactId) {
            $joins[] = "left join PaperWatch on (PaperWatch.paperId=Paper.paperId and PaperWatch.contactId=$contactId)";
            $cols[] = "PaperWatch.watch";
        }

        // conditions
        if ($paperset !== null) {
            $where[] = "Paper.paperId" . sql_in_int_list($paperset);
        }
        if ($options["finalized"] ?? false) {
            $where[] = "timeSubmitted>0";
        } else if ($options["unsub"] ?? false) {
            $where[] = "timeSubmitted<=0";
        }
        if ($options["accepted"] ?? false) {
            $where[] = "outcome>0";
        }
        if ($options["undecided"] ?? false) {
            $where[] = "outcome=0";
        }
        if ($options["active"]
            ?? $options["myReviews"]
            ?? $options["myOutstandingReviews"]
            ?? $options["myReviewRequests"]
            ?? false) {
            $where[] = "timeWithdrawn<=0";
        }
        if ($options["myLead"] ?? false) {
            $where[] = "leadContactId=$contactId";
        }
        if ($options["myManaged"] ?? false) {
            $where[] = "managerContactId=$contactId";
        }
        if (($options["myWatching"] ?? false) && $contactId) {
            // return the papers with explicit or implicit WATCH_REVIEW
            // (i.e., author/reviewer/commenter); or explicitly managed
            // papers
            $owhere = [
                "PaperConflict.conflictType>=" . CONFLICT_AUTHOR,
                "PaperReview.reviewType>0",
                "exists (select * from PaperComment where paperId=Paper.paperId and contactId=$contactId)",
                "(PaperWatch.watch&" . Contact::WATCH_REVIEW . ")!=0"
            ];
            if ($this->has_any_lead_or_shepherd()) {
                $owhere[] = "leadContactId=$contactId";
            }
            if ($this->has_any_manager() && $user->is_explicit_manager()) {
                $owhere[] = "managerContactId=$contactId";
            }
            $where[] = "(" . join(" or ", $owhere) . ")";
        }
        if ($options["myConflicts"] ?? false) {
            $where[] = $contactId ? "PaperConflict.conflictType>" . CONFLICT_MAXUNCONFLICTED : "false";
        }

        $pq = "select " . join(",\n    ", $cols)
            . "\nfrom " . join("\n    ", $joins);
        if (!empty($where)) {
            $pq .= "\nwhere " . join("\n    and ", $where);
        }

        $pq .= "\ngroup by Paper.paperId\n";
        // This `having` is probably faster than a `where exists` if most papers
        // have at least one tag.
        if (($options["tags"] ?? false) === "require") {
            $pq .= "having paperTags!=''\n";
        }
        $pq .= ($options["order"] ?? "order by Paper.paperId") . "\n";

        //Conf::msg_debugt($pq);
        return $this->qe_raw($pq);
    }

    /** @param array{paperId?:list<int>} $options
     * @return PaperInfoSet */
    function paper_set($options, Contact $user = null) {
        $rowset = new PaperInfoSet;
        $result = $this->paper_result($options, $user);
        while (($prow = PaperInfo::fetch($result, $user, $this))) {
            $rowset->add($prow);
        }
        Dbl::free($result);
        return $rowset;
    }

    /** @param int $pid
     * @return ?PaperInfo */
    function paper_by_id($pid, Contact $user = null, $options = []) {
        $options["paperId"] = [$pid];
        $result = $this->paper_result($options, $user);
        $prow = PaperInfo::fetch($result, $user, $this);
        Dbl::free($result);
        return $prow;
    }

    /** @param int $pid
     * @return PaperInfo */
    function checked_paper_by_id($pid, Contact $user = null, $options = []) {
        $prow = $this->paper_by_id($pid, $user, $options);
        if (!$prow) {
            throw new Exception("Conf::checked_paper_by_id($pid) failed");
        }
        return $prow;
    }

    /** @deprecated
     * @param int $pid
     * @return ?PaperInfo */
    function fetch_paper($pid, Contact $user = null, $options = []) {
        return $this->paper_by_id($pid, $user, $options);
    }

    /** @return ?PaperInfo */
    function set_paper_request(Qrequest $qreq, Contact $user) {
        $this->paper = $prow = null;
        if ($qreq->p) {
            if (ctype_digit($qreq->p)) {
                $prow = $this->paper_by_id(intval($qreq->p), $user);
            }
            if (($whynot = $user->perm_view_paper($prow, false, $qreq->p))) {
                $qreq->set_annex("paper_whynot", $whynot);
            } else {
                $this->paper = $prow;
            }
        }
        return $this->paper;
    }


    function preference_conflict_result($type, $extra) {
        $q = "select PRP.paperId, PRP.contactId, PRP.preference
                from PaperReviewPreference PRP
                join ContactInfo c on (c.contactId=PRP.contactId and c.roles!=0 and (c.roles&" . Contact::ROLE_PC . ")!=0)
                join Paper P on (P.paperId=PRP.paperId)
                left join PaperConflict PC on (PC.paperId=PRP.paperId and PC.contactId=PRP.contactId)
                where PRP.preference<=-100 and coalesce(PC.conflictType,0)<=" . CONFLICT_MAXUNCONFLICTED . "
                  and P.timeWithdrawn<=0";
        if ($type !== "all" && $type !== "act") {
            $q .= " and P.timeSubmitted>0";
        }
        if ($extra) {
            $q .= " " . $extra;
        }
        return $this->ql_raw($q);
    }


    //
    // Message routines
    //

    /** @param string|list<string> $text
     * @param int|string $type */
    static function msg_on(Conf $conf = null, $text, $type) {
        if (PHP_SAPI === "cli") {
            if (is_array($text)) {
                $text = join("\n", $text);
            }
            if ($type === "xmerror" || $type === "merror" || $type === 2) {
                fwrite(STDERR, "$text\n");
            } else if ($type === "xwarning" || $type === "warning" || $type === 1
                       || !defined("HOTCRP_TESTHARNESS")) {
                fwrite(STDOUT, "$text\n");
            }
        } else if ($conf && !$conf->headerPrinted) {
            ensure_session();
            $conf->initial_msg_count();
            $_SESSION[$conf->dsn]["msgs"][] = [$text, $type];
        } else if (is_int($type) || $type[0] === "x") {
            echo Ht::msg($text, $type);
        } else {
            if (is_array($text)) {
                $text = '<div class="multimessage">' . join("", array_map(function ($x) { return '<div class="mmm">' . $x . '</div>'; }, $text)) . '</div>';
            }
            echo "<div class=\"$type\">$text</div>";
        }
    }

    /** @param string|list<string> $text */
    function msg($text, $type) {
        self::msg_on($this, $text, $type);
    }

    /** @param string|list<string> $text */
    function infoMsg($text, $minimal = false) {
        self::msg_on($this, $text, $minimal ? "xinfo" : "info");
    }

    /** @param string|list<string> $text */
    static function msg_info($text, $minimal = false) {
        self::msg_on(self::$g, $text, $minimal ? "xinfo" : "info");
    }

    /** @param string|list<string> $text */
    function warnMsg($text, $minimal = false) {
        self::msg_on($this, $text, $minimal ? "xwarning" : "warning");
    }

    /** @param string|list<string> $text */
    static function msg_warning($text, $minimal = false) {
        self::msg_on(self::$g, $text, $minimal ? "xwarning" : "warning");
    }

    /** @param string|list<string> $text */
    function confirmMsg($text, $minimal = false) {
        self::msg_on($this, $text, $minimal ? "xconfirm" : "confirm");
    }

    /** @param string|list<string> $text */
    static function msg_confirm($text, $minimal = false) {
        self::msg_on(self::$g, $text, $minimal ? "xconfirm" : "confirm");
    }

    /** @param string|list<string> $text */
    function errorMsg($text, $minimal = false) {
        self::msg_on($this, $text, $minimal ? "xmerror" : "merror");
        return false;
    }

    /** @param string|list<string> $text */
    static function msg_error($text, $minimal = false) {
        self::msg_on(self::$g, $text, $minimal ? "xmerror" : "merror");
        return false;
    }

    /** @param mixed $text */
    static function msg_debugt($text) {
        if (is_object($text) || is_array($text) || $text === null || $text === false || $text === true) {
            $text = json_encode_browser($text);
        }
        self::msg_on(self::$g, Ht::pre_text_wrap($text), "merror");
        return false;
    }

    function post_missing_msg() {
        $this->msg("Your uploaded data wasn’t received. This can happen on unusually slow connections, or if you tried to upload a file larger than I can accept.", "merror");
    }

    /** @return int */
    function initial_msg_count() {
        if (!isset($this->_initial_msg_count)
            && session_id() !== "")  {
            $this->_initial_msg_count = 0;
            if (isset($_SESSION[$this->dsn])
                && isset($_SESSION[$this->dsn]["msgs"])) {
                $this->_initial_msg_count = count($_SESSION[$this->dsn]["msgs"]);
            }
        }
        return $this->_initial_msg_count;
    }


    //
    // Conference header, footer
    //

    /** @return bool */
    function has_active_list() {
        return !!$this->_active_list;
    }

    /** @return ?SessionList */
    function active_list() {
        if ($this->_active_list === false) {
            $this->_active_list = null;
        }
        return $this->_active_list;
    }

    function set_active_list(SessionList $list = null) {
        assert($this->_active_list === false);
        $this->_active_list = $list;
    }

    function make_css_link($url, $media = null) {
        global $ConfSitePATH;
        if (str_starts_with($url, "<meta") || str_starts_with($url, "<link")) {
            return $url;
        }
        $t = '<link rel="stylesheet" type="text/css" href="';
        $absolute = preg_match(',\A(?:https:?:|/),i', $url);
        if (!$absolute) {
            $t .= $this->opt["assetsUrl"];
        }
        $t .= htmlspecialchars($url);
        if (!$absolute && ($mtime = @filemtime("$ConfSitePATH/$url")) !== false) {
            $t .= "?mtime=$mtime";
        }
        if ($media) {
            $t .= '" media="' . $media;
        }
        return $t . '">';
    }

    function make_script_file($url, $no_strict = false, $integrity = null) {
        global $ConfSitePATH;
        if (str_starts_with($url, "scripts/")) {
            $post = "";
            if (($mtime = @filemtime("$ConfSitePATH/$url")) !== false) {
                $post = "mtime=$mtime";
            }
            if (($this->opt["strictJavascript"] ?? false) && !$no_strict) {
                $url = $this->opt["scriptAssetsUrl"] . "cacheable.php?file=" . urlencode($url)
                    . "&strictjs=1" . ($post ? "&$post" : "");
            } else {
                $url = $this->opt["scriptAssetsUrl"] . $url . ($post ? "?$post" : "");
            }
            if ($this->opt["scriptAssetsUrl"] === Navigation::siteurl()) {
                return Ht::script_file($url);
            }
        }
        return Ht::script_file($url, ["crossorigin" => "anonymous", "integrity" => $integrity]);
    }

    private function make_jquery_script_file($jqueryVersion) {
        $integrity = null;
        if ($this->opt("jqueryCdn")) {
            if ($jqueryVersion === "3.5.1") {
                $integrity = "sha384-ZvpUoO/+PpLXR1lu4jmpXWu80pZlYUAfxl5NsBMWOEPSjUn/6Z/hRTt8+pR6L4N2";
            } else if ($jqueryVersion === "3.4.1") {
                $integrity = "sha384-vk5WoKIaW/vJyUAd9n/wmopsmNhiy+L2Z+SBxGYnUkunIxVxAv/UtMOhba/xskxh";
            } else if ($jqueryVersion === "3.3.1") {
                $integrity = "sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=";
            } else if ($jqueryVersion === "1.12.4") {
                $integrity = "sha256-ZosEbRLbNQzLpnKIkEdrPv7lOy9C27hHQ+Xp8a4MxAQ=";
            }
            $jquery = "//code.jquery.com/jquery-{$jqueryVersion}.min.js";
        } else {
            $jquery = "scripts/jquery-{$jqueryVersion}.min.js";
        }
        return $this->make_script_file($jquery, true, $integrity);
    }

    function prepare_content_security_policy() {
        if (($csp = $this->opt("contentSecurityPolicy"))) {
            if (is_string($csp)) {
                $csp = [$csp];
            } else if ($csp === true) {
                $csp = [];
            }
            $report_only = false;
            if (($pos = array_search("'report-only'", $csp)) !== false) {
                $report_only = true;
                array_splice($csp, $pos, 1);
            }
            if (empty($csp)) {
                array_push($csp, "script-src", "'nonce'");
            }
            if (($pos = array_search("'nonce'", $csp)) !== false) {
                $nonceval = base64_encode(random_bytes(16));
                $csp[$pos] = "'nonce-$nonceval'";
                Ht::set_script_nonce($nonceval);
            }
            header("Content-Security-Policy"
                   . ($report_only ? "-Report-Only: " : ": ")
                   . join(" ", $csp));
        }
    }

    function set_cookie($name, $value, $expires_at) {
        $opt = [
            "expires" => $expires_at, "path" => Navigation::site_path(),
            "domain" => $this->opt("sessionDomain", ""),
            "secure" => $this->opt("sessionSecure", false)
        ];
        if (($samesite = $this->opt("sessionSameSite", "Lax"))) {
            $opt["samesite"] = $samesite;
        }
        hotcrp_setcookie($name, $value, $opt);
    }

    function header_head($title, $extra = []) {
        global $Me, $Now, $ConfSitePATH;
        // clear session list cookies
        foreach ($_COOKIE as $k => $v) {
            if (str_starts_with($k, "hotlist-info"))
                $this->set_cookie($k, "", $Now - 86400);
        }

        echo "<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">
<meta name=\"google\" content=\"notranslate\">\n";

        if (($font_script = $this->opt("fontScript"))) {
            if (!str_starts_with($font_script, "<script")) {
                $font_script = Ht::script($font_script);
            }
            echo $font_script, "\n";
        }

        foreach (mkarray($this->opt("prependStylesheets", [])) as $css) {
            echo $this->make_css_link($css), "\n";
        }
        echo $this->make_css_link("stylesheets/style.css"), "\n";
        if ($this->opt("mobileStylesheet")) {
            echo '<meta name="viewport" content="width=device-width, initial-scale=1">', "\n";
            echo $this->make_css_link("stylesheets/mobile.css", "screen and (max-width: 1100px)"), "\n";
        }
        foreach (mkarray($this->opt("stylesheets", [])) as $css) {
            echo $this->make_css_link($css), "\n";
        }

        // favicon
        $favicon = $this->opt("favicon", "images/review48.png");
        if ($favicon) {
            if (strpos($favicon, "://") === false && $favicon[0] != "/") {
                if ($this->opt["assetsUrl"] && substr($favicon, 0, 7) === "images/") {
                    $favicon = $this->opt["assetsUrl"] . $favicon;
                } else {
                    $favicon = Navigation::siteurl() . $favicon;
                }
            }
            if (substr($favicon, -4) == ".png") {
                echo "<link rel=\"icon\" type=\"image/png\" href=\"$favicon\">\n";
            } else if (substr($favicon, -4) == ".ico") {
                echo "<link rel=\"shortcut icon\" href=\"$favicon\">\n";
            } else if (substr($favicon, -4) == ".gif") {
                echo "<link rel=\"icon\" type=\"image/gif\" href=\"$favicon\">\n";
            } else {
                echo "<link rel=\"icon\" href=\"$favicon\">\n";
            }
        }

        // title
        echo "<title>";
        if ($title) {
            if (is_array($title)) {
                if (count($title) === 3 && $title[2]) {
                    $title = $title[1] . " - " . $title[0];
                } else {
                    $title = $title[0];
                }
            }
            $title = preg_replace("/<([^>\"']|'[^']*'|\"[^\"]*\")*>/", "", $title);
        }
        if ($title && $title !== "Home" && $title !== "Sign in") {
            echo $title, " - ";
        }
        echo htmlspecialchars($this->short_name), "</title>\n</head>\n";

        // jQuery
        $stash = Ht::unstash();
        if (isset($this->opt["jqueryUrl"])) {
            Ht::stash_html($this->make_script_file($this->opt["jqueryUrl"], true) . "\n");
        } else {
            $jqueryVersion = $this->opt["jqueryVersion"] ?? "3.5.1";
            if ($jqueryVersion[0] === "3") {
                Ht::stash_html("<!--[if lt IE 9]>" . $this->make_jquery_script_file("1.12.4") . "<![endif]-->\n");
                Ht::stash_html("<![if !IE|gte IE 9]>" . $this->make_jquery_script_file($jqueryVersion) . "<![endif]>\n");
            } else {
                Ht::stash_html($this->make_jquery_script_file($jqueryVersion) . "\n");
            }
        }
        if ($this->opt("jqueryMigrate")) {
            Ht::stash_html($this->make_script_file("//code.jquery.com/jquery-migrate-3.0.0.js", true));
        }

        // Javascript settings to set before script.js
        $nav = Navigation::get();
        Ht::stash_script("siteurl=" . json_encode_browser($nav->site_path_relative)
            . ";siteurl_base_path=" . json_encode_browser($nav->base_path)
            . ";siteurl_suffix=\"" . $nav->php_suffix . "\"");
        $p = "";
        if (($x = $this->opt("sessionDomain"))) {
            $p .= "; domain=" . $x;
        }
        if ($this->opt("sessionSecure")) {
            $p .= "; secure";
        }
        Ht::stash_script("siteurl_postvalue=" . json_encode(post_value(true)) . ";siteurl_cookie_params=" . json_encode($p));
        if (self::$hoturl_defaults) {
            $urldefaults = [];
            foreach (self::$hoturl_defaults as $k => $v) {
                $urldefaults[$k] = urldecode($v);
            }
            Ht::stash_script("siteurl_defaults=" . json_encode_browser($urldefaults) . ";");
        }
        Ht::stash_script("assetsurl=" . json_encode_browser($this->opt["assetsUrl"]) . ";");
        $huser = (object) array();
        if ($Me && $Me->email) {
            $huser->email = $Me->email;
        }
        if ($Me && $Me->is_pclike()) {
            $huser->is_pclike = true;
        }
        if ($Me && $Me->has_account_here()) {
            $huser->cid = $Me->contactId;
        }
        Ht::stash_script("hotcrp_user=" . json_encode_browser($huser) . ";");

        $pid = $extra["paperId"] ?? null;
        $pid = $pid && ctype_digit($pid) ? (int) $pid : 0;
        if (!$pid && $this->paper) {
            $pid = $this->paper->paperId;
        }
        if ($pid) {
            Ht::stash_script("hotcrp_paperid=$pid");
        }
        if ($pid && $Me && $Me->is_admin_force()) {
            Ht::stash_script("hotcrp_want_override_conflict=true");
        }

        // script.js
        if (!$this->opt("noDefaultScript")) {
            Ht::stash_html($this->make_script_file("scripts/script.js") . "\n");
        }

        // other scripts
        foreach ($this->opt("scripts", []) as $file) {
            Ht::stash_html($this->make_script_file($file) . "\n");
        }

        if ($stash) {
            Ht::stash_html($stash);
        }
    }

    /** @return bool */
    function has_interesting_deadline($my_deadlines) {
        global $Now;
        if ($my_deadlines->sub->open ?? false) {
            foreach (["reg", "update", "sub"] as $k) {
                if ($Now <= get($my_deadlines->sub, $k, 0) || get($my_deadlines->sub, "{$k}_ingrace"))
                    return true;
            }
        }
        if (($my_deadlines->is_author ?? false)
            && ($my_deadlines->resps ?? false)) {
            foreach ($my_deadlines->resps as $r) {
                if ($r->open && ($Now <= $r->done || ($r->ingrace ?? false)))
                    return true;
            }
        }
        return false;
    }

    function header_body($title, $id, $extra = []) {
        global $ConfSitePATH, $Me, $Now;
        echo "<body";
        if ($id) {
            echo ' id="body-', $id, '"';
        }
        $class = $extra["body_class"] ?? null;
        if (($list = $this->active_list())) {
            $class = ($class ? $class . " " : "") . "has-hotlist";
        }
        if ($class) {
            echo ' class="', $class, '"';
        }
        if ($list) {
            echo ' data-hotlist="', htmlspecialchars($list->info_string()), '"';
        }
        echo ">\n";

        // initial load (JS's timezone offsets are negative of PHP's)
        Ht::stash_script("hotcrp_load.time(" . (-(int) date("Z", $Now) / 60) . "," . ($this->opt("time24hour") ? 1 : 0) . ")");

        // deadlines settings
        $my_deadlines = null;
        if ($Me) {
            $my_deadlines = $Me->my_deadlines($this->paper);
            Ht::stash_script("hotcrp_deadlines.init(" . json_encode_browser($my_deadlines) . ")");
        }
        if ($this->default_format) {
            Ht::stash_script("render_text.set_default_format(" . $this->default_format . ")");
        }

        echo '<div id="top">';

        // site header
        if ($id === "home") {
            $site_div = '<div id="header-site" class="header-site-home">'
                . '<h1><a class="qq" href="' . $this->hoturl("index", ["cap" => null])
                . '">' . htmlspecialchars($this->short_name) . '</a></h1></div>';
        } else {
            $site_div = '<div id="header-site" class="header-site-page">'
                . '<a class="qq" href="' . $this->hoturl("index", ["cap" => null])
                . '"><span class="header-site-name">' . htmlspecialchars($this->short_name)
                . '</span> Home</a></div>';
        }

        // $header_profile
        $profile_html = "";
        if ($Me && !$Me->is_empty()) {
            // profile link
            $profile_parts = [];
            if ($Me->has_email() && !$Me->is_disabled()) {
                if (!$Me->is_anonymous_user()) {
                    $purl = $this->hoturl("profile");
                    $profile_parts[] = "<a class=\"q\" href=\"{$purl}\"><strong>" . htmlspecialchars($Me->email) . "</strong></a> &nbsp; <a href=\"{$purl}\">Profile</a>";
                } else {
                    $profile_parts[] = "<strong>" . htmlspecialchars($Me->email) . "</strong>";
                }
            }

            // "act as" link
            if (($actas = $_SESSION["last_actas"] ?? null)
                && (($Me->privChair && strcasecmp($actas, $Me->email) !== 0)
                    || Contact::$true_user)) {
                // Link becomes true user if not currently chair.
                $actas = Contact::$true_user ? Contact::$true_user->email : $actas;
                $profile_parts[] = "<a href=\""
                    . $this->selfurl(null, ["actas" => Contact::$true_user ? null : $actas]) . "\">"
                    . (Contact::$true_user ? "Admin" : htmlspecialchars($actas))
                    . "&nbsp;" . Ht::img("viewas.png", "Act as " . htmlspecialchars($actas))
                    . "</a>";
            }

            // help
            if (!$Me->is_disabled()) {
                $helpargs = ($id == "search" ? "t=$id" : ($id == "settings" ? "t=chair" : ""));
                $profile_parts[] = '<a href="' . $this->hoturl("help", $helpargs) . '">Help</a>';
            }

            // sign in and out
            if ((!$Me->is_signed_in() && !isset($this->opt["httpAuthLogin"]))
                && $id !== "signin") {
                $profile_parts[] = '<a href="' . $this->hoturl("signin", ["cap" => null]) . '" class="nw">Sign in</a>';
            }
            if ((!$Me->is_empty() || isset($this->opt["httpAuthLogin"]))
                && $id !== "signout") {
                $profile_parts[] = Ht::form($this->hoturl_post("signout", ["cap" => null]), ["class" => "d-inline"])
                    . Ht::button("Sign out", ["type" => "submit", "class" => "btn btn-link"])
                    . "</form>";
            }

            if (!empty($profile_parts))
                $profile_html .= join(' <span class="barsep">·</span> ', $profile_parts);
        }

        $action_bar = $extra["action_bar"] ?? null;
        if ($action_bar === null) {
            $action_bar = actionBar();
        }

        $title_div = $extra["title_div"] ?? null;
        if ($title_div === null) {
            if (($subtitle = $extra["subtitle"] ?? null)) {
                $title .= " &nbsp;&#x2215;&nbsp; <strong>" . $subtitle . "</strong>";
            }
            if ($title && $title !== "Home") {
                $title_div = '<div id="header-page"><h1>' . $title . '</h1></div>';
            } else if ($action_bar) {
                $title_div = '<hr class="c">';
            }
        }

        echo $site_div, '<div id="header-right">', $profile_html;
        if ($my_deadlines && $this->has_interesting_deadline($my_deadlines)) {
            echo '<div id="header-deadline">&nbsp;</div>';
        } else {
            echo '<div id="header-deadline" class="hidden"></div>';
        }
        echo '</div>', ($title_div ? : ""), ($action_bar ? : "");

        echo "  <hr class=\"c\">\n";

        $this->headerPrinted = true;
        echo "<div id=\"msgs-initial\">\n";
        if (($x = $this->opt("maintenance"))) {
            echo Ht::msg(is_string($x) ? $x : "<strong>The site is down for maintenance.</strong> Please check back later.", 2);
        }
        if ($Me
            && ($msgs = $Me->session("msgs"))
            && !empty($msgs)) {
            $Me->save_session("msgs", null);
            foreach ($msgs as $m)
                $this->msg($m[0], $m[1]);
        }
        if (isset($_COOKIE["hotcrpmessage"])) {
            $message = json_decode(rawurldecode($_COOKIE["hotcrpmessage"]));
            if (is_array($message)) {
                if (count($message) === 2
                    && (is_int($message[1]) || $message[1] === "confirm")) {
                    $message = [$message];
                }
                foreach ($message as $m) {
                    if (is_array($m)
                        && (is_int($m[1]) || $m[1] === "confirm")
                        && ($t = CleanHTML::basic_clean_all($m[0])) !== false) {
                        $this->msg($t, $m[1]);
                    }
                }
                hotcrp_setcookie("hotcrpmessage", "", ["expires" => $Now - 3600]);
            }
        }
        echo "</div></div>\n";

        echo "<div id=\"body\" class=\"body\">\n";

        // If browser owns tracker, send it the script immediately
        if ($this->setting("tracker")
            && MeetingTracker::session_owns_tracker($this))
            echo Ht::unstash();

        // Callback for version warnings
        if ($Me
            && $Me->privChair
            && (!isset($_SESSION["updatecheck"])
                || $_SESSION["updatecheck"] + 3600 <= $Now)
            && (!isset($this->opt["updatesSite"]) || $this->opt["updatesSite"])) {
            $m = isset($this->opt["updatesSite"]) ? $this->opt["updatesSite"] : "//hotcrp.lcdf.org/updates";
            $m .= (strpos($m, "?") === false ? "?" : "&")
                . "addr=" . urlencode($_SERVER["SERVER_ADDR"])
                . "&base=" . urlencode(Navigation::siteurl())
                . "&version=" . HOTCRP_VERSION;
            $v = HOTCRP_VERSION;
            if (is_dir("$ConfSitePATH/.git")) {
                $args = array();
                exec("export GIT_DIR=" . escapeshellarg($ConfSitePATH) . "/.git; git rev-parse HEAD 2>/dev/null; git merge-base origin/master HEAD 2>/dev/null", $args);
                if (count($args) >= 1) {
                    $m .= "&git-head=" . urlencode($args[0]);
                    $v .= " " . $args[0];
                }
                if (count($args) >= 2) {
                    $m .= "&git-upstream=" . urlencode($args[1]);
                    $v .= " " . $args[1];
                }
            }
            Ht::stash_script("check_version(\"$m\",\"$v\")");
            $_SESSION["updatecheck"] = $Now;
        }
    }

    function header($title, $id, $extra = []) {
        if (!$this->headerPrinted) {
            $this->header_head($title, $extra);
            $this->header_body($title, $id, $extra);
        }
    }

    static function git_status() {
        global $ConfSitePATH;
        $args = array();
        if (is_dir("$ConfSitePATH/.git")) {
            exec("export GIT_DIR=" . escapeshellarg($ConfSitePATH) . "/.git; git rev-parse HEAD 2>/dev/null; git rev-parse v" . HOTCRP_VERSION . " 2>/dev/null", $args);
        }
        return count($args) == 2 ? $args : null;
    }

    function footer() {
        global $Me;
        echo "<hr class=\"c\"></div>", // class='body'
            '<div id="footer">',
            $this->opt("extraFooter", ""),
            '<a class="uu" href="https://hotcrp.com/">HotCRP</a>';
        if (!$this->opt("noFooterVersion")) {
            if ($Me && $Me->privChair) {
                echo " v", HOTCRP_VERSION;
                if (($git_data = self::git_status())
                    && $git_data[0] !== $git_data[1]) {
                    echo " [", substr($git_data[0], 0, 7), "...]";
                }
            } else {
                echo "<!-- Version ", HOTCRP_VERSION, " -->";
            }
        }
        echo '</div>', Ht::unstash(), "</body>\n</html>\n";
    }

    /** @param Contact $viewer
     * @param Contact $user */
    private function pc_json_item($viewer, $user) {
        $name = $viewer->name_text_for($user);
        $j = (object) [
            "name" => $name !== "" ? $name : $user->email,
            "email" => $user->email
        ];
        if (($color_classes = $user->viewable_color_classes($viewer))) {
            $j->color_classes = $color_classes;
        }
        if ($this->sort_by_last && $user->lastName !== "") {
            self::pc_json_sort_by_last($j, $user);
        }
        return $j;
    }

    /** @param Contact $viewer
     * @param ReviewInfo $user
     * @return stdClass */
    private function pc_json_reviewer_item($viewer, $user) {
        $j = (object) [
            "name" => Text::nameo($user, NAME_P),
            "email" => $user->email
        ];
        if ($this->sort_by_last && $user->lastName !== "") {
            self::pc_json_sort_by_last($j, $user);
        }
        return $j;
    }

    /** @param Contact|ReviewInfo $r */
    static private function pc_json_sort_by_last($j, $r) {
        if (strlen($r->lastName) !== strlen($j->name)) {
            $j->lastpos = UnicodeHelper::utf16_strlen($r->firstName) + 1;
        }
        if (($r->nameAmbiguous ?? false) && $j->name !== "" && $r->email !== "") {
            $j->emailpos = UnicodeHelper::utf16_strlen($j->name) + 1;
        }
    }

    /** @return array<string,mixed> */
    function hotcrp_pc_json(Contact $viewer) {
        $hpcj = $list = $otherj = [];
        foreach ($this->pc_members() as $pcm) {
            $hpcj[$pcm->contactId] = $this->pc_json_item($viewer, $pcm);
            $list[] = $pcm->contactId;
        }
        $hpcj["__order__"] = $list;
        if ($this->sort_by_last) {
            $hpcj["__sort__"] = "last";
        }
        if ($viewer->can_view_user_tags()) {
            $hpcj["__tags__"] = $this->viewable_user_tags($viewer);
        }
        if ($this->paper
            && ($viewer->privChair || $viewer->allow_administer($this->paper))) {
            $list = [];
            foreach ($this->pc_members() as $pcm) {
                if ($pcm->can_accept_review_assignment($this->paper)) {
                    $list[] = $pcm->contactId;
                }
            }
            $hpcj["__assignable__"] = [$this->paper->paperId => $list];
            if ($this->setting("extrev_shepherd")) {
                $this->paper->ensure_reviewer_names();
                $erlist = [];
                foreach ($this->paper->reviews_by_display($viewer) as $rrow) {
                    if ($rrow->reviewType == REVIEW_EXTERNAL
                        && !$rrow->reviewToken
                        && !in_array($rrow->contactId, $erlist)) {
                        $otherj[$rrow->contactId] = $this->pc_json_reviewer_item($viewer, $rrow);
                        $erlist[] = $rrow->contactId;
                    }
                }
                if (!empty($erlist)) {
                    $hpcj["__extrev__"] = [$this->paper->paperId => $erlist];
                }
            }
        }
        if (!empty($otherj)) {
            $hpcj["__other__"] = $otherj;
        }
        return $hpcj;
    }

    function stash_hotcrp_pc(Contact $viewer, $always = false) {
        if (($always || !$this->opt("largePC"))
            && Ht::mark_stash("hotcrp_pc")) {
            Ht::stash_script("demand_load.pc(" . json_encode_browser($this->hotcrp_pc_json($viewer)) . ");");
        }
    }


    //
    // Action recording
    //

    const action_log_query = "insert into ActionLog (ipaddr, contactId, destContactId, trueContactId, paperId, timestamp, action) values ?v";
    const action_log_query_action_index = 6;

    function save_logs($on) {
        if ($on && $this->_save_logs === false) {
            $this->_save_logs = [];
        } else if (!$on && $this->_save_logs !== false) {
            $qv = [];
            '@phan-var-force list<list<string>> $qv';
            $last_pids = null;
            foreach ($this->_save_logs as $cid_text => $pids) {
                $pos = strpos($cid_text, "|");
                list($user, $dest_user, $true_user) = explode(",", substr($cid_text, 0, $pos));
                $what = substr($cid_text, $pos + 1);
                $pids = array_keys($pids);

                // Combine `Tag` messages
                if (substr($what, 0, 4) === "Tag "
                    && ($n = count($qv)) > 0
                    && substr($qv[$n-1][self::action_log_query_action_index], 0, 4) === "Tag "
                    && $last_pids === $pids) {
                    $qv[$n-1][self::action_log_query_action_index] .= substr($what, 3);
                } else {
                    foreach (self::format_log_values($what, $user, $dest_user, $true_user, $pids) as $x) {
                        $qv[] = $x;
                    }
                    $last_pids = $pids;
                }
            }
            if (!empty($qv)) {
                $this->qe(self::action_log_query, $qv);
            }
            $this->_save_logs = false;
        }
    }

    private static function log_clean_user($user, &$text) {
        if (!$user) {
            return 0;
        } else if (!is_numeric($user)) {
            if ($user->email
                && !$user->contactId
                && !$user->is_site_contact) {
                $suffix = " <{$user->email}>";
                if (!str_ends_with($text, $suffix)) {
                    $text .= $suffix;
                }
            }
            return $user->contactId;
        } else {
            return $user;
        }
    }

    /** @param null|int|Contact $user
     * @param null|int|Contact $dest_user
     * @param string $text
     * @param null|int|PaperInfo|list<int|PaperInfo> $pids */
    function log_for($user, $dest_user, $text, $pids = null) {
        if (is_object($pids)) {
            $pids = [$pids->paperId];
        } else if (is_array($pids)) {
            foreach ($pids as &$p) {
                $p = is_object($p) ? $p->paperId : $p;
            }
            unset($p);
        } else if ($pids === null || $pids <= 0) {
            $pids = [];
        } else {
            $pids = [$pids];
        }
        '@phan-var-force list<int> $pids';

        $true_user = 0;
        if ($user && is_object($user)) {
            if ($user->is_actas_user()) {
                $true_user = Contact::$true_user->contactId;
            } else if (!$user->contactId
                       && !empty($pids)
                       && $user->has_capability_for($pids[0])) {
                $true_user = -1; // indicate download via link
            }
        }
        $user = self::log_clean_user($user, $text);
        $dest_user = self::log_clean_user($dest_user, $text);

        if ($this->_save_logs === false) {
            $this->qe(self::action_log_query, self::format_log_values($text, $user, $dest_user, $true_user, $pids));
        } else {
            $key = "$user,$dest_user,$true_user|$text";
            if (!isset($this->_save_logs[$key])) {
                $this->_save_logs[$key] = [];
            }
            foreach ($pids as $p) {
                $this->_save_logs[$key][$p] = true;
            }
        }
    }

    /** @return list<list<string>> */
    private static function format_log_values($text, $user, $dest_user, $true_user, $pids) {
        global $Now;
        if (empty($pids)) {
            $pids = [null];
        }
        $addr = $_SERVER["REMOTE_ADDR"] ?? null;
        $user = (int) $user;
        $dest_user = (int) $dest_user;
        if ($dest_user === 0 || $dest_user === $user) {
            $dest_user = null;
        }
        $true_user = (int) $true_user;
        if ($true_user === 0) {
            $true_user = null;
        }
        $l = 0;
        $n = count($pids);
        $result = [];
        while ($l < $n) {
            $t = $text;
            $r = $n;
            while ($l + 1 !== $r) {
                $t = $text . " (papers ";
                if ($l === 0 && $r === $n) {
                    $t .= join(", ", $pids);
                } else {
                    $t .= join(", ", array_slice($pids, $l, $r - $l, true));
                }
                $t .= ")";
                if (strlen($t) <= 4096) {
                    break;
                }
                $r = $l + max(1, ($r - $l) >> 1);
            }
            if ($l + 1 === $r) {
                $pid = $pids[$l];
                $t = substr($text, 0, 4096);
            } else {
                $pid = null;
                $t = substr($t, 0, 4096);
            }
            $result[] = [$addr, $user, $dest_user, $true_user, $pid, $Now, $t];
            $l = $r;
        }
        return $result;
    }


    // messages

    /** @return IntlMsgSet */
    function ims() {
        if (!$this->_ims) {
            $this->_ims = new IntlMsgSet;
            $this->_ims->add_requirement_resolver([$this, "resolve_ims_requirement"]);
            $m = ["?etc/msgs.json"];
            if (($lang = $this->opt("lang"))) {
                $m[] = "?etc/msgs.$lang.json";
            }
            $this->_ims->set_default_priority(-1.0);
            expand_json_includes_callback($m, [$this->_ims, "addj"]);
            $this->_ims->clear_default_priority();
            if (($mlist = $this->opt("messageOverrides"))) {
                expand_json_includes_callback($mlist, [$this->_ims, "addj"]);
            }
            foreach ($this->settingTexts as $k => $v) {
                if (str_starts_with($k, "msg."))
                    $this->_ims->add_override(substr($k, 4), $v);
            }
        }
        return $this->_ims;
    }

    function _($itext) {
        return call_user_func_array([$this->ims(), "x"], func_get_args());
    }

    function _c($context, $itext) {
        return call_user_func_array([$this->ims(), "xc"], func_get_args());
    }

    function _i($id) {
        return call_user_func_array([$this->ims(), "xi"], func_get_args());
    }

    function _ci($context, $id) {
        return call_user_func_array([$this->ims(), "xci"], func_get_args());
    }

    function resolve_ims_requirement($s, $isreq) {
        if ($isreq) {
            return null;
        } else if (str_starts_with($s, "setting.")) {
            return [$this->setting(substr($s, 8))];
        } else if (str_starts_with($s, "opt.")) {
            return [$this->opt(substr($s, 4))];
        } else {
            return null;
        }
    }


    // search keywords

    function _add_search_keyword_json($kwj) {
        if (isset($kwj->name) && is_string($kwj->name)) {
            return self::xt_add($this->_search_keyword_base, $kwj->name, $kwj);
        } else if (is_string($kwj->match) && is_string($kwj->expand_callback)) {
            $this->_search_keyword_factories[] = $kwj;
            return true;
        } else {
            return false;
        }
    }
    private function make_search_keyword_map() {
        $this->_search_keyword_base = $this->_search_keyword_factories = [];
        expand_json_includes_callback(["etc/searchkeywords.json"], [$this, "_add_search_keyword_json"]);
        if (($olist = $this->opt("searchKeywords"))) {
            expand_json_includes_callback($olist, [$this, "_add_search_keyword_json"]);
        }
        usort($this->_search_keyword_factories, "Conf::xt_priority_compare");
    }
    function search_keyword($keyword, Contact $user = null) {
        if ($this->_search_keyword_base === null) {
            $this->make_search_keyword_map();
        }
        $uf = $this->xt_search_name($this->_search_keyword_base, $keyword, $user);
        $ufs = $this->xt_search_factories($this->_search_keyword_factories, $keyword, $user, $uf);
        return self::xt_resolve_require($ufs[0]);
    }


    // assignment parsers

    function _add_assignment_parser_json($uf) {
        if (isset($uf->name) && is_string($uf->name)) {
            return self::xt_add($this->_assignment_parsers, $uf->name, $uf);
        } else {
            return false;
        }
    }
    /** @return ?AssignmentParser */
    function assignment_parser($keyword, Contact $user = null) {
        require_once("assignmentset.php");
        if ($this->_assignment_parsers === null) {
            $this->_assignment_parsers = [];
            expand_json_includes_callback(["etc/assignmentparsers.json"], [$this, "_add_assignment_parser_json"]);
            if (($olist = $this->opt("assignmentParsers"))) {
                expand_json_includes_callback($olist, [$this, "_add_assignment_parser_json"]);
            }
        }
        $uf = $this->xt_search_name($this->_assignment_parsers, $keyword, $user);
        $uf = self::xt_resolve_require($uf);
        if ($uf && !isset($uf->__parser)) {
            $p = $uf->parser_class;
            $uf->__parser = new $p($this, $uf);
        }
        return $uf ? $uf->__parser : null;
    }


    // formula functions

    function _add_formula_function_json($fj) {
        if (isset($fj->name) && is_string($fj->name)) {
            return self::xt_add($this->_formula_functions, $fj->name, $fj);
        } else {
            return false;
        }
    }
    function formula_function($fname, Contact $user) {
        if ($this->_formula_functions === null) {
            $this->_formula_functions = [];
            expand_json_includes_callback(["etc/formulafunctions.json"], [$this, "_add_formula_function_json"]);
            if (($olist = $this->opt("formulaFunctions"))) {
                expand_json_includes_callback($olist, [$this, "_add_formula_function_json"]);
            }
        }
        $uf = $this->xt_search_name($this->_formula_functions, $fname, $user);
        return self::xt_resolve_require($uf);
    }


    // API

    function _add_api_json($fj) {
        if (isset($fj->name) && is_string($fj->name)) {
            return self::xt_add($this->_api_map, $fj->name, $fj);
        } else {
            return false;
        }
    }
    private function api_map() {
        if ($this->_api_map === null) {
            $this->_api_map = [];
            expand_json_includes_callback(["etc/apifunctions.json"], [$this, "_add_api_json"]);
            if (($olist = $this->opt("apiFunctions"))) {
                expand_json_includes_callback($olist, [$this, "_add_api_json"]);
            }
        }
        return $this->_api_map;
    }
    private function check_api_json($fj, $user, $method) {
        if (isset($fj->allow_if) && !$this->xt_allowed($fj, $user)) {
            return false;
        } else if (!$method) {
            return true;
        } else {
            $k = strtolower($method);
            $methodx = $fj->$k ?? null;
            return $methodx
                || ($method === "POST" && $methodx === null && get($fj, "get"));
        }
    }
    function has_api($fn, Contact $user = null, $method = null) {
        return !!$this->api($fn, $user, $method);
    }
    function api($fn, Contact $user = null, $method = null) {
        $this->_xt_allow_callback = function ($xt, $user) use ($method) {
            return $this->check_api_json($xt, $user, $method);
        };
        $uf = $this->xt_search_name($this->api_map(), $fn, $user);
        $this->_xt_allow_callback = null;
        return self::xt_enabled($uf) ? $uf : null;
    }
    private function call_api($fn, $uf, Contact $user, Qrequest $qreq, $prow) {
        $method = $qreq->method();
        if ($method !== "GET"
            && $method !== "HEAD"
            && $method !== "OPTIONS"
            && !$qreq->post_ok()
            && (!$uf || ($uf->post ?? false))
            && (!$uf || !($uf->allow_xss ?? false))) {
            return new JsonResult(403, "Missing credentials.");
        } else if ($user->is_disabled()
                   && (!$uf || !($uf->allow_disabled ?? false))) {
            return new JsonResult(403, "Your account is disabled.");
        } else if (!$uf) {
            if ($this->has_api($fn, $user, null)) {
                return new JsonResult(405, "Method not supported.");
            } else if ($this->has_api($fn, null, $qreq->method())) {
                return new JsonResult(403, "Permission error.");
            } else {
                return new JsonResult(404, "Function not found.");
            }
        } else if (!$prow && ($uf->paper ?? false)) {
            return self::paper_error_json_result($qreq->annex("paper_whynot"));
        } else if (!is_string($uf->callback)) {
            return new JsonResult(404, "Function not found.");
        } else {
            self::xt_resolve_require($uf);
            return call_user_func($uf->callback, $user, $qreq, $prow, $uf);
        }
    }
    static function paper_error_json_result($whynot) {
        $result = ["ok" => false];
        if ($whynot) {
            $status = isset($whynot["noPaper"]) ? 404 : 403;
            $result["error"] = whyNotText($whynot, true);
            if (isset($whynot["signin"])) {
                $result["loggedout"] = true;
            }
        } else {
            $status = 400;
            $result["error"] = "Bad request, missing submission.";
        }
        return new JsonResult($status, $result);
    }
    function call_api_exit($fn, Contact $user, Qrequest $qreq, PaperInfo $prow = null) {
        // XXX precondition: $user->can_view_paper($prow) || !$prow
        $uf = $this->api($fn, $user, $qreq->method());
        if ($uf && $qreq->redirect && ($uf->redirect ?? false)
            && preg_match('/\A(?![a-z]+:|\/)./', $qreq->redirect)) {
            try {
                JsonResultException::$capturing = true;
                $j = $this->call_api($fn, $uf, $user, $qreq, $prow);
            } catch (JsonResultException $ex) {
                $j = $ex->result;
            }
            if ($j instanceof JsonResult) {
                $a = $j->content;
            } else if (is_object($j)) {
                $a = get_object_vars($j);
            } else {
                assert(is_associative_array($j));
                $a = $j;
            }
            if (($x = $a["error"] ?? null)) { // XXX many instances of `error` are html
                Conf::msg_error(htmlspecialchars($x));
            } else if (($x = $a["error_html"] ?? null)) {
                Conf::msg_error($x);
            } else if (!($a["ok"] ?? false)) {
                Conf::msg_error("Internal error.");
            }
            Navigation::redirect_site($qreq->redirect);
        } else {
            json_exit($this->call_api($fn, $uf, $user, $qreq, $prow));
        }
    }


    // List action API

    function _add_list_action_json($fj) {
        $ok = false;
        if (isset($fj->name) && is_string($fj->name)) {
            if (isset($fj->render_callback) && is_string($fj->render_callback)) {
                $ok = self::xt_add($this->_list_action_renderers, $fj->name, $fj);
            }
            if (isset($fj->callback) && is_string($fj->callback)) {
                $ok = self::xt_add($this->_list_action_map, $fj->name, $fj);
            }
        } else if (is_string($fj->match) && is_string($fj->expand_callback)) {
            $this->_list_action_factories[] = $fj;
            $ok = true;
        }
        return $ok;
    }
    function list_action_map() {
        if ($this->_list_action_map === null) {
            $this->_list_action_map = $this->_list_action_renderers = $this->_list_action_factories = [];
            expand_json_includes_callback(["etc/listactions.json"], [$this, "_add_list_action_json"]);
            if (($olist = $this->opt("listActions"))) {
                expand_json_includes_callback($olist, [$this, "_add_list_action_json"]);
            }
            usort($this->_list_action_factories, "Conf::xt_priority_compare");
        }
        return $this->_list_action_map;
    }
    function list_action_renderers() {
        $this->list_action_map();
        return $this->_list_action_renderers;
    }
    function has_list_action($name, Contact $user = null, $method = null) {
        return !!$this->list_action($name, $user, $method);
    }
    function list_action($name, Contact $user = null, $method = null) {
        $this->_xt_allow_callback = function ($xt, $user) use ($method) {
            return $this->check_api_json($xt, $user, $method);
        };
        $uf = $this->xt_search_name($this->list_action_map(), $name, $user);
        if (($s = strpos($name, "/")) !== false) {
            $uf = $this->xt_search_name($this->list_action_map(), substr($name, 0, $s), $user, $uf);
        }
        $ufs = $this->xt_search_factories($this->_list_action_factories, $name, $user, $uf);
        $this->_xt_allow_callback = null;
        return self::xt_resolve_require($ufs[0]);
    }


    // paper columns

    function _add_paper_column_json($fj) {
        $ok = false;
        if (isset($fj->name) && is_string($fj->name)) {
            $ok = self::xt_add($this->_paper_column_map, $fj->name, $fj);
        }
        if (isset($fj->match)
            && is_string($fj->match)
            && isset($fj->expand_callback)
            && is_string($fj->expand_callback)) {
            $this->_paper_column_factories[] = $fj;
            $ok = true;
        }
        return $ok;
    }
    function paper_column_map() {
        if ($this->_paper_column_map === null) {
            require_once("papercolumn.php");
            $this->_paper_column_map = $this->_paper_column_factories = [];
            expand_json_includes_callback(["etc/papercolumns.json"], [$this, "_add_paper_column_json"]);
            if (($olist = $this->opt("paperColumns"))) {
                expand_json_includes_callback($olist, [$this, "_add_paper_column_json"]);
            }
            usort($this->_paper_column_factories, "Conf::xt_priority_compare");
        }
        return $this->_paper_column_map;
    }
    function paper_column_factories() {
        $this->paper_column_map();
        return $this->_paper_column_factories;
    }
    function basic_paper_column($name, Contact $user = null) {
        $uf = $this->xt_search_name($this->paper_column_map(), $name, $user);
        return self::xt_enabled($uf) ? $uf : null;
    }
    function paper_columns($name, Contact $user, $options = null) {
        if ($name === "" || $name[0] === "?") {
            return [];
        }
        $uf = $this->xt_search_name($this->paper_column_map(), $name, $user);
        $ufs = $this->xt_search_factories($this->_paper_column_factories, $name, $user, $uf, "i", $options);
        foreach ($ufs as $uf) {
            if ($uf && ($options || isset($uf->options)))
                $uf->options = $options;
        }
        return array_filter($ufs, "Conf::xt_resolve_require");
    }


    // option types

    function _add_option_type_json($fj) {
        $cb = isset($fj->callback) && is_string($fj->callback);
        if (isset($fj->name) && is_string($fj->name) && $cb) {
            return self::xt_add($this->_option_type_map, $fj->name, $fj);
        } else if (is_string($fj->match) && (isset($fj->expand_callback) ? is_string($fj->expand_callback) : $cb)) {
            $this->_option_type_factories[] = $fj;
            return true;
        } else {
            return false;
        }
    }
    function option_type_map() {
        if ($this->_option_type_map === null) {
            require_once("paperoption.php");
            $this->_option_type_map = $this->_option_type_factories = [];
            expand_json_includes_callback(["etc/optiontypes.json"], [$this, "_add_option_type_json"]);
            if (($olist = $this->opt("optionTypes")))
                expand_json_includes_callback($olist, [$this, "_add_option_type_json"]);
            usort($this->_option_type_factories, "Conf::xt_priority_compare");
            // option types are global (cannot be allowed per user)
            $m = [];
            foreach (array_keys($this->_option_type_map) as $name) {
                if (($uf = $this->xt_search_name($this->_option_type_map, $name, null)))
                    $m[$name] = $uf;
            }
            $this->_option_type_map = $m;
        }
        return $this->_option_type_map;
    }
    function option_type($name) {
        $uf = ($this->option_type_map())[$name] ?? null;
        $ufs = $this->xt_search_factories($this->_option_type_factories, $name, null, $uf, "i");
        return $ufs[0];
    }


    // capability tokens

    function _add_capability_json($fj) {
        $ok = false;
        if (isset($fj->match) && is_string($fj->match)
            && isset($fj->callback) && is_string($fj->callback)) {
            $this->_capability_factories[] = $fj;
            $ok = true;
        }
        if (isset($fj->type) && is_int($fj->type)) {
            self::xt_add($this->_capability_types, $fj->type, $fj);
        }
        return true;
    }
    function capability_type_map() {
        if ($this->_capability_factories === null) {
            $this->_capability_factories = [];
            $this->_capability_types = [];
            expand_json_includes_callback(["etc/capabilityhandlers.json"], [$this, "_add_capability_json"]);
            if (($olist = $this->opt("capabilityHandlers"))) {
                expand_json_includes_callback($olist, [$this, "_add_capability_json"]);
            }
            usort($this->_capability_factories, "Conf::xt_priority_compare");
            // option types are global (cannot be allowed per user)
            $m = [];
            foreach (array_keys($this->_capability_types) as $ct) {
                if (($uf = $this->xt_search_name($this->_capability_types, $ct, null)))
                    $m[$ct] = $uf;
            }
            $this->_capability_types = $m;
        }
        return $this->_capability_types;
    }
    function capability_handler($cap) {
        $this->capability_type_map();
        $ufs = $this->xt_search_factories($this->_capability_factories, $cap, null);
        return $ufs[0];
    }


    // mail keywords

    function _add_mail_keyword_json($fj) {
        if (isset($fj->name) && is_string($fj->name)) {
            return self::xt_add($this->_mail_keyword_map, $fj->name, $fj);
        } else if (is_string($fj->match)) {
            $this->_mail_keyword_factories[] = $fj;
            return true;
        } else {
            return false;
        }
    }
    private function mail_keyword_map() {
        if ($this->_mail_keyword_map === null) {
            $this->_mail_keyword_map = $this->_mail_keyword_factories = [];
            expand_json_includes_callback(["etc/mailkeywords.json"], [$this, "_add_mail_keyword_json"]);
            if (($mks = $this->opt("mailKeywords"))) {
                expand_json_includes_callback($mks, [$this, "_add_mail_keyword_json"]);
            }
            usort($this->_mail_keyword_factories, "Conf::xt_priority_compare");
        }
        return $this->_mail_keyword_map;
    }
    function mail_keywords($name) {
        $uf = $this->xt_search_name($this->mail_keyword_map(), $name, null);
        $ufs = $this->xt_search_factories($this->_mail_keyword_factories, $name, null, $uf);
        return array_filter($ufs, "Conf::xt_resolve_require");
    }


    // mail templates

    function _add_mail_template_json($fj) {
        if (isset($fj->name) && is_string($fj->name)) {
            if (is_array($fj->body)) {
                $fj->body = join("", $fj->body);
            }
            return self::xt_add($this->_mail_template_map, $fj->name, $fj);
        } else {
            return false;
        }
    }
    function mail_template_map() {
        if ($this->_mail_template_map === null) {
            $this->_mail_template_map = [];
            if ($this->opt("mailtemplate_include")) { // XXX backwards compatibility
                global $ConfSitePATH, $mailTemplates;
                $mailTemplates = [];
                read_included_options($this->opt["mailtemplate_include"]);
                '@phan-var-force array<string,mixed> $mailTemplates';
                foreach ($mailTemplates as $name => $template) {
                    error_log("Warning: Adding obsolete mail template for $name");
                    $template["name"] = $name;
                    $this->_add_mail_template_json((object) $template);
                }
            }
            expand_json_includes_callback(["etc/mailtemplates.json"], [$this, "_add_mail_template_json"]);
            if (($mts = $this->opt("mailTemplates"))) {
                expand_json_includes_callback($mts, [$this, "_add_mail_template_json"]);
            }
        }
        return $this->_mail_template_map;
    }
    function mail_template($name, $default_only = false) {
        $uf = $this->xt_search_name($this->mail_template_map(), $name, null);
        if (!$uf || !Conf::xt_resolve_require($uf))
            return null;
        if (!$default_only) {
            $se = $this->has_setting("mailsubj_$name");
            $s = $se ? $this->setting_data("mailsubj_$name") : null;
            $be = $this->has_setting("mailbody_$name");
            $b = $be ? $this->setting_data("mailbody_$name") : null;
            if (($se && $s !== $uf->subject)
                || ($be && $b !== $uf->body)) {
                $uf = clone $uf;
                if ($se) {
                    $uf->subject = $s;
                }
                if ($be) {
                    $uf->body = $b;
                }
            }
        }
        return $uf;
    }


    // hooks

    function _add_hook_json($fj) {
        if (isset($fj->callback) && is_string($fj->callback)) {
            if (isset($fj->event) && is_string($fj->event)) {
                return self::xt_add($this->_hook_map, $fj->event, $fj);
            } else if (isset($fj->match) && is_string($fj->match)) {
                $this->_hook_factories[] = $fj;
                return true;
            }
        }
        return false;
    }
    function add_hook($name, $callback = null, $priority = null) {
        if ($this->_hook_map === null) {
            $this->hook_map();
        }
        $fj = is_object($name) ? $name : $callback;
        if (is_string($fj)) {
            $fj = (object) ["callback" => $fj];
        }
        if (is_string($name)) {
            $fj->event = $name;
        }
        if ($priority !== null) {
            $fj->priority = $priority;
        }
        return $this->_add_hook_json($fj) ? $fj : false;
    }
    function remove_hook($fj) {
        if (isset($fj->event) && is_string($fj->event)
            && isset($this->_hook_map[$fj->event])
            && ($i = array_search($fj, $this->_hook_map[$fj->event], true)) !== false) {
            array_splice($this->_hook_map[$fj->event], $i, 1);
            return true;
        } else if (isset($fj->match) && is_string($fj->match)
                   && ($i = array_search($fj, $this->_hook_factories, true)) !== false) {
            array_splice($this->_hook_factories, $i, 1);
            return true;
        }
        return false;
    }
    private function hook_map() {
        if ($this->_hook_map === null) {
            $this->_hook_map = $this->_hook_factories = [];
            if (($hlist = $this->opt("hooks"))) {
                expand_json_includes_callback($hlist, [$this, "_add_hook_json"]);
            }
        }
        return $this->_hook_map;
    }
    function call_hooks($name, Contact $user = null /* ... args */) {
        $hs = ($this->hook_map())[$name] ?? null;
        foreach ($this->_hook_factories as $fj) {
            if ($fj->match === ".*"
                || preg_match("\1\\A(?:{$fj->match})\\z\1", $name, $m)) {
                $xfj = clone $fj;
                $xfj->event = $name;
                $xfj->match_data = $m;
                $hs = $hs ?? [];
                $hs[] = $xfj;
            }
        }
        if ($hs !== null) {
            $args = array_slice(func_get_args(), 1);
            usort($hs, "Conf::xt_priority_compare");
            $ids = [];
            foreach ($hs as $fj) {
                if ((!isset($fj->id) || !isset($ids[$fj->id]))
                    && $this->xt_allowed($fj, $user)) {
                    if (isset($fj->id)) {
                        $ids[$fj->id] = true;
                    }
                    if (self::xt_enabled($fj)) {
                        $fj->conf = $this;
                        $fj->user = $user;
                        $args[0] = $fj;
                        $x = call_user_func_array($fj->callback, $args);
                        unset($fj->conf, $fj->user);
                        if ($x === false) {
                            return false;
                        }
                    }
                }
            }
        }
    }


    // pages

    /** @return GroupedExtensions */
    function page_partials(Contact $viewer) {
        if (!$this->_page_partials || $this->_page_partials->viewer() !== $viewer) {
            $this->_page_partials = new GroupedExtensions($viewer, ["etc/pagepartials.json"], $this->opt("pagePartials"));
        }
        return $this->_page_partials;
    }
}
