<?php
// reviewinfo.php -- HotCRP class representing reviews
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

/** @property ?string $timeRequested
 * @property ?string $timeRequestNotified
 * @property ?string $reviewAuthorModified
 * @property ?string $reviewNotified
 * @property ?string $reviewAuthorNotified
 * @property ?string $reviewEditVersion
 * @property null|int|string $reviewWordCount
 * @property ?string $reviewFormat
 * @property ?string $data
 * @property ?string $sfields
 * @property ?string $tfields
 *
 * @property ?string $allRatings
 * @property ?string $firstName
 * @property ?string $lastName
 * @property ?string $email
 * @property ?string $reviewFirstName
 * @property ?string $reviewLastName
 * @property ?string $reviewEmail
 * @property ?string $reviewLastLogin
 * @property ?string $contactTags */
class ReviewInfo implements JsonSerializable {
    /** @var Conf */
    public $conf;
    /** @var int */
    public $paperId;
    /** @var int */
    public $reviewId;
    /** @var int */
    public $contactId;
    public $reviewToken;
    /** @var int */
    public $reviewType;
    public $reviewRound;
    public $requestedBy;
    //public $timeRequested;
    //public $timeRequestNotified;
    public $reviewBlind;
    /** @var int */
    public $reviewModified;
    //public $reviewAuthorModified;
    /** @var ?int */
    public $reviewSubmitted;
    //public $reviewNotified;
    //public $reviewAuthorNotified;
    /** @var ?int */
    public $reviewAuthorSeen;
    public $reviewOrdinal;
    public $timeDisplayed;
    public $timeApprovalRequested;
    //public $reviewEditVersion;
    public $reviewNeedsSubmit;
    /** @var int */
    public $reviewViewScore;
    // ... scores ...
    //public $reviewWordCount;
    //public $reviewFormat;
    //public $data;
    private $_data;

    const VIEWSCORE_RECOMPUTE = -100;

    /** @var array<non-empty-string,non-empty-string> */
    static public $text_field_map = [
        "paperSummary" => "t01", "commentsToAuthor" => "t02",
        "commentsToPC" => "t03", "commentsToAddress" => "t04",
        "weaknessOfPaper" => "t05", "strengthOfPaper" => "t06",
        "textField7" => "t07", "textField8" => "t08"
    ];
    /** @var list<?non-empty-string> */
    static private $new_text_fields = [
        null, "paperSummary", "commentsToAuthor", "commentsToPC",
        "commentsToAddress", "weaknessOfPaper", "strengthOfPaper",
        "textField7", "textField8"
    ];
    /** @var array<non-empty-string,non-empty-string> */
    static private $score_field_map = [
        "overAllMerit" => "s01", "reviewerQualification" => "s02",
        "novelty" => "s03", "technicalMerit" => "s04",
        "interestToCommunity" => "s05", "longevity" => "s06", "grammar" => "s07",
        "likelyPresentation" => "s08", "suitableForShort" => "s09",
        "potential" => "s10", "fixability" => "s11"
    ];
    /** @var list<?non-empty-string> */
    static private $new_score_fields = [
        null, "overAllMerit", "reviewerQualification", "novelty",
        "technicalMerit", "interestToCommunity", "longevity", "grammar",
        "likelyPresentation", "suitableForShort", "potential", "fixability"
    ];
    const MIN_SFIELD = 12;

    const RATING_GOODMASK = 1;
    const RATING_BADMASK = 126;
    // See also script.js:unparse_ratings
    static public $rating_options = [
        1 => "good review", 2 => "needs work",
        4 => "too short", 8 => "too vague", 16 => "too narrow",
        32 => "not constructive", 64 => "not correct"
    ];
    static public $rating_bits = [
        1 => "good", 2 => "bad", 4 => "short", 8 => "vague",
        16 => "narrow", 32 => "not-constructive", 64 => "wrong"
    ];

    static private $type_map = [
        "meta" => REVIEW_META,
        "primary" => REVIEW_PRIMARY, "pri" => REVIEW_PRIMARY,
        "secondary" => REVIEW_SECONDARY, "sec" => REVIEW_SECONDARY,
        "optional" => REVIEW_PC, "opt" => REVIEW_PC, "pc" => REVIEW_PC,
        "external" => REVIEW_EXTERNAL, "ext" => REVIEW_EXTERNAL
    ];
    static private $type_revmap = [
        REVIEW_EXTERNAL => "review", REVIEW_PC => "pcreview",
        REVIEW_SECONDARY => "secondary", REVIEW_PRIMARY => "primary",
        REVIEW_META => "metareview"
    ];

    static function parse_type($str) {
        $str = strtolower($str);
        if ($str === "review" || $str === "" || $str === "all" || $str === "any") {
            return null;
        }
        if (str_ends_with($str, "review")) {
            $str = substr($str, 0, -6);
        }
        return self::$type_map[$str] ?? false;
    }
    static function unparse_assigner_action($type) {
        return self::$type_revmap[$type] ?? "clearreview";
    }

    private function merge(Conf $conf, $recomputing_view_scores) {
        $this->conf = $conf;
        foreach (["paperId", "reviewId", "contactId", "reviewType",
                  "reviewRound", "requestedBy", "reviewBlind",
                  "reviewOrdinal", "reviewNeedsSubmit", "reviewViewScore",
                  "reviewModified"] as $k) {
            assert($this->$k !== null, "null $k");
            $this->$k = (int) $this->$k;
        }
        foreach (["reviewSubmitted", "reviewAuthorSeen"] as $k) {
            if (isset($this->$k)) {
                $this->$k = (int) $this->$k;
            }
        }
        if (isset($this->tfields) && ($x = json_decode($this->tfields, true))) {
            foreach ($x as $k => $v) {
                $this->$k = $v;
            }
        }
        if (isset($this->sfields) && ($x = json_decode($this->sfields, true))) {
            foreach ($x as $k => $v) {
                $this->$k = $v;
            }
        }
        if (!$recomputing_view_scores && $this->reviewViewScore == self::VIEWSCORE_RECOMPUTE) {
            assert($this->reviewViewScore != self::VIEWSCORE_RECOMPUTE);
            $conf->review_form()->compute_view_scores();
        }
    }
    /** @return ?ReviewInfo */
    static function fetch($result, Conf $conf, $recomputing_view_scores = false) {
        $rrow = $result ? $result->fetch_object("ReviewInfo") : null;
        '@phan-var ?ReviewInfo $rrow';
        if ($rrow) {
            $rrow->merge($conf, $recomputing_view_scores);
        }
        return $rrow;
    }
    static function review_signature_sql(Conf $conf, $scores = null) {
        $t = "r.reviewId, ' ', r.contactId, ' ', r.reviewToken, ' ', r.reviewType, ' ', r.reviewRound, ' ', r.requestedBy, ' ', r.reviewBlind, ' ', r.reviewModified, ' ', coalesce(r.reviewSubmitted,0), ' ', coalesce(r.reviewAuthorSeen,0), ' ', r.reviewOrdinal, ' ', r.timeDisplayed, ' ', r.timeApprovalRequested, ' ', r.reviewNeedsSubmit, ' ', r.reviewViewScore";
        foreach ($scores ?? [] as $fid) {
            if (($f = $conf->review_field($fid)) && $f->main_storage)
                $t .= ", ' " . $f->short_id . "=', " . $f->id;
        }
        return "group_concat($t order by r.reviewId)";
    }
    static function make_signature(PaperInfo $prow, $signature) {
        $rrow = new ReviewInfo;
        $rrow->paperId = $prow->paperId;
        $vals = explode(" ", $signature);
        $rrow->reviewId = (int) $vals[0];
        $rrow->contactId = (int) $vals[1];
        $rrow->reviewToken = $vals[2];
        $rrow->reviewType = (int) $vals[3];
        $rrow->reviewRound = (int) $vals[4];
        $rrow->requestedBy = (int) $vals[5];
        $rrow->reviewBlind = (int) $vals[6];
        $rrow->reviewModified = (int) $vals[7];
        $rrow->reviewSubmitted = (int) $vals[8];
        $rrow->reviewAuthorSeen = (int) $vals[9];
        $rrow->reviewOrdinal = (int) $vals[10];
        $rrow->timeDisplayed = (int) $vals[11];
        $rrow->timeApprovalRequested = (int) $vals[12];
        $rrow->reviewNeedsSubmit = (int) $vals[13];
        $rrow->reviewViewScore = (int) $vals[14];
        for ($i = 15; isset($vals[$i]); ++$i) {
            $eq = strpos($vals[$i], "=");
            $f = self::field_info(substr($vals[$i], 0, $eq), $prow->conf);
            $fid = $f->id;
            $rrow->$fid = substr($vals[$i], $eq + 1);
            $prow->_mark_has_score($fid);
        }
        $rrow->merge($prow->conf, false);
        return $rrow;
    }


    /** @return bool */
    function is_subreview() {
        return $this->reviewType == REVIEW_EXTERNAL
            && !$this->reviewSubmitted
            && !$this->reviewOrdinal
            && ($this->timeApprovalRequested < 0 || $this->conf->ext_subreviews);
    }

    /** @return bool */
    function needs_approval() {
        return $this->reviewType == REVIEW_EXTERNAL
            && !$this->reviewSubmitted
            && $this->requestedBy
            && $this->conf->ext_subreviews > 1;
    }

    /** @return string */
    function round_name() {
        return $this->reviewRound ? $this->conf->round_name($this->reviewRound) : "";
    }

    /** @return string */
    function type_icon() {
        if ($this->is_subreview()) {
            $title = "Subreview";
        } else {
            $title = ReviewForm::$revtype_names_full[$this->reviewType];
        }
        $t = '<span class="rto rt' . $this->reviewType;
        if (!$this->reviewSubmitted) {
            if ($this->timeApprovalRequested < 0) {
                $t .= " rtsubrev";
            } else {
                $t .= " rtinc";
            }
            if ($title !== "Subreview" || $this->timeApprovalRequested >= 0) {
                $title .= " (" . $this->status_description() . ")";
            }
        }
        return $t . '" title="' . $title . '"><span class="rti">'
            . ReviewForm::$revtype_icon_text[$this->reviewType]
            . '</span></span>';
    }

    /** @return string */
    function status_description() {
        if ($this->reviewSubmitted) {
            return "complete";
        } else if ($this->reviewType == REVIEW_EXTERNAL
                   && $this->timeApprovalRequested < 0) {
            return "approved";
        } else if ($this->reviewType == REVIEW_EXTERNAL
                   && $this->timeApprovalRequested > 0) {
            return "pending approval";
        } else if ($this->reviewModified > 1) {
            return "draft";
        } else if ($this->reviewType == REVIEW_SECONDARY
                   && $this->reviewNeedsSubmit <= 0
                   && $this->conf->ext_subreviews < 3) {
            return "delegated";
        } else if ($this->reviewModified > 0) {
            return "started";
        } else {
            return "not started";
        }
    }

    /** @return string */
    function unparse_ordinal() {
        return unparseReviewOrdinal($this);
    }


    function assign_name($c) {
        $this->firstName = $c->firstName;
        $this->lastName = $c->lastName;
        $this->email = $c->email;
        $this->contactTags = $c->contactTags;
    }

    /** @param string $id
     * @return ?ReviewFieldInfo */
    static function field_info($id, Conf $conf) {
        if (strlen($id) === 3 && ctype_digit(substr($id, 1))) {
            $n = intval(substr($id, 1), 10);
            $json_storage = $id;
            if ($id[0] === "s" && isset(self::$new_score_fields[$n])) {
                $fid = self::$new_score_fields[$n];
                return new ReviewFieldInfo($fid, $id, true, $fid, null);
            } else if ($id[0] === "s" || $id[0] === "t") {
                return new ReviewFieldInfo($id, $id, $id[0] === "s", null, $id);
            } else {
                return null;
            }
        } else if (isset(self::$text_field_map[$id])) {
            $short_id = self::$text_field_map[$id];
            return new ReviewFieldInfo($short_id, $short_id, false, null, $short_id);
        } else if (isset(self::$score_field_map[$id])) {
            $short_id = self::$score_field_map[$id];
            return new ReviewFieldInfo($id, $short_id, true, $id, null);
        } else {
            return null;
        }
    }

    /** @return bool */
    function field_match_pregexes($reg, $field) {
        $data = $this->$field;
        $field_deaccent = $field . "_deaccent";
        if (!isset($this->$field_deaccent)) {
            if (is_usascii($data)) {
                $this->$field_deaccent = false;
            } else {
                $this->$field_deaccent = UnicodeHelper::deaccent($data);
            }
        }
        return Text::match_pregexes($reg, $data, $this->$field_deaccent);
    }

    function unparse_sfields() {
        $data = [];
        foreach (get_object_vars($this) as $k => $v) {
            if (strlen($k) === 3
                && $k[0] === "s"
                && (int) $v !== 0
                && ($n = cvtint(substr($k, 1))) >= self::MIN_SFIELD)
                $data[$k] = (int) $v;
        }
        return empty($data) ? null : json_encode_db($data);
    }

    function unparse_tfields() {
        global $Conf;
        $data = [];
        foreach (get_object_vars($this) as $k => $v) {
            if (strlen($k) === 3
                && $k[0] === "t"
                && $v !== null
                && $v !== "")
                $data[$k] = $v;
        }
        if (empty($data)) {
            return null;
        } else {
            $json = json_encode_db($data);
            if ($json === null) {
                error_log(($Conf ? "{$Conf->dbname}: " : "") . "review #{$this->paperId}/{$this->reviewId}: text fields cannot be converted to JSON");
            }
            return $json;
        }
    }

    static function compare_id($a, $b) {
        if ($a->paperId != $b->paperId) {
            return (int) $a->paperId < (int) $b->paperId ? -1 : 1;
        } else if ($a->reviewId != $b->reviewId) {
            return (int) $a->reviewId < (int) $b->reviewId ? -1 : 1;
        } else {
            return 0;
        }
    }


    /** @return array<int,int> */
    function ratings() {
        $ratings = [];
        if ((string) $this->allRatings !== "") {
            foreach (explode(",", $this->allRatings) as $rx) {
                list($cid, $rating) = explode(" ", $rx);
                $ratings[(int) $cid] = intval($rating);
            }
        }
        return $ratings;
    }

    /** @param int|Contact $user
     * @return ?int */
    function rating_of_user($user) {
        $cid = is_object($user) ? $user->contactId : $user;
        $str = ",$cid ";
        $pos = strpos("," . $this->allRatings, $str);
        if ($pos !== false) {
            return intval(substr($this->allRatings, $pos + strlen($str) - 1));
        } else {
            return null;
        }
    }

    static function unparse_rating($rating) {
        if (isset(self::$rating_bits[$rating])) {
            return self::$rating_bits[$rating];
        } else if (!$rating) {
            return "none";
        } else {
            $a = [];
            foreach (self::$rating_bits as $k => $v)
                if ($rating & $k)
                    $a[] = $v;
            return join(" ", $a);
        }
    }

    static function parse_rating($s) {
        if (ctype_digit($s)) {
            $n = intval($s);
            if ($n >= 0 && $n < 127)
                return $n ? : null;
        }
        $n = 0;
        foreach (preg_split('/\s+/', $s) as $word) {
            if (($k = array_search($word, ReviewInfo::$rating_bits)) !== false) {
                $n |= $k;
            } else if ($word !== "" && $word !== "none") {
                return false;
            }
        }
        return $n;
    }


    private function _load_data() {
        if (!property_exists($this, "data")) {
            $this->data = $this->conf->fetch_value("select `data` from PaperReview where paperId=? and reviewId=?", $this->paperId, $this->reviewId);
        }
        $this->_data = $this->data ? json_decode($this->data) : (object) [];
    }

    private function _save_data() {
        $this->data = json_encode_db($this->_data);
        if ($this->data === "{}") {
            $this->data = null;
        }
        $this->conf->qe("update PaperReview set `data`=? where paperId=? and reviewId=?", $this->data, $this->paperId, $this->reviewId);
    }

    function acceptor() {
        global $Now;
        if ($this->_data === null) {
            $this->_load_data();
        }
        if (!isset($this->_data->acceptor)) {
            $text = base48_encode(random_bytes(10));
            $this->_data->acceptor = (object) ["text" => $text, "at" => $Now];
            $this->_save_data();
        }
        return $this->_data->acceptor;
    }
    function acceptor_is($text) {
        if ($this->_data === null) {
            $this->_load_data();
        }
        return isset($this->_data->acceptor)
            && $this->_data->acceptor->text === $text;
    }
    function delete_acceptor() {
        if ($this->_data === null) {
            $this->_load_data();
        }
        if (isset($this->_data->acceptor) && $this->_data->acceptor->at) {
            $this->_data->acceptor->at = 0;
            $this->_save_data();
        }
    }

    function jsonSerialize() {
        $j = ["confid" => $this->conf->dbname];
        foreach (get_object_vars($this) as $k => $v) {
            if ($k !== "conf" && $k !== "_data") {
                $j[$k] = $v;
            }
        }
        return $j;
    }
}
