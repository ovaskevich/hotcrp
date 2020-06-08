<?php
// paperinfo.php -- HotCRP paper objects
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class PaperContactInfo {
    /** @var int */
    public $paperId;
    /** @var int */
    public $contactId;
    /** @var int */
    public $conflictType = 0;
    /** @var int */
    public $reviewType = 0;
    /** @var int */
    public $reviewSubmitted = 0;
    /** @var int */
    public $review_status = 0;    // 0 means no review
    const RS_DECLINED = 1;        // declined assigned review
    const RS_UNSUBMITTED = 2;     // review not submitted, needs submit
    const RS_PROXIED = 3;         // review proxied (e.g., lead)
    const RS_SUBMITTED = 4;       // review submitted

    /** @var ?bool */
    public $rights_forced = null;
    /** @var ?PaperContactInfo */
    private $forced_rights_link = null;

    // set by Contact::rights()
    /** @var bool */
    public $allow_administer;
    /** @var bool */
    public $can_administer;
    /** @var bool */
    public $primary_administrator;
    /** @var bool */
    public $allow_pc_broad;
    /** @var bool */
    public $allow_pc;
    /** @var bool */
    public $potential_reviewer;
    /** @var bool */
    public $allow_review;
    /** @var bool */
    public $act_author;
    /** @var bool */
    public $allow_author;
    /** @var int */
    public $view_conflict_type;
    /** @var bool */
    public $act_author_view;
    /** @var bool */
    public $allow_author_view;
    /** @var bool */
    public $can_view_decision;
    /** @var int */
    public $view_authors_state;

    // cached by PaperInfo methods
    /** @var ?list<ReviewInfo> */
    public $vsreviews_array;
    /** @var ?int */
    public $vsreviews_version;
    /** @var ?string */
    public $viewable_tags;
    /** @var ?string */
    public $searchable_tags;

    static function make_empty(PaperInfo $prow, $user) {
        $ci = new PaperContactInfo;
        $ci->paperId = $prow->paperId;
        $ci->contactId = $user->contactXid;
        if ($user->contactId > 0
            && $user->isPC
            && isset($prow->leadContactId)
            && $prow->leadContactId == $user->contactId
            && !$prow->conf->setting("lead_noseerev")) {
            $ci->review_status = PaperContactInfo::RS_PROXIED;
        }
        return $ci;
    }

    static function make_my(PaperInfo $prow, $user, $object) {
        $ci = PaperContactInfo::make_empty($prow, $user);
        $ci->conflictType = (int) $object->conflictType;
        if (property_exists($object, "myReviewPermissions")) {
            $ci->mark_my_review_permissions($object->myReviewPermissions);
        } else if ($object instanceof PaperInfo
                   && property_exists($object, "reviewSignatures")) {
            foreach ($object->reviews_of_user($user->contactId, $user->review_tokens()) as $rrow)
                $ci->mark_review($rrow);
        }
        return $ci;
    }

    private function mark_conflict($ct) {
        $this->conflictType = max($ct, $this->conflictType);
    }

    private function mark_review_type($rt, $rs, $rns) {
        $this->reviewType = max($rt, $this->reviewType);
        $this->reviewSubmitted = max($rs, $this->reviewSubmitted);
        if ($rt > 0) {
            if ($rs > 0 || $rns == 0) {
                $this->review_status = PaperContactInfo::RS_SUBMITTED;
            } else if ($this->review_status == 0) {
                $this->review_status = PaperContactInfo::RS_UNSUBMITTED;
            }
        }
    }

    function mark_review(ReviewInfo $rrow) {
        $this->mark_review_type($rrow->reviewType, (int) $rrow->reviewSubmitted, $rrow->reviewNeedsSubmit);
    }

    private function mark_my_review_permissions($sig) {
        if ((string) $sig !== "") {
            foreach (explode(",", $sig) as $r) {
                list($rt, $rs, $rns) = explode(" ", $r);
                $this->mark_review_type((int) $rt, (int) $rs, (int) $rns);
            }
        }
    }

    static function load_into(PaperInfo $prow, $user) {
        global $Me;
        $conf = $prow->conf;
        $pid = $prow->paperId;
        $q = "select conflictType, reviewType, reviewSubmitted, reviewNeedsSubmit";
        $cid = $user->contactXid;
        $rev_tokens = $user->review_tokens();
        if ($cid > 0
            && !$rev_tokens
            && ($row_set = $prow->_row_set)
            && $row_set->size() > 1) {
            $result = $conf->qe("$q, Paper.paperId paperId, ? contactId
                from Paper
                left join PaperConflict on (PaperConflict.paperId=Paper.paperId and PaperConflict.contactId=?)
                left join PaperReview on (PaperReview.paperId=Paper.paperId and PaperReview.contactId=?)
                where Paper.paperId?a",
                $cid, $cid, $cid, $row_set->paper_ids());
            foreach ($row_set as $row) {
                $row->_clear_contact_info($user);
            }
            while (($local = $result->fetch_row())) {
                $row = $row_set->get((int) $local[4]);
                $ci = $row->_get_contact_info((int) $local[5]);
                $ci->mark_conflict((int) $local[0]);
                $ci->mark_review_type((int) $local[1], (int) $local[2], (int) $local[3]);
            }
            Dbl::free($result);
            return;
        }
        if ($cid > 0
            && !$rev_tokens
            && (!$Me || ($Me->contactId != $cid
                         && ($Me->privChair || $Me->contactId == $prow->managerContactId)))
            && ($pcm = $conf->pc_members())
            && isset($pcm[$cid])) {
            foreach ($pcm as $u) {
                $prow->_clear_contact_info($u);
            }
            $result = $conf->qe("$q, ContactInfo.contactId
                from ContactInfo
                left join PaperConflict on (PaperConflict.paperId=? and PaperConflict.contactId=ContactInfo.contactId)
                left join PaperReview on (PaperReview.paperId=? and PaperReview.contactId=ContactInfo.contactId)
                where roles!=0 and (roles&" . Contact::ROLE_PC . ")!=0",
                $pid, $pid);
        } else {
            $prow->_clear_contact_info($user);
            if ($cid > 0 || $rev_tokens) {
                $q = "$q, ? contactId
                from (select ? paperId) P
                left join PaperConflict on (PaperConflict.paperId=? and PaperConflict.contactId=?)
                left join PaperReview on (PaperReview.paperId=? and (PaperReview.contactId=?";
                $qv = [$cid, $pid, $pid, $cid, $pid, $cid];
                if ($rev_tokens) {
                    $q .= " or PaperReview.reviewToken?a";
                    $qv[] = $rev_tokens;
                }
                $result = $conf->qe_apply("$q))", $qv);
            } else {
                $result = null;
            }
        }
        while ($result && ($local = $result->fetch_row())) {
            $ci = $prow->_get_contact_info((int) $local[4]);
            $ci->mark_conflict((int) $local[0]);
            $ci->mark_review_type((int) $local[1], (int) $local[2], (int) $local[3]);
        }
        Dbl::free($result);
    }

    function get_forced_rights() {
        if (!$this->forced_rights_link) {
            $ci = $this->forced_rights_link = clone $this;
            $ci->vsreviews_array = $ci->viewable_tags = $ci->searchable_tags = null;
        }
        return $this->forced_rights_link;
    }
}

class PaperInfo_Conflict {
    /** @var int */
    public $contactId;
    /** @var int */
    public $conflictType;
    /** @var string */
    public $email;

    /** @param int $cid
     * @param int $ctype
     * @param ?string $email */
    function __construct($cid, $ctype, $email = null) {
        $this->contactId = (int) $cid;
        $this->conflictType = (int) $ctype;
        $this->email = $email;
    }
    /** @return bool */
    function is_conflicted() {
        return $this->conflictType > CONFLICT_MAXUNCONFLICTED;
    }
}

class PaperInfoSet implements ArrayAccess, IteratorAggregate, Countable {
    /** @var list<PaperInfo> */
    private $prows = [];
    /** @var array<int,PaperInfo> */
    private $by_pid = [];
    private $_need_pid_sort = false;
    public $loaded_allprefs = 0;
    function __construct(PaperInfo $prow = null) {
        if ($prow) {
            $this->add($prow, true);
        }
    }
    function add(PaperInfo $prow, $copy = false) {
        $this->prows[] = $prow;
        if (!isset($this->by_pid[$prow->paperId])) {
            $this->by_pid[$prow->paperId] = $prow;
        }
        if (!$copy) {
            assert(!$prow->_row_set);
            $prow->_row_set = $this;
        }
    }
    function take_all(PaperInfoSet $set) {
        foreach ($set->prows as $prow) {
            $prow->_row_set = null;
            $this->add($prow);
        }
        $set->prows = $set->by_pid = [];
    }
    /** @return list<PaperInfo> */
    function as_array() {
        return $this->prows;
    }
    /** @return list<PaperInfo> */
    function all() {
        return $this->prows;
    }
    /** @return int */
    function size() {
        return count($this->prows);
    }
    /** @return int */
    function count() {
        return count($this->prows);
    }
    /** @return bool */
    function is_empty() {
        return empty($this->prows);
    }
    function sort_by($compare) {
        usort($this->prows, $compare);
        $this->_need_pid_sort = true;
    }
    /** @return list<int> */
    function paper_ids() {
        if ($this->_need_pid_sort) {
            $by_pid = [];
            foreach ($this->prows as $prow) {
                if (!isset($by_pid[$prow->paperId]))
                    $by_pid[$prow->paperId] = $this->by_pid[$prow->paperId];
            }
            $this->by_pid = $by_pid;
            $this->_need_pid_sort = false;
        }
        return array_keys($this->by_pid);
    }
    /** @param int $pid
     * @return ?PaperInfo */
    function paper_by_id($pid) {
        return $this->by_pid[$pid] ?? null;
    }
    /** @param int $pid
     * @return PaperInfo */
    function checked_paper_by_id($pid) {
        $prow = $this->by_pid[$pid] ?? null;
        if (!$prow) {
            throw new Exception("PaperInfoSet::checked_paper_by_id($pid) failure");
        }
        return $prow;
    }
    /** @param int $pid
     * @return ?PaperInfo */
    function get($pid) {
        return $this->by_pid[$pid] ?? null;
    }
    /** @param callable(PaperInfo):bool $func
     * @return PaperInfoSet */
    function filter($func) {
        $next_set = new PaperInfoSet;
        foreach ($this->prows as $prow) {
            if (call_user_func($func, $prow))
                $next_set->add($prow, true);
        }
        return $next_set;
    }
    /** @param callable(PaperInfo):bool $func */
    function apply_filter($func) {
        $nprows = $by_pid = [];
        foreach ($this->prows as $prow) {
            if (call_user_func($func, $prow)) {
                $nprows[] = $prow;
                if (!isset($by_pid[$prow->paperId])) {
                    $by_pid[$prow->paperId] = $prow;
                }
            }
        }
        $this->prows = $nprows;
        $this->by_pid = $by_pid;
        $this->_need_pid_sort = false;
    }
    /** @param callable(PaperInfo):bool $func */
    function any($func) {
        foreach ($this as $prow) {
            if (($x = call_user_func($func, $prow)))
                return $x;
        }
        return false;
    }
    /** @return Iterator<PaperInfo> */
    function getIterator() {
        return new ArrayIterator($this->prows);
    }
    function offsetExists($offset) {
        return isset($this->by_pid[$offset]);
    }
    /** @return ?PaperInfo */
    function offsetGet($offset) {
        return $this->by_pid[$offset] ?? null;
    }
    function offsetSet($offset, $value) {
        error_log("invalid PaperInfoSet::offsetSet");
    }
    function offsetUnset($offset) {
        error_log("invalid PaperInfoSet::offsetSet");
    }
}

/** @property ?string $pdfFormatStatus
 * @property ?string $withdrawReason
 * @property ?string $timeFinalSubmitted
 * @property ?string $size
 * @property ?string $mimetype
 * @property ?string $blind
 * @property ?string $sha1
 * @property ?string $leadContactId
 * @property ?string $shepherdContactId
 * @property ?string $capVersion
 *
 * @property ?string $paperTags
 * @property ?string $optionIds
 * @property ?string $topicIds
 * @property ?string $conflictType
 * @property ?string $watch
 * @property ?string $allConflictType
 * @property ?string $reviewSignatures
 * @property ?string $reviewWordCountSignature
 * @property ?string $commentSkeletonInfo
 * @property ?string $myReviewPermissions
 * @property ?string $allReviewerPreference
 * @property ?string $myReviewerPreference
 * @property ?string $myReviewerExpertise
 */
class PaperInfo {
    /** @var int */
    public $paperId;
    /** @var Conf */
    public $conf;
    /** @var string */
    public $title;
    public $authorInformation;
    public $abstract;
    public $collaborators;
    public $timeSubmitted;
    public $timeWithdrawn;
    public $paperStorageId;
    public $finalPaperStorageId;
    public $managerContactId;
    public $paperFormat;
    public $outcome;
    public $dataOverflow;
    // $paperTags: DO NOT LIST (property_exists() is meaningful)
    // $optionIds: DO NOT LIST (property_exists() is meaningful)
    // $topicIds: DO NOT LIST (property_exists() is meaningful)
    // $allConflictType: DO NOT LIST (property_exists() is meaningful)
    // $reviewSignatures: DO NOT LIST (property_exists() is meaningful)

    /** @var array<int,PaperContactInfo> */
    private $_contact_info = [];
    private $_rights_version = 0;
    /** @var ?list<Author> */
    private $_author_array;
    /** @var ?list<AuthorMatcher> */
    private $_collaborator_array;
    /** @var ?array<int,array{int,?int}> */
    private $_prefs_array;
    /** @var ?array{int,?array{int,?int}} */
    private $_prefs_cid;
    /** @var ?int */
    private $_desirability;
    /** @var ?list<int> */
    private $_topics_array;
    /** @var ?array<int,float> */
    private $_topic_interest_score_array;
    /** @var ?array<int,list<int>> */
    private $_option_values;
    /** @var ?array<int,list<?string>> */
    private $_option_data;
    /** @var ?array<int,PaperValue> */
    private $_option_array;
    /** @var array<int,PaperValue> */
    private $_new_option_array;
    /** @var array<int,DocumentInfo> */
    private $_document_array;
    /** @var ?array<int,array<int,int>> */
    private $_doclink_array;
    /** @var ?array<int,PaperInfo_Conflict> */
    private $_conflict_array;
    /** @var bool */
    private $_conflict_array_email;
    /** @var ?array<int,ReviewInfo> */
    private $_review_array;
    /** @var int */
    private $_review_array_version = 0;
    private $_reviews_have = [];
    /** @var ?list<ReviewInfo> */
    private $_full_review;
    /** @var ?string */
    private $_full_review_key;
    /** @var ?array<int,CommentInfo> */
    private $_comment_array;
    /** @var ?array<int,CommentInfo> */
    private $_comment_skeleton_array;
    /** @var ?list<array{string,string}> */
    private $_potential_conflicts;
    private $_potential_conflict_flags;
    /** @var ?list<ReviewRequestInfo> */
    private $_request_array;
    /** @var ?list<ReviewRefusalInfo> */
    private $_refusal_array;
    /** @var ?Contact */
    private $_author_view_user;
    /** @var ?PaperInfoSet */
    public $_row_set;

    const SUBMITTED_AT_FOR_WITHDRAWN = 1000000000;

    /** @param ?array<string,null|string|int> $p
     * @param ?Contact $contact */
    function __construct($p = null, $contact = null, Conf $conf = null) {
        $this->merge($p, $contact, $conf);
    }

    /** @param ?array<string,null|string|int> $p
     * @param ?Contact $contact
     * @param ?Conf $conf */
    private function merge($p, $contact, $conf) {
        assert($contact === null ? $conf !== null : $contact instanceof Contact);
        $this->conf = $contact ? $contact->conf : $conf;
        if ($p) {
            foreach ($p as $k => $v) {
                $this->$k = $v;
            }
        }
        $this->paperId = (int) $this->paperId;
        $this->managerContactId = (int) $this->managerContactId;
        if ($contact) {
            if (property_exists($this, "myReviewPermissions")
                || property_exists($this, "reviewSignatures")) {
                $this->_rights_version = Contact::$rights_version;
                $this->load_my_contact_info($contact, $this);
            } else {
                assert(!property_exists($this, "conflictType"));
            }
            if (property_exists($this, "myReviewerPreference")) {
                $rp = (int) $this->myReviewerPreference;
                $re = $this->myReviewerExpertise;
                $this->_prefs_cid = [$contact->contactId, [$rp, $re !== null ? (int) $re : null]];
            }
        }
        foreach (["paperTags", "optionIds"] as $k) {
            if (property_exists($this, $k) && $this->$k === null)
                $this->$k = "";
        }
        if (isset($this->dataOverflow) && is_string($this->dataOverflow)) {
            $this->dataOverflow = json_decode($this->dataOverflow, true);
            if ($this->dataOverflow === null) {
                error_log("{$this->conf->dbname}: #{$this->paperId}: bad dataOverflow");
            }
        }
    }

    /** @param Dbl_Result $result
     * @param ?Contact $contact
     * @return ?PaperInfo */
    static function fetch($result, $contact, Conf $conf = null) {
        $prow = $result->fetch_object("PaperInfo", [null, $contact, $conf]);
        if ($prow && !is_int($prow->paperId)) {
            $prow->merge(null, $contact, $conf);
        }
        return $prow;
    }

    /** @return PaperInfo */
    static function make_new(Contact $user) {
        assert($user->contactId === $user->contactXid);
        $prow = new PaperInfo(null, null, $user->conf);
        $prow->abstract = $prow->title = $prow->collaborators =
            $prow->authorInformation = $prow->paperTags = $prow->optionIds =
            $prow->topicIds = "";
        $prow->leadContactId = $prow->shepherdContactId = "0";
        $prow->blind = "1";
        $prow->allConflictType = $user->contactId . " " . CONFLICT_CONTACTAUTHOR;
        $prow->check_rights_version();
        $ci = PaperContactInfo::make_empty($prow, $user);
        $ci->conflictType = CONFLICT_CONTACTAUTHOR;
        $prow->_contact_info[$ci->contactId] = $ci;
        $prow->_comment_skeleton_array = $prow->_comment_array = [];
        return $prow;
    }

    static function table_name() {
        return "Paper";
    }

    static function id_column() {
        return "paperId";
    }

    static function comment_table_name() {
        return "PaperComment";
    }

    static function my_review_permissions_sql($prefix = "") {
        return "group_concat({$prefix}reviewType, ' ', coalesce({$prefix}reviewSubmitted,0), ' ', reviewNeedsSubmit)";
    }

    function make_whynot($rest = []) {
        return ["fail" => true, "paperId" => $this->paperId, "conf" => $this->conf] + $rest;
    }

    function hoturl($param = [], $flags = 0) {
        $param["p"] = $this->paperId;
        return $this->conf->hoturl("paper", $param, $flags);
    }

    function reviewurl($param = [], $flags = 0) {
        $param["p"] = $this->paperId;
        return $this->conf->hoturl("review", $param, $flags);
    }


    /** @param int|Contact $contact
     * @return int */
    static private function contact_to_cid($contact) {
        assert($contact !== null);
        return is_object($contact) ? $contact->contactId : $contact;
    }

    private function check_rights_version() {
        if ($this->_rights_version !== Contact::$rights_version) {
            if ($this->_rights_version) {
                $this->_contact_info = $this->_reviews_have = [];
                $this->_review_array = $this->_conflict_array = null;
                ++$this->_review_array_version;
                unset($this->reviewSignatures, $this->allConflictType);
            }
            $this->_rights_version = Contact::$rights_version;
        }
    }

    /** @param int $cid
     * @return PaperContactInfo */
    function _get_contact_info($cid) {
        return $this->_contact_info[$cid];
    }

    /** @param Contact $user */
    function _clear_contact_info($user) {
        $this->_contact_info[$user->contactXid] = PaperContactInfo::make_empty($this, $user);
    }

    /** @return PaperContactInfo */
    function contact_info(Contact $user) {
        $this->check_rights_version();
        $cid = $user->contactXid;
        if (!array_key_exists($cid, $this->_contact_info)) {
            if ($this->_review_array
                || property_exists($this, "reviewSignatures")) {
                $ci = PaperContactInfo::make_empty($this, $user);
                if (($c = ($this->conflicts())[$cid] ?? null)) {
                    $ci->conflictType = $c->conflictType;
                }
                foreach ($this->reviews_of_user($cid, $user->review_tokens()) as $rrow) {
                    $ci->mark_review($rrow);
                }
                $this->_contact_info[$cid] = $ci;
            } else {
                PaperContactInfo::load_into($this, $user);
            }
        }
        return $this->_contact_info[$cid];
    }

    /** @param array<int,PaperContactInfo> $cimap */
    function replace_contact_info_map($cimap) {
        $old_cimap = $this->_contact_info;
        $this->_contact_info = $cimap;
        $this->_rights_version = Contact::$rights_version;
        return $old_cimap;
    }

    function invalidate_contact_info() {
        $this->replace_contact_info_map([]);
    }

    function load_my_contact_info($contact, $object) {
        $ci = PaperContactInfo::make_my($this, $contact, $object);
        $this->_contact_info[$ci->contactId] = $ci;
    }

    /** @return Contact */
    function author_view_user() {
        if (!$this->_author_view_user) {
            $this->_author_view_user = new Contact(null, $this->conf);
            $this->_author_view_user->set_capability("@av{$this->paperId}", true);
        }
        return $this->_author_view_user;
    }


    /** @return array<string,true> */
    function missing_fields($registration = false, Contact $user = null) {
        $f = [];
        if ($this->title === ""
            || (strlen($this->title) <= 6
                && preg_match('{\A(?:|N/?A|TB[AD])\z}i', $this->title))) {
            $f["title"] = true;
        }
        if ((string) $this->authorInformation === "") {
            $f["authors"] = true;
        }
        $ab = $this->abstract_text();
        if (($ab === ""
             || (strlen($ab) <= 6
                 && preg_match('/\A(?:|N\/?A|TB[AD])\s*\z/i', $ab)))
            && !$this->conf->opt("noAbstract")) {
            $f["abstract"] = true;
        }
        if (!$registration
            && !$this->conf->opt("noPapers")
            && $this->paperStorageId <= 1) {
            $f["submission"] = true;
        }
        foreach ($this->conf->paper_opts->option_list() as $o) {
            if ($o->test_required($this)
                && (!$user || $user->can_view_option($this, $o))
                && !$o->value_present($this->force_option($o))) {
                $f[$o->json_key()] = true;
            }
        }
        return $f;
    }


    /** @return string */
    function unaccented_title() {
        return $this->unaccented_field("title");
    }

    /** @return int */
    function pretty_text_title_indent($width = 75) {
        $n = "Paper #{$this->paperId}: ";
        $vistitle = $this->unaccented_title();
        $l = (int) (($width + 0.5 - strlen($vistitle) - strlen($n)) / 2);
        return strlen($n) + max(0, $l);
    }

    /** @return string */
    function pretty_text_title($width = 75) {
        $l = $this->pretty_text_title_indent($width);
        return prefix_word_wrap("Paper #{$this->paperId}: ", $this->title, $l);
    }

    /** @return int */
    function format_of($text, $check_simple = false) {
        return $this->conf->check_format($this->paperFormat, $check_simple ? $text : null);
    }

    /** @return int */
    function title_format() {
        return $this->format_of($this->title, true);
    }

    /** @return string */
    function abstract_text() {
        if ($this->dataOverflow && isset($this->dataOverflow["abstract"])) {
            return $this->dataOverflow["abstract"];
        } else {
            return $this->abstract ?? "";
        }
    }

    /** @return int */
    function abstract_format() {
        return $this->format_of($this->abstract_text(), true);
    }

    function edit_format() {
        return $this->conf->format_info($this->paperFormat);
    }

    /** @return list<Author> */
    function author_list() {
        if (!isset($this->_author_array)) {
            $this->_author_array = array();
            foreach (explode("\n", $this->authorInformation) as $line) {
                if ($line != "")
                    $this->_author_array[] = Author::make_tabbed($line);
            }
        }
        return $this->_author_array;
    }

    /** @return ?Author */
    function author_by_email($email) {
        foreach ($this->author_list() as $a) {
            if (strcasecmp($a->email, $email) == 0 && (string) $email !== "")
                return $a;
        }
        return null;
    }

    /** @return string */
    function parse_author_list() {
        $ai = "";
        foreach ($this->_author_array as $au) {
            $ai .= $au->firstName . "\t" . $au->lastName . "\t" . $au->email . "\t" . $au->affiliation . "\n";
        }
        return ($this->authorInformation = $ai);
    }

    /** @return string */
    function pretty_text_author_list() {
        $info = "";
        foreach ($this->author_list() as $au) {
            $info .= $au->name() ? : $au->email;
            if ($au->affiliation) {
                $info .= " (" . $au->affiliation . ")";
            }
            $info .= "\n";
        }
        return $info;
    }

    /** @param Contact|int $contact
     * @return int */
    function conflict_type($contact) {
        $cid = self::contact_to_cid($contact);
        if (array_key_exists($cid, $this->_contact_info)) {
            return $this->_contact_info[$cid]->conflictType;
        } else if (($ci = (($this->conflicts())[$cid] ?? null))) {
            return $ci->conflictType;
        } else {
            return 0;
        }
    }

    /** @param Contact|int $contact
     * @return bool */
    function has_conflict($contact) {
        return $this->conflict_type($contact) > CONFLICT_MAXUNCONFLICTED;
    }

    /** @param Contact|int $contact
     * @return bool */
    function has_author($contact) {
        return $this->conflict_type($contact) >= CONFLICT_AUTHOR;
    }

    /** @return string */
    function collaborators() {
        if ($this->dataOverflow && isset($this->dataOverflow["collaborators"])) {
            return $this->dataOverflow["collaborators"];
        } else {
            return $this->collaborators ?? "";
        }
    }

    /** @return list<AuthorMatcher> */
    function collaborator_list() {
        if ($this->_collaborator_array === null) {
            $this->_collaborator_array = [];
            foreach (explode("\n", $this->collaborators()) as $co) {
                if (($m = AuthorMatcher::make_collaborator_line($co)))
                    $this->_collaborator_array[] = $m;
            }
        }
        return $this->_collaborator_array;
    }

    /** @return bool */
    function has_nonempty_collaborators() {
        $collab = $this->collaborators();
        return $collab !== "" && strcasecmp($collab, "none") !== 0;
    }

    function potential_conflict_callback(Contact $user, $callback) {
        $nproblems = $auproblems = 0;
        if ($this->field_match_pregexes($user->aucollab_general_pregexes(), "authorInformation")) {
            foreach ($this->author_list() as $n => $au) {
                foreach ($user->aucollab_matchers() as $matcher) {
                    if (($why = $matcher->test($au, $matcher->nonauthor))) {
                        if (!$callback) {
                            return true;
                        }
                        $auproblems |= $why;
                        ++$nproblems;
                        call_user_func($callback, $user, $matcher, $au, $n + 1, $why);
                    }
                }
            }
        }
        if (($collab = $this->collaborators()) !== "") {
            $aum = $user->full_matcher();
            if (Text::match_pregexes($aum->general_pregexes(), $collab, UnicodeHelper::deaccent($collab))) {
                foreach ($this->collaborator_list() as $co) {
                    if (($co->lastName !== ""
                         || !($auproblems & AuthorMatcher::MATCH_AFFILIATION))
                        && ($why = $aum->test($co, true))) {
                        if (!$callback) {
                            return true;
                        }
                        ++$nproblems;
                        call_user_func($callback, $user, $aum, $co, 0, $why);
                    }
                }
            }
        }
        return $nproblems > 0;
    }

    function potential_conflict(Contact $user) {
        return $this->potential_conflict_callback($user, null);
    }

    function _potential_conflict_html_callback($user, $matcher, $conflict, $aunum, $why) {
        if ($aunum && $matcher->nonauthor) {
            $matchdesc = "collaborator";
        } else if ($why === AuthorMatcher::MATCH_AFFILIATION) {
            $matchdesc = "affiliation";
            if (!($this->_potential_conflict_flags & 1)) {
                $matchdesc .= " (" . htmlspecialchars($user->affiliation) . ")";
                $this->_potential_conflict_flags |= 1;
            }
        } else {
            $matchdesc = "name";
        }
        if ($aunum) {
            if ($matcher->nonauthor) {
                $aumatcher = new AuthorMatcher($conflict);
                $what = "$matchdesc " . $aumatcher->highlight($matcher) . "<br>matches author #$aunum " . $matcher->highlight($conflict);
            } else if ($why == AuthorMatcher::MATCH_AFFILIATION) {
                $what = "$matchdesc matches author #$aunum affiliation " . $matcher->highlight($conflict->affiliation);
            } else {
                $what = "$matchdesc matches author #$aunum name " . $matcher->highlight($conflict->name());
            }
            $this->_potential_conflicts[] = ["#$aunum", $what];
        } else {
            $what = "$matchdesc matches paper collaborator ";
            $this->_potential_conflicts[] = ["other conflicts", $what . $matcher->highlight($conflict)];
        }
    }

    /** @return false|array{string,list<string>} */
    function potential_conflict_html(Contact $user, $highlight = false) {
        $this->_potential_conflicts = [];
        $this->_potential_conflict_flags = 0;
        if (!$this->potential_conflict_callback($user, [$this, "_potential_conflict_html_callback"])) {
            return false;
        }
        usort($this->_potential_conflicts, function ($a, $b) { return strnatcmp($a[0], $b[0]); });
        $authors = array_unique(array_map(function ($x) { return $x[0]; }, $this->_potential_conflicts));
        $authors = array_filter($authors, function ($f) { return $f !== "other conflicts"; });
        $messages = array_map(function ($x) { return $x[1]; }, $this->_potential_conflicts);
        $this->_potential_conflicts = null;
        return ['<div class="pcconfmatch'
            . ($highlight ? " pcconfmatch-highlight" : "")
            . '">Possible conflict'
            . (empty($authors) ? "" : " with " . pluralx($authors, "author") . " " . numrangejoin($authors))
            . '…</div>', $messages];
    }

    static function potential_conflict_tooltip_html($potconf) {
        return $potconf ? '<ul class="x"><li>' . join('</li><li>', $potconf[1]) . '</li></ul>' : '';
    }


    /** @return int */
    function submitted_at() {
        if ($this->timeSubmitted > 0) {
            return (int) $this->timeSubmitted;
        } else if ($this->timeWithdrawn > 0) {
            if ($this->timeSubmitted == -100) {
                return self::SUBMITTED_AT_FOR_WITHDRAWN;
            } else if ($this->timeSubmitted < -100) {
                return -(int) $this->timeSubmitted;
            }
        }
        return 0;
    }

    /** @return list<Contact> */
    function administrators() {
        if ($this->managerContactId) {
            $u = $this->conf->cached_user_by_id($this->managerContactId);
            return $u ? [$u] : [];
        }

        $chairs = true;
        if ($this->conf->check_track_admin_sensitivity()) {
            foreach ($this->conf->track_tags() as $ttag)
                if ($this->conf->track_permission($ttag, Track::ADMIN)
                    && $this->has_tag($ttag)) {
                    $chairs = false;
                    break;
                }
        }
        $as = $cas = [];
        foreach ($chairs ? $this->conf->pc_chairs() : $this->conf->pc_members() as $u) {
            if ($u->is_primary_administrator($this)) {
                if ($u->can_administer($this)) {
                    $as[] = $u;
                } else {
                    $cas[] = $u;
                }
            }
        }
        return empty($as) ? $cas : $as;
    }


    /** @return string|false */
    function deaccented_field($field) {
        $data = $this->$field;
        if ((string) $data !== "") {
            $field_deaccent = $field . "_deaccent";
            if (!isset($this->$field_deaccent)) {
                if (is_usascii($data)) {
                    $this->$field_deaccent = false;
                } else {
                    $this->$field_deaccent = UnicodeHelper::deaccent($data);
                }
            }
            return $this->$field_deaccent;
        } else {
            return false;
        }
    }

    /** @return string */
    function unaccented_field($field) {
        $s = $this->deaccented_field($field);
        return $s === false ? $this->$field : $s;
    }

    /** @param TextPregexes $reg
     * @return bool */
    function field_match_pregexes($reg, $field) {
        return Text::match_pregexes($reg, $this->$field, $this->deaccented_field($field));
    }


    /** @return bool */
    function can_author_view_submitted_review() {
        if ($this->can_author_respond()) {
            return true;
        } else if ($this->conf->au_seerev == Conf::AUSEEREV_TAGS) {
            return $this->has_any_tag($this->conf->tag_au_seerev);
        } else {
            return $this->conf->au_seerev != 0;
        }
    }

    /** @return bool */
    function can_author_respond() {
        if ($this->conf->any_response_open === 2) {
            return true;
        } else if ($this->conf->any_response_open) {
            foreach ($this->conf->resp_rounds() as $rrd) {
                if ($rrd->time_allowed(true) && $rrd->search->filter([$this])) {
                    return true;
                }
            }
        }
        return false;
    }

    /** @return bool */
    function can_author_view_decision() {
        return $this->outcome != 0
            && $this->conf->can_all_author_view_decision();
    }

    /** @return bool */
    function can_author_edit_final_paper() {
        return $this->timeWithdrawn <= 0
            && $this->outcome > 0
            && $this->can_author_view_decision()
            && $this->conf->time_submit_final_version();
    }


    /** @return int */
    function review_type($contact) {
        $this->check_rights_version();
        if (is_object($contact) && $contact->has_capabilities()) {
            $ci = $this->contact_info($contact);
            return $ci ? $ci->reviewType : 0;
        }
        $cid = self::contact_to_cid($contact);
        if (array_key_exists($cid, $this->_contact_info)) {
            $rrow = $this->_contact_info[$cid];
        } else {
            $rrow = $this->review_of_user($cid);
        }
        return $rrow ? $rrow->reviewType : 0;
    }

    /** @return bool */
    function has_reviewer($contact) {
        return $this->review_type($contact) > 0;
    }

    /** @return bool */
    function review_not_incomplete($contact) {
        $ci = $this->contact_info($contact);
        return $ci && $ci->review_status > PaperContactInfo::RS_UNSUBMITTED;
    }

    /** @return bool */
    function review_submitted($contact) {
        $ci = $this->contact_info($contact);
        return $ci && $ci->reviewType > 0 && $ci->reviewSubmitted > 0;
    }

    /** @return array<int,Contact> */
    function pc_can_become_reviewer_ignore_conflict() {
        if (!$this->conf->check_track_review_sensitivity()) {
            return $this->conf->pc_members();
        } else {
            $pcm = array();
            foreach ($this->conf->pc_members() as $cid => $pc) {
                if ($pc->can_become_reviewer_ignore_conflict($this))
                    $pcm[$cid] = $pc;
            }
            return $pcm;
        }
    }


    function load_tags() {
        $result = $this->conf->qe("select group_concat(' ', tag, '#', tagIndex order by tag separator '') from PaperTag where paperId=? group by paperId", $this->paperId);
        $this->paperTags = "";
        if (($row = $result->fetch_row()) && $row[0] !== null) {
            $this->paperTags = $row[0];
        }
        Dbl::free($result);
    }

    /** @return bool */
    function has_tag($tag) {
        if (!property_exists($this, "paperTags")) {
            $this->load_tags();
        }
        return $this->paperTags !== null
            && $this->paperTags !== ""
            && stripos($this->paperTags, " $tag#") !== false;
    }

    /** @return bool */
    function has_any_tag($tags) {
        if (!property_exists($this, "paperTags")) {
            $this->load_tags();
        }
        if ($this->paperTags !== null && $this->paperTags !== "") {
            foreach ($tags as $tag) {
                if (stripos($this->paperTags, " $tag#") !== false)
                    return true;
            }
        }
        return false;
    }

    /** @return bool */
    function has_viewable_tag($tag, Contact $user) {
        $tags = $this->viewable_tags($user);
        return $tags !== "" && stripos(" " . $tags, " $tag#") !== false;
    }

    /** @param string $tag
     * @return false|float */
    function tag_value($tag) {
        if (!property_exists($this, "paperTags")) {
            $this->load_tags();
        }
        if ($this->paperTags !== null
            && $this->paperTags !== ""
            && ($pos = stripos($this->paperTags, " $tag#")) !== false) {
            return (float) substr($this->paperTags, $pos + strlen($tag) + 2);
        } else {
            return false;
        }
    }

    /** @return string */
    function all_tags_text() {
        if (!property_exists($this, "paperTags")) {
            $this->load_tags();
        }
        return $this->paperTags ?? "";
    }

    /** @return string */
    function searchable_tags(Contact $user) {
        if (!$user->isPC || $this->all_tags_text() === "") {
            return "";
        }
        $rights = $user->__rights($this);
        if ($rights->searchable_tags === null) {
            $dt = $this->conf->tags();
            $rights->searchable_tags = $dt->censor(TagMap::CENSOR_SEARCH, $this->all_tags_text(), $user, $this);
        }
        return $rights->searchable_tags;
    }

    /** @return string */
    function sorted_searchable_tags(Contact $user) {
        $tags = $this->searchable_tags($user);
        return $tags === "" ? "" : $this->conf->tags()->sort_string($tags);
    }

    /** @return string */
    function viewable_tags(Contact $user) {
        // see also Contact::can_view_tag()
        if (!$user->isPC || $this->all_tags_text() === "") {
            return "";
        }
        $rights = $user->__rights($this);
        if ($rights->viewable_tags === null) {
            $dt = $this->conf->tags();
            $tags = $dt->censor(TagMap::CENSOR_VIEW, $this->all_tags_text(), $user, $this);
            $rights->viewable_tags = $dt->sort_string($tags);
        }
        return $rights->viewable_tags;
    }

    /** @return string */
    function sorted_viewable_tags(Contact $user) {
        // XXX don't sort until required
        return $this->viewable_tags($user);
    }

    /** @return string */
    function sorted_editable_tags(Contact $user) {
        $tags = $this->all_tags_text();
        if ($tags !== "") {
            $old_overrides = $user->add_overrides(Contact::OVERRIDE_CONFLICT);
            $tags = $this->sorted_viewable_tags($user);
            if ($tags !== "") {
                $etags = [];
                foreach (explode(" ", $tags) as $tag) {
                    if ($tag !== "" && $user->can_change_tag($this, $tag, 0, 1))
                        $etags[] = $tag;
                }
                $tags = join(" ", $etags);
            }
            $user->set_overrides($old_overrides);
        }
        return $tags;
    }

    function add_tag_info_json($pj, Contact $user) {
        $tagger = new Tagger($user);
        $overrides = 0;
        if (($can_override = $user->has_overridable_conflict($this))) {
            $overrides = $user->add_overrides(Contact::OVERRIDE_CONFLICT);
        }
        $editable = $this->sorted_editable_tags($user);
        $viewable = $this->sorted_viewable_tags($user);
        $pj->tags = Tagger::split($viewable);
        $pj->tags_edit_text = $tagger->unparse($editable);
        $pj->tags_view_html = $tagger->unparse_link($viewable);
        if (($decor = $tagger->unparse_decoration_html($viewable))) {
            $pj->tag_decoration_html = $decor;
        }
        $tagmap = $this->conf->tags();
        $pj->color_classes = $tagmap->color_classes($viewable);
        if ($can_override && $viewable) {
            $user->remove_overrides(Contact::OVERRIDE_CONFLICT);
            $viewable_c = $this->sorted_viewable_tags($user);
            if ($viewable_c !== $viewable) {
                $pj->tags_conflicted = Tagger::split($viewable_c);
                if ($decor
                    && ($decor_c = $tagger->unparse_decoration_html($viewable_c)) !== $decor) {
                    $pj->tag_decoration_html_conflicted = $decor_c;
                }
                if ($pj->color_classes
                    && ($cc_c = $tagmap->color_classes($viewable_c)) !== $pj->color_classes) {
                    $pj->color_classes_conflicted = $cc_c;
                }
            }
        }
        if ($can_override) {
            $user->set_overrides($overrides);
        }
    }


    private function load_topics() {
        $row_set = $this->_row_set ? : new PaperInfoSet($this);
        foreach ($row_set as $prow) {
            $prow->topicIds = null;
        }
        if ($this->conf->has_topics()) {
            $result = $this->conf->qe("select paperId, group_concat(topicId) from PaperTopic where paperId?a group by paperId", $row_set->paper_ids());
            while ($result && ($row = $result->fetch_row())) {
                $prow = $row_set->get((int) $row[0]);
                $prow->topicIds = (string) $row[1];
            }
            Dbl::free($result);
        }
    }

    /** @return bool */
    function has_topics() {
        if (!property_exists($this, "topicIds")) {
            $this->load_topics();
        }
        return $this->topicIds !== null && $this->topicIds !== "";
    }

    /** @return list<int> */
    function topic_list() {
        if ($this->_topics_array === null) {
            if (!property_exists($this, "topicIds")) {
                $this->load_topics();
            }
            $this->_topics_array = [];
            if ($this->topicIds !== null && $this->topicIds !== "") {
                foreach (explode(",", $this->topicIds) as $t) {
                    $this->_topics_array[] = (int) $t;
                }
                $this->conf->topic_set()->sort($this->_topics_array);
            }
        }
        return $this->_topics_array;
    }

    /** @return array<int,string> */
    function topic_map() {
        $t = [];
        foreach ($this->topic_list() as $tid) {
            if (empty($t)) {
                $tset = $this->conf->topic_set();
            }
            $t[$tid] = $tset[$tid];
        }
        return $t;
    }

    /** @return string */
    function unparse_topics_text() {
        return join("; ", $this->topic_map());
    }

    private static $topic_interest_values = [-0.7071, -0.5, 0, 0.7071, 1];

    /** @param int|Contact $contact
     * @return int */
    function topic_interest_score($contact) {
        $score = 0;
        if (is_int($contact)) {
            $contact = ($this->conf->pc_members())[$contact] ?? null;
        }
        if ($contact) {
            if ($this->_topic_interest_score_array === null) {
                $this->_topic_interest_score_array = [];
            }
            if (isset($this->_topic_interest_score_array[$contact->contactId])) {
                $score = $this->_topic_interest_score_array[$contact->contactId];
            } else {
                $interests = $contact->topic_interest_map();
                $topics = $this->topic_list();
                foreach ($topics as $t) {
                    if (($j = $interests[$t] ?? 0)) {
                        if ($j >= -2 && $j <= 2) {
                            $score += self::$topic_interest_values[$j + 2];
                        } else if ($j > 2) {
                            $score += sqrt($j / 2);
                        } else {
                            $score += -sqrt(-$j / 4);
                        }
                    }
                }
                if ($score) {
                    // * Strong interest in the paper's single topic gets
                    //   score 10.
                    $score = (int) ($score / sqrt(count($topics)) * 10 + 0.5);
                }
                $this->_topic_interest_score_array[$contact->contactId] = $score;
            }
        }
        return $score;
    }

    function invalidate_topics() {
        unset($this->topicIds);
        $this->_topics_array = $this->_topic_interest_score_array = null;
    }


    /** @param bool $email */
    function load_conflicts($email) {
        if (!$email && property_exists($this, "allConflictType")) {
            $this->_conflict_array = [];
            $this->_conflict_array_email = $email;
            if ((string) $this->allConflictType !== "") {
                foreach (explode(",", $this->allConflictType) as $x) {
                    list($cid, $ctype) = explode(" ", $x);
                    $cflt = new PaperInfo_Conflict((int) $cid, (int) $ctype);
                    $this->_conflict_array[$cflt->contactId] = $cflt;
                }
            }
        } else {
            $row_set = $this->_row_set ? : new PaperInfoSet($this);
            foreach ($row_set as $prow) {
                $prow->_conflict_array = [];
                $prow->_conflict_array_email = $email;
            }
            if ($email) {
                $result = $this->conf->qe("select paperId, PaperConflict.contactId, conflictType, email from PaperConflict join ContactInfo using (contactId) where paperId?a", $row_set->paper_ids());
            } else {
                $result = $this->conf->qe("select paperId, contactId, conflictType, null from PaperConflict where paperId?a", $row_set->paper_ids());
            }
            while ($result && ($row = $result->fetch_row())) {
                $prow = $row_set->get((int) $row[0]);
                $cflt = new PaperInfo_Conflict((int) $row[1], (int) $row[2], $row[3]);
                $prow->_conflict_array[$cflt->contactId] = $cflt;
            }
            Dbl::free($result);
        }
    }

    /** @param bool $email
     * @return associative-array<int,PaperInfo_Conflict> */
    function conflicts($email = false) {
        if ($this->_conflict_array === null
            || ($email && !$this->_conflict_array_email)) {
            $this->load_conflicts($email);
        }
        return $this->_conflict_array;
    }

    /** @param bool $email
     * @return associative-array<int,PaperInfo_Conflict> */
    function pc_conflicts($email = false) {
        return array_intersect_key($this->conflicts($email), $this->conf->pc_members());
    }

    /** @return associative-array<int,int> */
    function conflict_types() {
        $ct = [];
        foreach ($this->conflicts() as $cflt) {
            $ct[$cflt->contactId] = $cflt->conflictType;
        }
        return $ct;
    }

    function invalidate_conflicts() {
        unset($this->allConflictType);
        $this->_conflict_array = null;
    }


    /** @return associative-array<int,PaperInfo_Conflict> */
    function contacts($email = false) {
        $c = array();
        foreach ($this->conflicts($email) as $id => $cflt) {
            if ($cflt->conflictType >= CONFLICT_AUTHOR)
                $c[$id] = $cflt;
        }
        return $c;
    }

    /** @return list<object> */
    function named_contacts() {
        $vals = Dbl::fetch_objects($this->conf->qe("select ContactInfo.contactId, conflictType, email, firstName, lastName, affiliation, roles, contactTags from PaperConflict join ContactInfo using (contactId) where paperId=$this->paperId and conflictType>=" . CONFLICT_AUTHOR));
        foreach ($vals as $v) {
            $v->contactId = (int) $v->contactId;
            $v->conflictType = (int) $v->conflictType;
        }
        return $vals;
    }


    function load_preferences() {
        if ($this->_row_set && ++$this->_row_set->loaded_allprefs >= 10) {
            $row_set = $this->_row_set->filter(function ($prow) {
                return !property_exists($prow, "allReviewerPreference");
            });
        } else {
            $row_set = new PaperInfoSet($this);
        }
        foreach ($row_set as $prow) {
            $prow->allReviewerPreference = null;
            $prow->_prefs_array = $prow->_prefs_cid = $prow->_desirability = null;
        }
        $result = $this->conf->qe("select paperId, " . $this->conf->query_all_reviewer_preference() . " from PaperReviewPreference where paperId?a group by paperId", $row_set->paper_ids());
        while ($result && ($row = $result->fetch_row())) {
            $prow = $row_set->get((int) $row[0]);
            $prow->allReviewerPreference = $row[1];
        }
        Dbl::free($result);
    }

    /** @return array<int,array{int,?int}> */
    function preferences() {
        if (!property_exists($this, "allReviewerPreference")) {
            $this->load_preferences();
        }
        if ($this->_prefs_array === null) {
            $x = array();
            if ($this->allReviewerPreference !== null && $this->allReviewerPreference !== "") {
                $p = preg_split('/[ ,]/', $this->allReviewerPreference);
                for ($i = 0; $i + 2 < count($p); $i += 3) {
                    if ($p[$i+1] !== "0" || $p[$i+2] !== ".")
                        $x[(int) $p[$i]] = [(int) $p[$i+1], $p[$i+2] === "." ? null : (int) $p[$i+2]];
                }
            }
            $this->_prefs_array = $x;
        }
        return $this->_prefs_array;
    }

    /** @param int|Contact $contact
     * @return array{int,?int,?int} */
    function preference($contact, $include_topic_score = false) {
        $cid = is_int($contact) ? $contact : $contact->contactId;
        if ($this->_prefs_cid === null
            && $this->_prefs_array === null
            && !property_exists($this, "allReviewerPreference")) {
            $row_set = $this->_row_set ? : new PaperInfoSet($this);
            foreach ($row_set as $prow) {
                $prow->_prefs_cid = [$cid, null];
            }
            $result = $this->conf->qe("select paperId, preference, expertise from PaperReviewPreference where paperId?a and contactId=?", $row_set->paper_ids(), $cid);
            while ($result && ($row = $result->fetch_row())) {
                $prow = $row_set->get((int) $row[0]);
                $prow->_prefs_cid[1] = [(int) $row[1], $row[2] === null ? null : (int) $row[2]];
            }
            Dbl::free($result);
        }
        if ($this->_prefs_cid !== null && $this->_prefs_cid[0] == $cid) {
            $pref = $this->_prefs_cid[1];
        } else {
            $pref = ($this->preferences())[$cid] ?? null;
        }
        $pref = $pref ? : [0, null];
        if ($include_topic_score) {
            $pref[] = $this->topic_interest_score($contact);
        }
        return $pref;
    }

    /** @return array<int,array{int,?int}> */
    function viewable_preferences(Contact $viewer, $aggregate = false) {
        if ($viewer->can_view_preference($this, $aggregate)) {
            return $this->preferences();
        } else if ($viewer->isPC) {
            $pref = $this->preference($viewer);
            return $pref[0] || $pref[1] ? [$viewer->contactId => $pref] : [];
        } else {
            return [];
        }
    }

    /** @return int */
    function desirability() {
        if ($this->_desirability === null) {
            $this->_desirability = 0;
            foreach ($this->preferences() as $pf) {
                if ($pf[0] > 0) {
                    $this->_desirability += 1;
                } else if ($pf[0] > -100 && $pf[0] < 0) {
                    $this->_desirability -= 1;
                }
            }
        }
        return $this->_desirability;
    }


    private function load_options($only_me, $need_data) {
        if ($this->_option_values === null
            && ($this->paperId === 0
                || (isset($this->optionIds) && $this->optionIds === ""))) {
            $this->_option_values = $this->_option_data = [];
        } else if ($this->_option_values === null
                   && isset($this->optionIds)
                   && !$need_data) {
            $this->_option_values = [];
            preg_match_all('/(\d+)#(-?\d+)/', $this->optionIds, $m);
            for ($i = 0; $i < count($m[1]); ++$i) {
                $this->_option_values[(int) $m[1][$i]][] = (int) $m[2][$i];
            }
        } else if ($this->_option_values === null
                   || ($need_data && $this->_option_data === null)) {
            $old_row_set = $this->_row_set;
            if ($only_me) {
                $this->_row_set = null;
            }
            $row_set = $this->_row_set ? : new PaperInfoSet($this);
            foreach ($row_set as $prow) {
                $prow->_option_values = $prow->_option_data = [];
            }
            $result = $this->conf->qe("select paperId, optionId, value, data, dataOverflow from PaperOption where paperId?a order by paperId", $row_set->paper_ids());
            while ($result && ($row = $result->fetch_row())) {
                $prow = $row_set->get((int) $row[0]);
                $prow->_option_values[(int) $row[1]][] = (int) $row[2];
                $prow->_option_data[(int) $row[1]][] = $row[3] !== null ? $row[3] : $row[4];
            }
            Dbl::free($result);
            if ($only_me) {
                $this->_row_set = $old_row_set;
            }
        }
    }

    private function _make_option_array() {
        $this->load_options(false, false);
        $paper_opts = $this->conf->paper_opts;
        $option_array = [];
        foreach ($this->_option_values as $oid => $ovalues) {
            if (($o = $paper_opts->option_by_id($oid))) {
                $option_array[$oid] = PaperValue::make_multi($this, $o, $ovalues, get($this->_option_data, $oid));
            }
        }
        foreach ($paper_opts->include_empty_option_list() as $oid => $o) {
            if (!isset($option_array[$oid])) {
                $option_array[$oid] = PaperValue::make_force($this, $o);
            }
        }
        return $option_array;
    }

    private function options() {
        if ($this->_option_array === null) {
            $this->_option_array = $this->_make_option_array();
        }
        return $this->_option_array;
    }

    /** @param int $id
     * @return array{list<int>,list<?string>} */
    function option_value_data($id) {
        if ($this->_option_data === null) {
            $this->load_options(false, true);
        }
        return [$this->_option_values[$id] ?? [],
                $this->_option_data[$id] ?? []];
    }

    /** @param int|PaperOption $o
     * @return ?PaperValue */
    function option($o) {
        $id = is_object($o) ? $o->id : $o;
        return ($this->options())[$id] ?? null;
    }

    /** @param int|PaperOption $o
     * @return PaperValue */
    function force_option($o) {
        if (is_object($o)) {
            return ($this->options())[$o->id] ?? PaperValue::make_force($this, $o);
        } else {
            $ov = ($this->options())[$o] ?? null;
            if (!$ov && ($oforce = $this->conf->option_by_id($o))) {
                $ov = PaperValue::make_force($this, $oforce);
            }
            return $ov;
        }
    }

    /** @param int|PaperOption $o
     * @return PaperValue */
    function new_option($o) {
        if (is_object($o)) {
            $ov = $this->_new_option_array[$o->id] ?? null;
        } else {
            $ov = $this->_new_option_array[$o] ?? null;
        }
        if (!$ov) {
            $ov = $this->force_option($o);
            $this->_new_option_array[$ov->id] = $ov;
        }
        return $ov;
    }

    function set_new_option(PaperValue $ov) {
        $this->_new_option_array[$ov->id] = $ov;
    }

    function invalidate_options($reload = false) {
        unset($this->optionIds);
        $this->_option_array = $this->_option_values = $this->_option_data = null;
        if ($reload) {
            $this->load_options(true, true);
        }
    }

    private function _document_sql() {
        return "paperId, paperStorageId, timestamp, mimetype, sha1, documentType, filename, infoJson, size, filterType, originalStorageId, inactive";
    }

    /** @param int $dtype
     * @param int $did
     * @return ?DocumentInfo */
    function document($dtype, $did = 0, $full = false) {
        if ($did <= 0) {
            if ($dtype == DTYPE_SUBMISSION) {
                $did = $this->paperStorageId;
            } else if ($dtype == DTYPE_FINAL) {
                $did = $this->finalPaperStorageId;
            } else if (($oa = $this->force_option($dtype))
                       && $oa->option->is_document()) {
                return $oa->document(0);
            }
        }

        if ($did <= 1) {
            return null;
        }

        if ($this->_document_array !== null
            && array_key_exists($did, $this->_document_array)) {
            return $this->_document_array[$did];
        }

        if ((($dtype == DTYPE_SUBMISSION
              && $did == $this->paperStorageId
              && $this->finalPaperStorageId <= 0)
             || ($dtype == DTYPE_FINAL
                 && $did == $this->finalPaperStorageId))
            && !$full) {
            $infoJson = get($this, $dtype == DTYPE_SUBMISSION ? "paper_infoJson" : "final_infoJson", false);
            return new DocumentInfo(["paperStorageId" => $did, "paperId" => $this->paperId, "documentType" => $dtype, "timestamp" => get($this, "timestamp"), "mimetype" => $this->mimetype, "sha1" => $this->sha1, "size" => get($this, "size"), "infoJson" => $infoJson, "is_partial" => true], $this->conf, $this);
        }

        if ($this->_document_array === null) {
            $result = $this->conf->qe("select " . $this->_document_sql() . " from PaperStorage where paperId=? and inactive=0", $this->paperId);
            $this->_document_array = [];
            while (($di = DocumentInfo::fetch($result, $this->conf, $this))) {
                $this->_document_array[$di->paperStorageId] = $di;
            }
            Dbl::free($result);
        }
        if (!array_key_exists($did, $this->_document_array)) {
            $result = $this->conf->qe("select " . $this->_document_sql() . " from PaperStorage where paperStorageId=?", $did);
            $this->_document_array[$did] = DocumentInfo::fetch($result, $this->conf, $this);
            Dbl::free($result);
        }
        return $this->_document_array[$did];
    }

    /** @return ?DocumentInfo */
    function primary_document() {
        return $this->document($this->finalPaperStorageId > 0 ? DTYPE_FINAL : DTYPE_SUBMISSION);
    }

    /** @return bool */
    function is_primary_document(DocumentInfo $doc) {
        return $doc->paperStorageId > 1
            && (($doc->paperStorageId == $this->paperStorageId
                 && $this->finalPaperStorageId <= 0
                 && $doc->documentType == DTYPE_SUBMISSION)
                || ($doc->paperStorageId == $this->finalPaperStorageId
                    && $doc->documentType == DTYPE_FINAL));
    }

    /** @param int $dtype
     * @return list<DocumentInfo> */
    function documents($dtype) {
        if ($dtype <= 0) {
            $doc = $this->document($dtype, 0, true);
            return $doc ? [$doc] : [];
        } else if (($ov = $this->option($dtype))
                   && $ov->option->has_document()) {
            return $ov->documents();
        } else {
            return [];
        }
    }

    function mark_inactive_documents() {
        // see also DocumentInfo::active_document_map
        $dids = [];
        if ($this->paperStorageId > 1) {
            $dids[] = $this->paperStorageId;
        }
        if ($this->finalPaperStorageId > 1) {
            $dids[] = $this->finalPaperStorageId;
        }
        foreach ($this->options() as $oa) {
            if ($oa->option->has_document()) {
                $dids = array_merge($dids, $oa->value_array());
            }
        }
        $this->conf->qe("update PaperStorage set inactive=1 where paperId=? and documentType>=? and paperStorageId?A", $this->paperId, DTYPE_FINAL, $dids);
    }

    function mark_inactive_linked_documents() {
        // see also DocumentInfo::active_document_map
        $this->conf->qe("update PaperStorage set inactive=1 where paperId=? and documentType<=? and paperStorageId not in (select documentId from DocumentLink where paperId=?)", $this->paperId, DTYPE_COMMENT, $this->paperId);
    }

    /** @param int $dtype
     * @return ?DocumentInfo */
    function attachment($dtype, $name) {
        $ov = $this->option($dtype);
        return $ov ? $ov->attachment($name) : null;
    }

    /** @return int */
    function npages() {
        $doc = $this->document($this->finalPaperStorageId <= 0 ? DTYPE_SUBMISSION : DTYPE_FINAL);
        return $doc ? $doc->npages() : 0;
    }

    /** @return array<int,array<int,int>> */
    private function doclink_array() {
        if ($this->_doclink_array === null) {
            $row_set = $this->_row_set ? : new PaperInfoSet($this);
            foreach ($row_set as $prow) {
                $prow->_doclink_array = [];
            }
            $result = $this->conf->qe("select paperId, linkId, linkType, documentId from DocumentLink where paperId?a order by paperId, linkId, linkType", $row_set->paper_ids());
            while ($result && ($row = $result->fetch_row())) {
                $prow = $row_set->get((int) $row[0]);
                $linkid = (int) $row[1];
                if (!isset($prow->_doclink_array[$linkid])) {
                    $prow->_doclink_array[$linkid] = [];
                }
                $prow->_doclink_array[$linkid][(int) $row[2]] = (int) $row[3];
            }
            Dbl::free($result);
        }
        return $this->_doclink_array;
    }

    /** @return list<DocumentInfo> */
    function linked_documents($linkid, $min, $max, $owner = null) {
        $docs = [];
        foreach (($this->doclink_array())[$linkid] ?? [] as $lt => $docid) {
            if ($lt >= $min
                && $lt < $max
                && ($d = $this->document(-2, $docid))) {
                $docs[] = $owner ? $d->with_owner($owner) : $d;
            }
        }
        if (!empty($docs)) {
            DocumentInfo::assign_unique_filenames($docs);
        }
        return $docs;
    }

    function invalidate_linked_documents() {
        $this->_doclink_array = null;
    }


    function load_reviews($always = false) {
        ++$this->_review_array_version;

        if (property_exists($this, "reviewSignatures")
            && $this->_review_array === null
            && !$always) {
            $this->_review_array = $this->_reviews_have = [];
            if ($this->reviewSignatures !== null
                && $this->reviewSignatures !== "") {
                foreach (explode(",", $this->reviewSignatures) as $rs) {
                    $rrow = ReviewInfo::make_signature($this, $rs);
                    $this->_review_array[$rrow->reviewId] = $rrow;
                }
            }
            return;
        }

        if ($this->_row_set && ($this->_review_array === null || $always)) {
            $row_set = $this->_row_set;
        } else {
            $row_set = new PaperInfoSet($this);
        }
        $had = [];
        foreach ($row_set as $prow) {
            $prow->_review_array = [];
            $had += $prow->_reviews_have;
            $prow->_reviews_have = ["full" => true];
        }

        $result = $this->conf->qe("select PaperReview.*, " . $this->conf->query_ratings() . " allRatings from PaperReview where paperId?a order by paperId, reviewId", $row_set->paper_ids());
        while (($rrow = ReviewInfo::fetch($result, $this->conf))) {
            $prow = $row_set->get($rrow->paperId);
            $prow->_review_array[$rrow->reviewId] = $rrow;
        }
        Dbl::free($result);

        $this->ensure_reviewer_names_set($row_set);
        if (isset($had["lastLogin"])) {
            $this->ensure_reviewer_last_login_set($row_set);
        }
    }

    function invalidate_reviews() {
        $this->_review_array = null;
        $this->_reviews_have = [];
    }

    /** @return int|false */
    private function parse_textual_id($textid) {
        if (ctype_digit($textid)) {
            return intval($textid);
        }
        if (str_starts_with($textid, (string) $this->paperId)) {
            $textid = (string) substr($textid, strlen((string) $this->paperId));
        }
        if ($textid !== ""
            && ctype_upper($textid)
            && ($n = parseReviewOrdinal($textid)) > 0) {
            return -$n;
        } else {
            return false;
        }
    }

    /** @return array<int,ReviewInfo> */
    function reviews_by_id() {
        if ($this->_review_array === null) {
            $this->load_reviews();
        }
        return $this->_review_array;
    }

    /** @return list<ReviewInfo> */
    function reviews_by_id_order() {
        return array_values($this->reviews_by_id());
    }

    /** @return list<ReviewInfo> */
    function reviews_by_display(Contact $user) {
        $srs = $urs = $ers = [];

        foreach ($this->reviews_by_id() as $rrow) {
            if ($rrow->reviewSubmitted || $rrow->reviewOrdinal) {
                $srs[] = $rrow;
            } else if ($rrow->is_subreview()) {
                $ers[] = $rrow;
            } else {
                $urs[] = $rrow;
            }
        }

        usort($srs, function ($a, $b) {
            // NB: all submitted reviews have timeDisplayed
            if ($a->timeDisplayed != $b->timeDisplayed) {
                return $a->timeDisplayed < $b->timeDisplayed ? -1 : 1;
            } else if ($a->reviewOrdinal && $b->reviewOrdinal) {
                return $a->reviewOrdinal < $b->reviewOrdinal ? -1 : 1;
            } else {
                return $a->reviewId < $b->reviewId ? -1 : 1;
            }
        });

        foreach ($urs as $urow) {
            $srs[] = $urow;
        }

        foreach ($ers as $urow) {
            $p0 = count($srs);
            foreach ($srs as $i => $srow) {
                if ($urow->requestedBy == $srow->contactId
                    || ($srow->reviewType < REVIEW_PC
                        && $urow->requestedBy == $srow->requestedBy
                        && ($urow->timeApprovalRequested >= 0
                            || ($srow->timeApprovalRequested < 0
                                && $urow->timeApprovalRequested < $srow->timeApprovalRequested)))) {
                    $p0 = $i + 1;
                }
            }
            array_splice($srs, $p0, 0, [$urow]);
        }

        return $srs;
    }

    /** @param int $id
     * @return ?ReviewInfo */
    function review_of_id($id) {
        return ($this->reviews_by_id())[$id] ?? null;
    }

    /** @param int|Contact $contact
     * @return ?ReviewInfo */
    function review_of_user($contact) {
        $cid = self::contact_to_cid($contact);
        foreach ($this->reviews_by_id() as $rrow) {
            if ($rrow->contactId == $cid) {
                return $rrow;
            }
        }
        return null;
    }

    /** @param int|Contact $contact
     * @return list<ReviewInfo> */
    function reviews_of_user($contact, $rev_tokens = null) {
        $cid = self::contact_to_cid($contact);
        $rrows = [];
        foreach ($this->reviews_by_id() as $rrow) {
            if ($rrow->contactId == $cid
                || ($rev_tokens
                    && $rrow->reviewToken
                    && in_array($rrow->reviewToken, $rev_tokens))) {
                $rrows[] = $rrow;
            }
        }
        return $rrows;
    }

    /** @param int $ordinal
     * @return ?ReviewInfo */
    function review_of_ordinal($ordinal) {
        foreach ($this->reviews_by_id() as $rrow) {
            if ($rrow->reviewOrdinal == $ordinal) {
                return $rrow;
            }
        }
        return null;
    }

    /** @param int|string $token
     * @return ?ReviewInfo */
    function review_of_token($token) {
        if (!is_int($token)) {
            $token = decode_token($token, "V");
        }
        foreach ($this->reviews_by_id() as $rrow) {
            if ($rrow->reviewToken == $token) {
                return $rrow;
            }
        }
        return null;
    }

    /** @param string $textid
     * @return false|?ReviewInfo */
    function review_of_textual_id($textid) {
        if (($n = $this->parse_textual_id($textid)) === false) {
            return false;
        } else if ($n < 0) {
            return $this->review_of_ordinal(-$n);
        } else {
            return $this->review_of_id($n);
        }
    }

    private function ensure_full_review_name() {
        foreach ($this->_full_review ?? [] as $rrow) {
            if (($u = $this->conf->cached_user_by_id($rrow->contactId))) {
                $rrow->assign_name($u);
            }
        }
    }

    /** @return ?ReviewInfo */
    function full_review_of_id($id) {
        if ($this->_full_review_key === null
            && !isset($this->_reviews_have["full"])) {
            $this->_full_review_key = "r$id";
            $result = $this->conf->qe("select PaperReview.*, " . $this->conf->query_ratings() . " allRatings from PaperReview where paperId=? and reviewId=?", $this->paperId, $id);
            $rrow = ReviewInfo::fetch($result, $this->conf);
            $this->_full_review = $rrow ? [$rrow] : [];
            Dbl::free($result);
            $this->ensure_full_review_name();
        }
        if ($this->_full_review_key === "r$id") {
            return $this->_full_review[0] ?? null;
        }
        $this->ensure_full_reviews();
        return $this->review_of_id($id);
    }

    /** @param int|Contact $contact
     * @return list<ReviewInfo> */
    function full_reviews_of_user($contact) {
        $cid = self::contact_to_cid($contact);
        if ($this->_full_review_key === null
            && !isset($this->_reviews_have["full"])) {
            $row_set = $this->_row_set ? : new PaperInfoSet($this);
            foreach ($row_set as $prow) {
                $prow->_full_review = [];
                $prow->_full_review_key = "u$cid";
            }
            $result = $this->conf->qe("select PaperReview.*, " . $this->conf->query_ratings() . " allRatings from PaperReview where paperId?a and contactId=? order by paperId, reviewId", $row_set->paper_ids(), $cid);
            while (($rrow = ReviewInfo::fetch($result, $this->conf))) {
                $prow = $row_set->get($rrow->paperId);
                $prow->_full_review[] = $rrow;
            }
            Dbl::free($result);
            $this->ensure_full_review_name();
        }
        if ($this->_full_review_key === "u$cid") {
            return $this->_full_review;
        }
        $this->ensure_full_reviews();
        return $this->reviews_of_user($contact);
    }

    /** @return ?ReviewInfo */
    function full_review_of_ordinal($ordinal) {
        if ($this->_full_review_key === null
            && !isset($this->_reviews_have["full"])) {
            $this->_full_review_key = "o$ordinal";
            $result = $this->conf->qe("select PaperReview.*, " . $this->conf->query_ratings() . " allRatings from PaperReview where paperId=? and reviewOrdinal=?", $this->paperId, $ordinal);
            $rrow = ReviewInfo::fetch($result, $this->conf);
            $this->_full_review = $rrow ? [$rrow] : [];
            Dbl::free($result);
            $this->ensure_full_review_name();
        }
        if ($this->_full_review_key === "o$ordinal") {
            return $this->_full_review[0] ?? null;
        }
        $this->ensure_full_reviews();
        return $this->review_of_ordinal($ordinal);
    }

    /** @return false|?ReviewInfo */
    function full_review_of_textual_id($textid) {
        if (($n = $this->parse_textual_id($textid)) === false) {
            return false;
        } else if ($n < 0) {
            return $this->full_review_of_ordinal(-$n);
        } else {
            return $this->full_review_of_id($n);
        }
    }

    private function fresh_review_of($key, $value) {
        $result = $this->conf->qe("select PaperReview.*, " . $this->conf->query_ratings() . " allRatings, ContactInfo.firstName, ContactInfo.lastName, ContactInfo.email, ContactInfo.roles, ContactInfo.contactTags from PaperReview join ContactInfo using (contactId) where paperId=? and $key=? order by paperId, reviewId", $this->paperId, $value);
        $rrow = ReviewInfo::fetch($result, $this->conf);
        Dbl::free($result);
        return $rrow;
    }

    /** @return ?ReviewInfo */
    function fresh_review_of_id($id) {
        return $this->fresh_review_of("reviewId", $id);
    }

    /** @return ?ReviewInfo */
    function fresh_review_of_user($contact) {
        return $this->fresh_review_of("contactId", self::contact_to_cid($contact));
    }

    /** @return list<ReviewInfo> */
    function viewable_submitted_reviews_by_display(Contact $user) {
        $cinfo = $user->__rights($this);
        if ($cinfo->vsreviews_array === null
            || $cinfo->vsreviews_version !== $this->_review_array_version) {
            $cinfo->vsreviews_array = [];
            foreach ($this->reviews_by_display($user) as $rrow) {
                if ($rrow->reviewSubmitted > 0
                    && $user->can_view_review($this, $rrow)) {
                    $cinfo->vsreviews_array[] = $rrow;
                }
            }
            $cinfo->vsreviews_version = $this->_review_array_version;
        }
        return $cinfo->vsreviews_array;
    }

    /** @return array<int,ReviewInfo> */
    function viewable_submitted_reviews_by_user(Contact $user) {
        $rrows = [];
        foreach ($this->viewable_submitted_reviews_by_display($user) as $rrow) {
            $rrows[$rrow->contactId] = $rrow;
        }
        return $rrows;
    }

    /** @return bool */
    function can_view_review_identity_of($cid, Contact $user) {
        if ($user->can_administer_for_track($this, Track::VIEWREVID)
            || $cid == $user->contactId) {
            return true;
        }
        foreach ($this->reviews_of_user($cid) as $rrow) {
            if ($user->can_view_review_identity($this, $rrow)) {
                return true;
            }
        }
        return false;
    }

    /** @param ReviewField $field
     * @return bool */
    function may_have_viewable_scores($field, Contact $user) {
        return $user->can_view_review($this, null, $field->view_score)
            || $this->review_type($user);
    }

    function ensure_reviews() {
        if ($this->_review_array === null) {
            $this->load_reviews();
        }
    }

    function ensure_full_reviews() {
        if (!isset($this->_reviews_have["full"])) {
            $this->load_reviews(true);
        }
    }

    private function ensure_reviewer_names_set($row_set) {
        foreach ($row_set as $prow) {
            foreach ($prow->reviews_by_id() as $rrow) {
                $this->conf->request_cached_user_by_id($rrow->contactId);
            }
        }
        foreach ($row_set as $prow) {
            $prow->_reviews_have["names"] = true;
            foreach ($prow->reviews_by_id() as $rrow) {
                if (($u = $this->conf->cached_user_by_id($rrow->contactId))) {
                    $rrow->assign_name($u);
                }
            }
        }
    }

    function ensure_reviewer_names() {
        $this->ensure_reviews();
        if (!empty($this->_review_array)
            && !isset($this->_reviews_have["names"])) {
            $this->ensure_reviewer_names_set($this->_row_set ? : new PaperInfoSet($this));
        }
    }

    private function ensure_reviewer_last_login_set($row_set) {
        $users = [];
        foreach ($row_set as $prow) {
            $prow->_reviews_have["lastLogin"] = true;
            foreach ($prow->reviews_by_id() as $rrow)
                $users[$rrow->contactId] = true;
        }
        if (!empty($users)) {
            $result = $this->conf->qe("select contactId, lastLogin from ContactInfo where contactId?a", array_keys($users));
            $users = Dbl::fetch_iimap($result);
            foreach ($row_set as $prow) {
                foreach ($prow->reviews_by_id() as $rrow)
                    $rrow->reviewLastLogin = $users[$rrow->contactId];
            }
        }
    }

    function ensure_reviewer_last_login() {
        $this->ensure_reviews();
        if (!empty($this->_review_array)
            && !isset($this->_reviews_have["lastLogin"])) {
            $this->ensure_reviewer_last_login_set($this->_row_set ? : new PaperInfoSet($this));
        }
    }

    private function load_review_fields($fid, $maybe_null = false) {
        $k = $fid . "Signature";
        $row_set = $this->_row_set ? : new PaperInfoSet($this);
        foreach ($row_set as $prow) {
            $prow->$k = "";
        }
        $select = $maybe_null ? "coalesce($fid,'.')" : $fid;
        $result = $this->conf->qe("select paperId, group_concat($select order by reviewId) from PaperReview where paperId?a group by paperId", $row_set->paper_ids());
        while ($result && ($row = $result->fetch_row())) {
            $prow = $row_set->get((int) $row[0]);
            $prow->$k = $row[1];
        }
        Dbl::free($result);
    }

    /** @param string|ReviewField $field */
    function ensure_review_score($field) {
        $fid = is_object($field) ? $field->id : $field;
        if (!isset($this->_reviews_have[$fid])
            && !isset($this->_reviews_have["full"])) {
            $rfi = is_object($field) ? $field : ReviewInfo::field_info($fid, $this->conf);
            if (!$rfi) {
                $this->_reviews_have[$fid] = false;
            } else if (!$rfi->main_storage) {
                $this->ensure_full_reviews();
            } else {
                $this->_reviews_have[$fid] = true;
                $k = $rfi->main_storage . "Signature";
                if (!property_exists($this, $k))
                    $this->load_review_fields($rfi->main_storage);
                $x = explode(",", $this->$k);
                foreach ($this->reviews_by_id_order() as $i => $rrow)
                    $rrow->$fid = (int) $x[$i];
            }
        }
    }

    /** @param string $fid */
    function _mark_has_score($fid) {
        $this->_reviews_have[$fid] = true;
    }

    private function _update_review_word_counts($rids) {
        $rf = $this->conf->review_form();
        $result = $this->conf->qe("select * from PaperReview where paperId=$this->paperId and reviewId?a", $rids);
        $qs = [];
        while (($rrow = ReviewInfo::fetch($result, $this->conf))) {
            if ($rrow->reviewWordCount === null) {
                $rrow->reviewWordCount = $rf->word_count($rrow);
                $qs[] = "update PaperReview set reviewWordCount={$rrow->reviewWordCount} where paperId={$this->paperId} and reviewId={$rrow->reviewId}";
            }
            $my_rrow = get($this->_review_array, $rrow->reviewId);
            $my_rrow->reviewWordCount = (int) $rrow->reviewWordCount;
        }
        Dbl::free($result);
        if (!empty($qs)) {
            $mresult = Dbl::multi_qe($this->conf->dblink, join(";", $qs));
            $mresult->free_all();
        }
    }

    function ensure_review_word_counts() {
        if (!isset($this->_reviews_have["reviewWordCount"])) {
            $this->_reviews_have["reviewWordCount"] = true;
            if (!property_exists($this, "reviewWordCountSignature")) {
                $this->load_review_fields("reviewWordCount", true);
            }
            $x = explode(",", $this->reviewWordCountSignature ?? "");
            $bad_ids = [];

            foreach ($this->reviews_by_id_order() as $i => $rrow) {
                if ($x[$i] !== ".") {
                    $rrow->reviewWordCount = (int) $x[$i];
                } else {
                    $bad_ids[] = $rrow->reviewId;
                }
            }
            if (!empty($bad_ids)) {
                $this->_update_review_word_counts($bad_ids);
            }
        }
    }

    /** @return bool */
    function has_author_seen_any_review() {
        foreach ($this->reviews_by_id() as $rrow) {
            if ($rrow->reviewAuthorSeen) {
                return true;
            }
        }
        return false;
    }


    function load_review_requests($always = false) {
        if ($this->_row_set && ($this->_request_array === null || $always)) {
            $row_set = $this->_row_set;
        } else {
            $row_set = new PaperInfoSet($this);
        }
        foreach ($row_set as $prow) {
            $prow->_request_array = [];
        }

        $result = $this->conf->qe("select * from ReviewRequest where paperId?a", $row_set->paper_ids());
        while (($ref = ReviewRequestInfo::fetch($result))) {
            $prow = $row_set->get($ref->paperId);
            $prow->_request_array[] = $ref;
        }
        Dbl::free($result);
    }

    /** @return list<ReviewRequestInfo> */
    function review_requests() {
        if ($this->_request_array === null) {
            $this->load_review_requests();
        }
        return $this->_request_array;
    }


    function load_review_refusals($always = false) {
        if ($this->_row_set && ($this->_refusal_array === null || $always)) {
            $row_set = $this->_row_set;
        } else {
            $row_set = new PaperInfoSet($this);
        }
        foreach ($row_set as $prow) {
            $prow->_refusal_array = [];
        }

        $result = $this->conf->qe("select * from PaperReviewRefused where paperId?a", $row_set->paper_ids());
        while (($ref = ReviewRefusalInfo::fetch($result))) {
            $prow = $row_set->get($ref->paperId);
            $prow->_refusal_array[] = $ref;
        }
        Dbl::free($result);
    }

    /** @return list<ReviewRefusalInfo> */
    function review_refusals() {
        if ($this->_refusal_array === null) {
            $this->load_review_refusals();
        }
        return $this->_refusal_array;
    }

    /** @return list<ReviewRefusalInfo> */
    function review_refusals_of_user(Contact $user) {
        $a = [];
        foreach ($this->review_refusals() as $ref) {
            if ($ref->contactId == $user->contactId
                || strcasecmp($ref->email, $user->email) === 0) {
                $a[] = $ref;
            }
        }
        return $a;
    }

    /** @return list<ReviewRefusalInfo> */
    function review_refusals_of_email($email) {
        $a = [];
        foreach ($this->review_refusals() as $ref) {
            if (strcasecmp($ref->email, $email) === 0) {
                $a[] = $ref;
            }
        }
        return $a;
    }


    static function fetch_comment_query() {
        return "select PaperComment.*,
            firstName reviewFirstName, lastName reviewLastName, email reviewEmail
            from PaperComment
            join ContactInfo on (ContactInfo.contactId=PaperComment.contactId)";
    }

    /** @return array<int,CommentInfo> */
    function fetch_comments($extra_where = null) {
        $result = $this->conf->qe(self::fetch_comment_query()
            . " where paperId={$this->paperId}" . ($extra_where ? " and $extra_where" : "")
            . " order by paperId, commentId");
        $comments = [];
        while (($c = CommentInfo::fetch($result, $this, $this->conf))) {
            $comments[$c->commentId] = $c;
        }
        Dbl::free($result);
        return $comments;
    }

    function load_comments() {
        $row_set = $this->_row_set ? : new PaperInfoSet($this);
        foreach ($row_set as $prow) {
            $prow->_comment_array = [];
        }
        $result = $this->conf->qe(self::fetch_comment_query()
            . " where paperId?a order by paperId, commentId", $row_set->paper_ids());
        $comments = [];
        while (($c = CommentInfo::fetch($result, null, $this->conf))) {
            $prow = $row_set->checked_paper_by_id($c->paperId);
            $c->set_prow($prow);
            $prow->_comment_array[$c->commentId] = $c;
        }
        Dbl::free($result);
    }

    /** @return array<int,CommentInfo> */
    function all_comments() {
        if ($this->_comment_array === null) {
            $this->load_comments();
        }
        return $this->_comment_array;
    }

    /** @return array<int,CommentInfo> */
    function viewable_comments(Contact $user, $textless = false) {
        $crows = [];
        foreach ($this->all_comments() as $cid => $crow) {
            if ($user->can_view_comment($this, $crow, $textless)) {
                $crows[$cid] = $crow;
            }
        }
        return $crows;
    }

    /** @return array<int,CommentInfo> */
    function all_comment_skeletons() {
        if ($this->_comment_skeleton_array === null) {
            if ($this->_comment_array !== null
                || !property_exists($this, "commentSkeletonInfo")) {
                return $this->all_comments();
            }
            $this->_comment_skeleton_array = [];
            preg_match_all('/(\d+);(\d+);(\d+);(\d+);([^|]*)/',
                           $this->commentSkeletonInfo ?? "", $ms, PREG_SET_ORDER);
            foreach ($ms as $m) {
                $c = new CommentInfo([
                        "commentId" => $m[1], "contactId" => $m[2],
                        "commentType" => $m[3], "commentRound" => $m[4],
                        "commentTags" => $m[5]
                    ], $this, $this->conf);
                $this->_comment_skeleton_array[$c->commentId] = $c;
            }
        }
        return $this->_comment_skeleton_array;
    }

    /** @return array<int,CommentInfo> */
    function viewable_comment_skeletons(Contact $user, $textless = false) {
        $crows = [];
        foreach ($this->all_comment_skeletons() as $cid => $crow) {
            if ($user->can_view_comment($this, $crow, $textless)) {
                $crows[$cid] = $crow;
            }
        }
        return $crows;
    }

    /** @param int|Contact $contact
     * @return bool */
    function has_commenter($contact) {
        $cid = self::contact_to_cid($contact);
        foreach ($this->all_comment_skeletons() as $crow) {
            if ($crow->contactId == $cid) {
                return true;
            }
        }
        return false;
    }


    /** @param list<ReviewInfo> $rrows
     * @param list<CommentInfo> $crows
     * @return list<ReviewInfo|CommentInfo> */
    function merge_reviews_and_comments($rrows, $crows) {
        if (empty($crows)) {
            return $rrows;
        }

        usort($crows, function ($a, $b) {
            if ($a->timeDisplayed != $b->timeDisplayed) {
                if ($a->timeDisplayed == 0 || $b->timeDisplayed == 0) {
                    return $a->timeDisplayed == 0 ? 1 : -1;
                } else {
                    return $a->timeDisplayed < $b->timeDisplayed ? -1 : 1;
                }
            } else {
                return $a->commentId < $b->commentId ? -1 : 1;
            }
        });

        $xrows = [];
        $i = $j = 0;
        while ($i < count($rrows) && $j < count($crows)) {
            $rr = $rrows[$i];
            $cr = $crows[$j];
            if ($rr->timeDisplayed == 0 || $cr->timeDisplayed == 0) {
                break;
            } else if ($rr->timeDisplayed <= $cr->timeDisplayed) {
                $xrows[] = $rr;
                ++$i;
                while ($i < count($rrows) && $rrows[$i]->timeDisplayed == 0) {
                    $xrows[] = $rrows[$i];
                    ++$i;
                }
            } else {
                $xrows[] = $cr;
                ++$j;
            }
        }
        while ($i < count($rrows)) {
            $xrows[] = $rrows[$i];
            ++$i;
        }
        while ($j < count($crows)) {
            $xrows[] = $crows[$j];
            ++$j;
        }
        return $xrows;
    }

    /** @return list<ReviewInfo|CommentInfo> */
    function viewable_submitted_reviews_and_comments(Contact $user) {
        $this->ensure_full_reviews();
        return $this->merge_reviews_and_comments($this->viewable_submitted_reviews_by_display($user), $this->viewable_comments($user));
    }

    /** @return list<ReviewInfo|CommentInfo> */
    function viewable_reviews_and_comments(Contact $user) {
        $this->ensure_full_reviews();
        $rrows = [];
        foreach ($this->reviews_by_display($user) as $rrow) {
            if ($user->can_view_review($this, $rrow)) {
                $rrows[] = $rrow;
            }
        }
        return $this->merge_reviews_and_comments($rrows, $this->viewable_comments($user));
    }

    static function review_or_comment_text_separator($a, $b) {
        if (!$a || !$b) {
            return "";
        } else if (isset($a->reviewId)
                   || isset($b->reviewId)
                   || (($a->commentType | $b->commentType) & COMMENTTYPE_RESPONSE)) {
            return "\n\n\n";
        } else {
            return "\n\n";
        }
    }


    /** @param Contact $a
     * @param Contact $b */
    static function notify_user_compare($a, $b) {
        // group authors together, then reviewers
        $act = (int) $a->conflictType;
        $bct = (int) $b->conflictType;
        if (($act >= CONFLICT_AUTHOR) !== ($bct >= CONFLICT_AUTHOR)) {
            return $act >= CONFLICT_AUTHOR ? -1 : 1;
        }
        $arp = $a->myReviewPermissions;
        $brp = $b->myReviewPermissions;
        if ((bool) $arp !== (bool) $brp) {
            return (bool) $arp ? -1 : 1;
        }
        return call_user_func($a->conf->user_comparator(), $a, $b);
    }

    function notify_reviews($callback, $sending_user) {
        $result = $this->conf->qe_raw("select ContactInfo.contactId, firstName, lastName, email,
                password, roles, contactTags, defaultWatch,
                " . self::my_review_permissions_sql() . " myReviewPermissions,
                conflictType, watch, preferredEmail, disabled
        from ContactInfo
        left join PaperConflict on (PaperConflict.paperId=$this->paperId and PaperConflict.contactId=ContactInfo.contactId)
        left join PaperWatch on (PaperWatch.paperId=$this->paperId and PaperWatch.contactId=ContactInfo.contactId)
        left join PaperReview on (PaperReview.paperId=$this->paperId and PaperReview.contactId=ContactInfo.contactId)
        where (watch&" . Contact::WATCH_REVIEW . ")!=0
        or (defaultWatch&" . (Contact::WATCH_REVIEW_ALL | Contact::WATCH_REVIEW_MANAGED) . ")!=0
        or conflictType>=" . CONFLICT_AUTHOR . "
        or reviewType is not null
        or exists (select * from PaperComment where paperId=$this->paperId and contactId=ContactInfo.contactId)
        group by ContactInfo.contactId");

        $watchers = [];
        $lastContactId = 0;
        while (($minic = Contact::fetch($result, $this->conf))) {
            if ($minic->contactId == $lastContactId
                || ($sending_user && $minic->contactId == $sending_user->contactId)
                || Contact::is_anonymous_email($minic->email)) {
                continue;
            }
            $lastContactId = $minic->contactId;
            if ($minic->following_reviews($this, $minic->watch)) {
                $watchers[$minic->contactId] = $minic;
            }
        }
        Dbl::free($result);
        usort($watchers, "PaperInfo::notify_user_compare");

        // save my current contact info map -- we are replacing it with another
        // map that lacks review token information and so forth
        $cimap = $this->replace_contact_info_map([]);

        foreach ($watchers as $minic) {
            $this->load_my_contact_info($minic, $minic);
            call_user_func($callback, $this, $minic);
        }

        $this->replace_contact_info_map($cimap);
    }

    function notify_final_submit($callback, $sending_user) {
        $result = $this->conf->qe_raw("select ContactInfo.contactId, firstName, lastName, email,
                password, roles, contactTags, defaultWatch,
                " . self::my_review_permissions_sql() . " myReviewPermissions,
                conflictType, watch, preferredEmail, disabled
        from ContactInfo
        left join PaperConflict on (PaperConflict.paperId=$this->paperId and PaperConflict.contactId=ContactInfo.contactId)
        left join PaperWatch on (PaperWatch.paperId=$this->paperId and PaperWatch.contactId=ContactInfo.contactId)
        left join PaperReview on (PaperReview.paperId=$this->paperId and PaperReview.contactId=ContactInfo.contactId)
        where (defaultWatch&" . (Contact::WATCH_FINAL_SUBMIT_ALL) . ")!=0
        group by ContactInfo.contactId");

        $watchers = [];
        $lastContactId = 0;
        while (($minic = Contact::fetch($result, $this->conf))) {
            if ($minic->contactId == $lastContactId
                || ($sending_user && $minic->contactId == $sending_user->contactId)
                || Contact::is_anonymous_email($minic->email))
                continue;
            $lastContactId = $minic->contactId;
            $watchers[$minic->contactId] = $minic;
        }
        Dbl::free($result);
        usort($watchers, "PaperInfo::notify_user_compare");

        // save my current contact info map -- we are replacing it with another
        // map that lacks review token information and so forth
        $cimap = $this->replace_contact_info_map([]);

        foreach ($watchers as $minic) {
            $this->load_my_contact_info($minic, $minic);
            call_user_func($callback, $this, $minic);
        }

        $this->replace_contact_info_map($cimap);
    }

    function delete_from_database(Contact $user = null) {
        // XXX email self?
        if ($this->paperId <= 0) {
            return false;
        }
        $rrows = $this->reviews_by_id();

        $qs = [];
        foreach (["PaperWatch", "PaperReviewPreference", "PaperReviewRefused", "ReviewRequest", "PaperTag", "PaperComment", "PaperReview", "PaperTopic", "PaperOption", "PaperConflict", "Paper", "PaperStorage", "Capability"] as $table) {
            $qs[] = "delete from $table where paperId={$this->paperId}";
        }
        $mresult = Dbl::multi_qe($this->conf->dblink, join(";", $qs));
        $mresult->free_all();

        if (!Dbl::$nerrors) {
            $this->conf->update_papersub_setting(-1);
            if ($this->outcome > 0) {
                $this->conf->update_paperacc_setting(-1);
            }
            if ($this->leadContactId > 0 || $this->shepherdContactId > 0) {
                $this->conf->update_paperlead_setting(-1);
            }
            if ($this->managerContactId > 0) {
                $this->conf->update_papermanager_setting(-1);
            }
            if ($rrows && array_filter($rrows, function ($rrow) { return $rrow->reviewToken > 0; })) {
                $this->conf->update_rev_tokens_setting(-1);
            }
            if ($rrows && array_filter($rrows, function ($rrow) { return $rrow->reviewType == REVIEW_META; })) {
                $this->conf->update_metareviews_setting(-1);
            }
            $this->conf->log_for($user, $user, "Paper deleted", $this->paperId);
            return true;
        } else {
            return false;
        }
    }
}
