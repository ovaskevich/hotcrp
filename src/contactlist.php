<?php
// contactlist.php -- HotCRP helper class for producing lists of contacts
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class ContactList {
    const FIELD_SELECTOR = 1000;
    const FIELD_SELECTOR_ON = 1001;

    const FIELD_NAME = 1;
    const FIELD_EMAIL = 2;
    const FIELD_AFFILIATION = 3;
    const FIELD_LASTVISIT = 5;
    const FIELD_HIGHTOPICS = 6;
    const FIELD_LOWTOPICS = 7;
    const FIELD_REVIEWS = 8;
    const FIELD_PAPERS = 9;
    const FIELD_REVIEW_PAPERS = 10;
    const FIELD_AFFILIATION_ROW = 11;
    const FIELD_REVIEW_RATINGS = 12;
    const FIELD_LEADS = 13;
    const FIELD_SHEPHERDS = 14;
    const FIELD_TAGS = 15;
    const FIELD_COLLABORATORS = 16;
    const FIELD_ACCEPTED_PAPERS = 17;
    const FIELD_SCORE = 50;

    public static $folds = array("topics", "aff", "tags", "collab");

    /** @var Conf */
    public $conf;
    /** @var Contact */
    public $user;
    public $qreq;
    var $showHeader = true;
    var $sortField = null;
    var $reverseSort;
    var $sortable;
    var $count;
    var $any;
    private $tagger;
    public $scoreMax;
    private $limit;
    public $have_folds = array();
    private $qopt = [];
    var $contactLinkArgs;
    /** @var PaperInfoSet */
    private $_rowset;
    /** @var array<int,list<int>> */
    private $_au_data;
    /** @var array<int,list<int>> */
    private $_auacc_data;
    /** @var array<int,list<int>> */
    private $_re_data;
    /** @var array<int,list<array{int,int,int,int}>> */
    private $_reord_data;
    /** @var array<int,array{int,int}> */
    private $_rect_data;
    /** @var array<int,int> */
    private $_lead_data;
    /** @var array<int,int> */
    private $_shepherd_data;
    /** @var array<string,array<int,list<int>>> */
    private $_score_data;
    /** @var array<int,array{int,int}> */
    private $_rating_data;
    /** @var array<int,true> */
    private $_limit_cids;

    function __construct(Contact $user, $sortable = true, $qreq = null) {
        global $contactListFields;

        $this->conf = $user->conf;
        $this->user = $user;
        if (!$qreq || !($qreq instanceof Qrequest)) {
            $qreq = new Qrequest("GET", $qreq);
        }
        $this->qreq = $qreq;

        $s = ($sortable ? (string) $this->qreq->sort : "");
        $x = (strlen($s) ? $s[strlen($s)-1] : "");
        $this->reverseSort = ($x == "R");
        if ($x == "R" || $x == "N") {
            $s = substr($s, 0, strlen($s) - 1);
        }
        if ($s !== "") {
            $this->sortField = $s;
        }
        $this->sortable = $sortable;

        $this->tagger = new Tagger($this->user);
        $this->contactLinkArgs = "";
    }

    /** @param int|string $fieldId */
    function selector($fieldId) {
        if (!$this->user->isPC
            && $fieldId != self::FIELD_NAME
            && $fieldId != self::FIELD_AFFILIATION
            && $fieldId != self::FIELD_AFFILIATION_ROW) {
            return false;
        }
        if ($fieldId == self::FIELD_HIGHTOPICS || $fieldId == self::FIELD_LOWTOPICS) {
            $this->have_folds["topics"] = $this->qopt["topics"] = true;
        }
        if ($fieldId == self::FIELD_REVIEWS) {
            $this->qopt["reviews"] = true;
        }
        if ($fieldId == self::FIELD_LEADS) {
            $this->qopt["papers"] = $this->qopt["leads"] = true;
        }
        if ($fieldId == self::FIELD_SHEPHERDS) {
            $this->qopt["papers"] = $this->qopt["shepherds"] = true;
        }
        if ($fieldId == self::FIELD_REVIEW_RATINGS) {
            if ($this->conf->setting("rev_ratings") == REV_RATINGS_NONE) {
                return false;
            }
            $this->qopt["revratings"] = $this->qopt["reviews"] = true;
        }
        if ($fieldId == self::FIELD_PAPERS
            || $fieldId == self::FIELD_ACCEPTED_PAPERS) {
            $this->qopt["papers"] = true;
        }
        if ($fieldId == self::FIELD_REVIEW_PAPERS) {
            $this->qopt["repapers"] = $this->qopt["reviews"] = true;
        }
        if ($fieldId == self::FIELD_AFFILIATION_ROW) {
            $this->have_folds["aff"] = true;
        }
        if ($fieldId == self::FIELD_TAGS) {
            $this->have_folds["tags"] = true;
        }
        if ($fieldId == self::FIELD_COLLABORATORS) {
            $this->have_folds["collab"] = true;
        }
        if (($f = $this->conf->review_field($fieldId))) {
            $revViewScore = $this->user->permissive_view_score_bound();
            if ($f->view_score <= $revViewScore || !$f->has_options) {
                return false;
            }
            $this->qopt["reviews"] = true;
            if (!isset($this->qopt["scores"])) {
                $this->qopt["scores"] = array();
            }
            $this->qopt["scores"][] = $f->id;
            $this->scoreMax[$f->id] = count($f->options);
        }
        return true;
    }

    function _sortBase($a, $b) {
        return call_user_func($this->conf->user_comparator(), $a, $b);
    }

    function _sortEmail($a, $b) {
        return strnatcasecmp($a->email, $b->email);
    }

    function _sortAffiliation($a, $b) {
        $x = strnatcasecmp($a->affiliation, $b->affiliation);
        return $x ? : $this->_sortBase($a, $b);
    }

    function _sortLastVisit($a, $b) {
        if ($a->activity_at != $b->activity_at) {
            return $a->activity_at < $b->activity_at ? 1 : -1;
        } else {
            return $this->_sortBase($a, $b);
        }
    }

    function _sortReviews($a, $b) {
        $ac = $this->_rect_data[$a->contactId] ?? [0, 0];
        $bc = $this->_rect_data[$b->contactId] ?? [0, 0];
        $x = $bc[1] - $ac[1] ? : $bc[0] - $ac[0];
        return $x ? : $this->_sortBase($a, $b);
    }

    function _sortLeads($a, $b) {
        $cid = $b->contactId;
        $x = ($this->_lead_data[$b->contactId] ?? 0) - ($this->_lead_data[$a->contactId] ?? 0);
        return $x ? : $this->_sortBase($a, $b);
    }

    function _sortShepherds($a, $b) {
        $x = ($this->_shepherd_data[$b->contactId] ?? 0) - ($this->_shepherd_data[$a->contactId] ?? 0);
        return $x ? : $this->_sortBase($a, $b);
    }

    function _sortReviewRatings($a, $b) {
        list($ag, $ab) = $this->_rating_data[$a->contactId] ?? [0, 0];
        list($bg, $bb) = $this->_rating_data[$b->contactId] ?? [0, 0];
        if ($ag - $ab === 0) {
            if ($bg + $bb !== 0) {
                return 1;
            }
        } else if ($bg + $bb === 0) {
            return -1;
        } else if ($ag - $ab !== $bg - $bb) {
            return $ag - $ab > $bg - $bb ? -1 : 1;
        } else if ($ag + $ab !== $bg + $bb) {
            return $ag + $ab > $bg + $bb ? -1 : 1;
        }
        return $this->_sortBase($a, $b);
    }

    /** @param Contact $a
     * @param Contact $b
     * @param array<int,list<int>> $map */
    private function _sort_paper_list($a, $b, $map) {
        $ap = $map[$a->contactId] ?? [];
        $bp = $map[$b->contactId] ?? [];
        if (count($ap) !== count($bp)) {
            return count($ap) > count($bp) ? -1 : 1;
        }
        for ($i = 0; $i !== count($ap); ++$i) {
            if ($ap[$i] !== $bp[$i])
                return $ap[$i] < $bp[$i] ? -1 : 1;
        }
        return $this->_sortBase($a, $b);
    }

    function _sort_papers($a, $b) {
        return $this->_sort_paper_list($a, $b, $this->_au_data);
    }

    function _sort_accepted_papers($a, $b) {
        return $this->_sort_paper_list($a, $b, $this->_auacc_data);
    }

    function _sort_reviewed_papers($a, $b) {
        return $this->_sort_paper_list($a, $b, $this->_re_data);
    }

    function _sortScores($a, $b) {
        if (!($x = ScoreInfo::compare($b->_sort_info, $a->_sort_info, -1))) {
            $x = ScoreInfo::compare($b->_sort_avg, $a->_sort_avg);
        }
        return $x ? ($x < 0 ? -1 : 1) : $this->_sortBase($a, $b);
    }

    function _sort($rows) {
        switch ($this->sortField) {
        case self::FIELD_NAME:
            usort($rows, [$this, "_sortBase"]);
            break;
        case self::FIELD_EMAIL:
            usort($rows, array($this, "_sortEmail"));
            break;
        case self::FIELD_AFFILIATION:
        case self::FIELD_AFFILIATION_ROW:
            usort($rows, array($this, "_sortAffiliation"));
            break;
        case self::FIELD_LASTVISIT:
            usort($rows, array($this, "_sortLastVisit"));
            break;
        case self::FIELD_REVIEWS:
            usort($rows, array($this, "_sortReviews"));
            break;
        case self::FIELD_LEADS:
            usort($rows, array($this, "_sortLeads"));
            break;
        case self::FIELD_SHEPHERDS:
            usort($rows, array($this, "_sortShepherds"));
            break;
        case self::FIELD_REVIEW_RATINGS:
            usort($rows, array($this, "_sortReviewRatings"));
            break;
        case self::FIELD_PAPERS:
            usort($rows, [$this, "_sort_papers"]);
            break;
        case self::FIELD_ACCEPTED_PAPERS:
            usort($rows, [$this, "_sort_accepted_papers"]);
            break;
        case self::FIELD_REVIEW_PAPERS:
            usort($rows, [$this, "_sort_reviewed_papers"]);
            break;
        default:
            if (($f = $this->conf->review_field($this->sortField))) {
                $fieldId = $this->sortField;
                $scoreMax = $this->scoreMax[$fieldId];
                $scoresort = $this->user->session("ulscoresort", "A");
                if (!in_array($scoresort, ["A", "V", "D"], true)) {
                    $scoresort = "A";
                }
                Contact::$allow_nonexistent_properties = true;
                foreach ($rows as $row) {
                    $scores = $this->_score_data[$fieldId][$row->contactId] ?? [];
                    $scoreinfo = new ScoreInfo($scores, true);
                    $row->_sort_info = $scoreinfo->sort_data($scoresort);
                    $row->_sort_avg = $scoreinfo->mean();
                }
                usort($rows, array($this, "_sortScores"));
                Contact::$allow_nonexistent_properties = false;
            }
            break;
        }
        if ($this->reverseSort) {
            return array_reverse($rows);
        } else {
            return $rows;
        }
    }

    function header($fieldId, $ordinal, $row = null) {
        switch ($fieldId) {
        case self::FIELD_NAME:
            return "Name";
        case self::FIELD_EMAIL:
            return "Email";
        case self::FIELD_AFFILIATION:
        case self::FIELD_AFFILIATION_ROW:
            return "Affiliation";
        case self::FIELD_LASTVISIT:
            return '<span class="hastitle" title="Includes paper changes, review updates, and profile changes">Last update</span>';
        case self::FIELD_HIGHTOPICS:
            return "High-interest topics";
        case self::FIELD_LOWTOPICS:
            return "Low-interest topics";
        case self::FIELD_REVIEWS:
            return '<span class="hastitle" title="“1/2” means 1 complete review out of 2 assigned reviews">Reviews</span>';
        case self::FIELD_LEADS:
            return "Leads";
        case self::FIELD_SHEPHERDS:
            return "Shepherds";
        case self::FIELD_REVIEW_RATINGS:
            return '<span class="hastitle" title="Ratings of reviews">Rating</a>';
        case self::FIELD_SELECTOR:
            return "";
        case self::FIELD_PAPERS:
            return "Submissions";
        case self::FIELD_ACCEPTED_PAPERS:
            return "Accepted submissions";
        case self::FIELD_REVIEW_PAPERS:
            return "Assigned submissions";
        case self::FIELD_TAGS:
            return "Tags";
        case self::FIELD_COLLABORATORS:
            return "Collaborators";
        default:
            if (($f = $this->conf->review_field($fieldId))) {
                return $f->web_abbreviation();
            } else {
                return "&lt;$fieldId&gt;?";
            }
        }
    }

    /** @param PaperInfo $prow
     * @param ReviewInfo $rrow */
    private function collect_review_data($prow, $rrow, $repapers, $review_limit, $scores) {
        $cid = $rrow->contactId;
        if ($repapers) {
            $this->_re_data[$cid][] = $rrow->paperId;
            $this->_reord_data[$cid][] = [$rrow->paperId, $rrow->reviewId, $rrow->reviewOrdinal];
        }
        if ($review_limit
            && ($prow->timeSubmitted > 0 || $rrow->reviewSubmitted > 0 || $rrow->timeApprovalRequested < 0)) {
            if ($this->limit === "re"
                || ($this->limit === "req" && $rrow->reviewType == REVIEW_EXTERNAL && $rrow->requestedBy == $this->user->contactId)
                || ($this->limit === "ext" && $rrow->reviewType == REVIEW_EXTERNAL)
                || ($this->limit === "extsub" && $rrow->reviewType == REVIEW_EXTERNAL && ($rrow->reviewSubmitted > 0 || $rrow->timeApprovalRequested < 0))) {
                $this->_limit_cids[$cid] = true;
            }
        }
        if (!isset($this->_rect_data[$cid])) {
            $this->_rect_data[$cid] = [0, 0];
        }
        if ($rrow->reviewSubmitted > 0 || $rrow->timeApprovalRequested < 0) {
            $this->_rect_data[$cid][0] += 1;
            $this->_rect_data[$cid][1] += 1;
            if ($this->user->can_view_review($prow, $rrow)) {
                foreach ($scores as $s) {
                    if ($rrow->$s) {
                        $this->_score_data[$s][$cid][] = (int) $rrow->$s;
                    }
                }
            }
        } else if ($rrow->reviewNeedsSubmit) {
            $this->_rect_data[$cid][0] += 1;
        }
    }

    private function collect_paper_data() {
        $review_limit = in_array($this->limit, ["re", "req", "ext", "extsub"]);

        $args = [];
        if (isset($this->qopt["papers"])) {
            $args["allConflictType"] = true;
        }
        if (isset($this->qopt["reviews"]) || $review_limit) {
            $args["reviewSignatures"] = true;
            if (isset($this->qopt["scores"])) {
                $args["scores"] = $this->qopt["scores"];
            }
        }
        if ($this->limit === "req") {
            $args["myReviewRequests"] = true;
        }
        if (empty($args)
            && !isset($this->qopt["leads"])
            && !isset($this->qopt["shepherds"])
            && !str_starts_with($this->limit, "au")) {
            return;
        }

        $overrides = $this->user->add_overrides(Contact::OVERRIDE_CONFLICT);

        $prows = $this->user->paper_set($args);
        $prows->apply_filter(function ($prow) {
            return $this->user->can_view_paper($prow);
        });

        if (str_starts_with($this->limit, "au")) {
            $this->_limit_cids = [];
            foreach ($prows as $prow) {
                if (($this->limit === "au" && $prow->timeSubmitted <= 0)
                    || ($this->limit === "aurej" && $prow->outcome >= 0)
                    || ($this->limit === "auacc" && $prow->outcome <= 0)
                    || ($this->limit === "auuns" && $prow->timeSubmitted > 0)) {
                    /* skip */
                } else {
                    foreach ($prow->contacts() as $cid => $cflt) {
                        $this->_limit_cids[$cid] = true;
                    }
                }
            }
        } else if ($review_limit) {
            $this->_limit_cids = [];
        }

        if (isset($this->qopt["papers"])) {
            $this->_au_data = $this->_auacc_data = [];
            foreach ($prows as $prow) {
                if ($this->user->can_view_authors($prow)) {
                    foreach ($prow->contacts() as $cflt) {
                        $this->_au_data[$cflt->contactId][] = $prow->paperId;
                    }
                    if ($prow->outcome > 0
                        && $this->user->can_view_decision($prow)) {
                        foreach ($prow->contacts() as $cflt) {
                            $this->_auacc_data[$cflt->contactId][] = $prow->paperId;
                        }
                    }
                }
            }
        }

        if (isset($this->qopt["reviews"]) || $review_limit) {
            $repapers = $this->qopt["repapers"] ?? false;
            $this->_rect_data = [];
            if ($repapers) {
                $this->_re_data = $this->_reord_data = [];
            }
            $scores = $this->qopt["scores"] ?? [];
            foreach ($scores as $s) {
                $this->_score_data[$s] = [];
            }
            foreach ($prows as $prow) {
                if ($this->user->can_view_review_assignment($prow, null)
                    && $this->user->can_view_review_identity($prow, null)) {
                    foreach ($prow->reviews_by_id() as $rrow) {
                        if ($this->user->can_view_review_assignment($prow, $rrow)
                            && $this->user->can_view_review_identity($prow, $rrow)) {
                            $this->collect_review_data($prow, $rrow, $repapers, $review_limit, $scores);
                        }
                    }
                }
            }
        }

        if (isset($this->qopt["revratings"])) {
            $pids = $ratings = [];
            foreach ($prows as $prow) {
                if ($this->user->can_view_review_ratings($prow)) {
                    $pids[] = $prow->paperId;
                }
            }
            $result = $this->conf->qe("select paperId, reviewId, " . $this->conf->query_ratings() . " allRatings from PaperReview where paperId ?a group by paperId, reviewId", $pids);
            while (($row = $result->fetch_row())) {
                $ratings[$row[0]][$row[1]] = $row[2];
            }
            Dbl::free($result);
            $this->_rating_data = [];
            foreach ($prows as $prow) {
                if ($this->user->can_view_review_ratings($prow)) {
                    foreach ($prow->reviews_by_id() as $rrow) {
                        if (isset($ratings[$prow->paperId][$rrow->reviewId])
                            && $this->user->can_view_review_ratings($prow, $rrow)) {
                            $rrow->allRatings = $ratings[$prow->paperId][$rrow->reviewId];
                            $cid = $rrow->contactId;
                            $this->_rating_data[$cid] = $this->_rating_data[$cid] ?? [0, 0];
                            foreach ($rrow->ratings() as $rate) {
                                $good = $rate & ReviewInfo::RATING_GOODMASK ? 0 : 1;
                                $this->_rating_data[$cid][$good] += 1;
                            }
                        }
                    }
                }
            }
        }

        if (isset($this->qopt["leads"])) {
            $this->_lead_data = [];
            foreach ($prows as $prow) {
                if ($prow->leadContactId
                    && $this->user->can_view_lead($prow)) {
                    $c = (int) $prow->leadContactId;
                    $this->_lead_data[$c] = ($this->_lead_data[$c] ?? 0) + 1;
                }
            }
        }

        if (isset($this->qopt["shepherds"])) {
            $this->_shepherd_data = [];
            foreach ($prows as $prow) {
                if ($prow->shepherdContactId
                    && $this->user->can_view_shepherd($prow)) {
                    $c = (int) $prow->shepherdContactId;
                    $this->_shepherd_data[$c] = ($this->_shepherd_data[$c] ?? 0) + 1;
                }
            }
        }

        $this->user->set_overrides($overrides);
    }

    function content($fieldId, $row) {
        switch ($fieldId) {
        case self::FIELD_NAME:
            $t = $row->name_h($this->sortField == $fieldId ? NAME_S : 0);
            if (trim($t) === "") {
                $t = "[No name]";
            }
            $t = '<span class="taghl">' . $t . '</span>';
            if ($this->user->privChair) {
                $t = "<a href=\"" . $this->conf->hoturl("profile", "u=" . urlencode($row->email) . $this->contactLinkArgs) . "\"" . ($row->is_disabled() ? ' class="uu"' : "") . ">$t</a>";
            }
            if (($viewable = $row->viewable_tags($this->user))
                && $this->conf->tags()->has_decoration) {
                $tagger = new Tagger($this->user);
                $t .= $tagger->unparse_decoration_html($viewable, Tagger::DECOR_USER);
            }
            $roles = $row->viewable_pc_roles($this->user);
            if ($roles === Contact::ROLE_PC && $this->limit === "pc") {
                $roles = 0;
            }
            if ($roles !== 0 && ($rolet = Contact::role_html_for($roles))) {
                $t .= " $rolet";
            }
            if ($this->user->privChair && $row->email != $this->user->email) {
                $t .= " <a href=\"" . $this->conf->hoturl("index", "actas=" . urlencode($row->email)) . "\">"
                    . Ht::img("viewas.png", "[Act as]", ["title" => "Act as " . $row->name(NAME_P)])
                    . "</a>";
            }
            if ($row->is_disabled() && $this->user->isPC) {
                $t .= ' <span class="hint">(disabled)</span>';
            }
            return $t;
        case self::FIELD_EMAIL:
            if ($this->user->isPC) {
                $e = htmlspecialchars($row->email);
                if (strpos($row->email, "@") === false) {
                    return $e;
                } else {
                    return "<a href=\"mailto:$e\" class=\"mailto\">$e</a>";
                }
            } else {
                return "";
            }
        case self::FIELD_AFFILIATION:
        case self::FIELD_AFFILIATION_ROW:
            return htmlspecialchars($row->affiliation);
        case self::FIELD_LASTVISIT:
            if (!$row->activity_at) {
                return "Never";
            } else {
                return $this->conf->unparse_time_obscure($row->activity_at);
            }
        case self::FIELD_SELECTOR:
        case self::FIELD_SELECTOR_ON:
            $this->any->sel = true;
            $c = "";
            if ($fieldId == self::FIELD_SELECTOR_ON) {
                $c = ' checked="checked"';
            }
            return '<input type="checkbox" class="uic js-range-click" name="pap[]" value="' . $row->contactId . '" tabindex="1"' . $c . ' />';
        case self::FIELD_HIGHTOPICS:
        case self::FIELD_LOWTOPICS:
            if (!($topics = $row->topic_interest_map())) {
                return "";
            }
            if ($fieldId == self::FIELD_HIGHTOPICS) {
                $nt = array_filter($topics, function ($i) { return $i > 0; });
            } else {
                $nt = array_filter($topics, function ($i) { return $i < 0; });
            }
            return $this->conf->topic_set()->unparse_list_html(array_keys($nt), $nt);
        case self::FIELD_REVIEWS:
            if (($ct = $this->_rect_data[$row->contactId] ?? null)) {
                $a1 = "<a href=\"" . $this->conf->hoturl("search", "t=s&amp;q=re:" . urlencode($row->email)) . "\">";
                if ($ct[0] === $ct[1]) {
                    return $a1 . "<b>{$ct[1]}</b></a>";
                } else {
                    return $a1 . "<b>{$ct[1]}</b>/{$ct[0]}</a>";
                }
            } else {
                return "";
            }
        case self::FIELD_LEADS:
            if (($c = $this->_lead_data[$row->contactId] ?? null)) {
                return "<a href=\"" . $this->conf->hoturl("search", "t=s&amp;q=lead:" . urlencode($row->email)) . "\">$c</a>";
            } else {
                return "";
            }
        case self::FIELD_SHEPHERDS:
            if (($c = $this->_shepherd_data[$row->contactId] ?? null)) {
                return "<a href=\"" . $this->conf->hoturl("search", "t=s&amp;q=shepherd:" . urlencode($row->email)) . "\">$c</a>";
            } else {
                return "";
            }
        case self::FIELD_REVIEW_RATINGS:
            if (($c = $this->_rating_data[$row->contactId] ?? null)
                && ($c[0] || $c[1])) {
                $a = $b = [];
                if ($c[0]) {
                    $a[] = "{$c[0]} positive";
                    $b[] = "<a href=\"" . $this->conf->hoturl("search", "q=re:" . urlencode($row->email) . "+rate:good") . "\">+{$c[0]}</a>";
                }
                if ($c[1]) {
                    $a[] = "{$c[1]} negative";
                    $b[] = "<a href=\"" . $this->conf->hoturl("search", "q=re:" . urlencode($row->email) . "+rate:bad") . "\">&minus;{$c[1]}</a>";
                }
                return '<span class="hastitle" title="' . join(", ", $a) . '">' . join(" ", $b) . '</span>';
            } else {
                return "";
            }
        case self::FIELD_PAPERS:
            if (($pids = $this->_au_data[$row->contactId] ?? null)) {
                $t = [];
                foreach ($pids as $p) {
                    $t[] = '<a href="' . $this->conf->hoturl("paper", "p=$p") . '">' . $p . '</a>';
                }
                if ($this->limit === "auuns" || $this->limit === "all") {
                    $ls = "p/all/";
                } else {
                    $ls = "p/s/";
                }
                return '<div class="has-hotlist" data-hotlist="'
                    . htmlspecialchars($ls . urlencode("au:" . $row->email))
                    . '">' . join(", ", $t) . '</div>';
            } else {
                return "";
            }
        case self::FIELD_ACCEPTED_PAPERS:
            if (($pids = $this->_auacc_data[$row->contactId] ?? null)) {
                $t = [];
                foreach ($pids as $p) {
                    $t[] = '<a href="' . $this->conf->hoturl("paper", "p=$p") . '">' . $p . '</a>';
                }
                return '<div class="has-hotlist" data-hotlist="'
                    . htmlspecialchars("p/acc/" . urlencode("au:" . $row->email))
                    . '">' . join(", ", $t) . '</div>';
            } else {
                return "";
            }
        case self::FIELD_REVIEW_PAPERS:
            $t = [];
            if (($reords = $this->_reord_data[$row->contactId] ?? null)) {
                $last = null;
                foreach ($reords as $reord) {
                    if ($last !== $reord[0])  {
                        if ($reord[2]) {
                            $url = $this->conf->hoturl("paper", "p={$reord[0]}#r{$reord[0]}" . unparseReviewOrdinal($reord[2]));
                        } else {
                            $url = $this->conf->hoturl("review", "p={$reord[0]}&amp;r={$reord[1]}");
                        }
                        $t[] = "<a href=\"{$url}\">{$reord[0]}</a>";
                    }
                    $last = $reord[0];
                }
            }
            if (!empty($t)) {
                $ls = htmlspecialchars("p/s/" . urlencode("re:" . $row->email));
                return '<div class="has-hotlist" data-hotlist="' . $ls . '">'
                    . join(", ", $t) . '</div>';
            } else {
                return "";
            }
        case self::FIELD_TAGS:
            if ($this->user->isPC
                && ($tags = $row->viewable_tags($this->user))) {
                $x = [];
                foreach (Tagger::split($tags) as $t) {
                    if ($t !== "pc#0")
                        $x[] = '<a class="qq nw" href="' . $this->conf->hoturl("users", "t=%23" . Tagger::base($t)) . '">' . $this->tagger->unparse_hashed($t) . '</a>';
                }
                return join(" ", $x);
            } else {
                return "";
            }
        case self::FIELD_COLLABORATORS:
            if ($this->user->isPC && ($row->roles & Contact::ROLE_PC)) {
                $t = [];
                foreach (explode("\n", $row->collaborators()) as $collab) {
                    if (preg_match(',\A(.*?)\s*(\(.*\))\s*\z,', $collab, $m)) {
                        $t[] = '<span class="nw">' . htmlspecialchars($m[1])
                            . ' <span class="auaff">' . htmlspecialchars($m[2]) . '</span></span>';
                    } else if (($collab = trim($collab)) !== "" && strcasecmp($collab, "None")) {
                        $t[] = '<span class="nw">' . htmlspecialchars($collab) . '</span>';
                    }
                }
                return join("; ", $t);
            } else {
                return "";
            }
        default:
            $f = $this->conf->review_field($fieldId);
            if ($f
                && (($row->roles & Contact::ROLE_PC)
                    || $this->user->privChair
                    || $this->limit === "req")
                && ($scores = $this->_score_data[$fieldId][$row->contactId] ?? [])) {
                return $f->unparse_graph($scores, 2, 0);
            } else {
                return "";
            }
        }
    }

    function addScores($a) {
        if ($this->user->isPC) {
            $uldisplay = $this->user->session("uldisplay", " tags overAllMerit ");
            foreach ($this->conf->all_review_fields() as $f) {
                if ($f->has_options && strpos($uldisplay, " {$f->id} ") !== false)
                    array_push($a, $f->id);
            }
            $this->scoreMax = array();
        }
        return $a;
    }

    function listFields($listname) {
        switch ($listname) {
        case "pc":
        case "admin":
        case "pcadmin":
            return $this->addScores(array($listname, self::FIELD_SELECTOR, self::FIELD_NAME, self::FIELD_EMAIL, self::FIELD_AFFILIATION, self::FIELD_LASTVISIT, self::FIELD_TAGS, self::FIELD_COLLABORATORS, self::FIELD_HIGHTOPICS, self::FIELD_LOWTOPICS, self::FIELD_REVIEWS, self::FIELD_REVIEW_RATINGS, self::FIELD_LEADS, self::FIELD_SHEPHERDS));
        case "pcadminx":
            return array($listname, self::FIELD_NAME, self::FIELD_EMAIL, self::FIELD_AFFILIATION, self::FIELD_LASTVISIT, self::FIELD_TAGS, self::FIELD_COLLABORATORS, self::FIELD_HIGHTOPICS, self::FIELD_LOWTOPICS);
          case "re":
            return $this->addScores(array($listname, self::FIELD_SELECTOR, self::FIELD_NAME, self::FIELD_EMAIL, self::FIELD_AFFILIATION, self::FIELD_LASTVISIT, self::FIELD_TAGS, self::FIELD_COLLABORATORS, self::FIELD_HIGHTOPICS, self::FIELD_LOWTOPICS, self::FIELD_REVIEWS, self::FIELD_REVIEW_RATINGS));
          case "ext":
          case "extsub":
            return $this->addScores(array($listname, self::FIELD_SELECTOR, self::FIELD_NAME, self::FIELD_EMAIL, self::FIELD_AFFILIATION, self::FIELD_LASTVISIT, self::FIELD_COLLABORATORS, self::FIELD_HIGHTOPICS, self::FIELD_LOWTOPICS, self::FIELD_REVIEWS, self::FIELD_REVIEW_RATINGS, self::FIELD_REVIEW_PAPERS));
          case "req":
            return $this->addScores(array("req", self::FIELD_SELECTOR, self::FIELD_NAME, self::FIELD_EMAIL, self::FIELD_AFFILIATION, self::FIELD_LASTVISIT, self::FIELD_TAGS, self::FIELD_COLLABORATORS, self::FIELD_HIGHTOPICS, self::FIELD_LOWTOPICS, self::FIELD_REVIEWS, self::FIELD_REVIEW_RATINGS, self::FIELD_REVIEW_PAPERS));
          case "au":
          case "aurej":
          case "auuns":
            return [$listname, self::FIELD_SELECTOR, self::FIELD_NAME, self::FIELD_EMAIL, self::FIELD_AFFILIATION_ROW, self::FIELD_LASTVISIT, self::FIELD_TAGS, self::FIELD_PAPERS, self::FIELD_COLLABORATORS];
          case "auacc":
            return [$listname, self::FIELD_SELECTOR, self::FIELD_NAME, self::FIELD_EMAIL, self::FIELD_AFFILIATION_ROW, self::FIELD_LASTVISIT, self::FIELD_TAGS, self::FIELD_ACCEPTED_PAPERS, self::FIELD_COLLABORATORS];
          case "all":
            return ["all", self::FIELD_SELECTOR, self::FIELD_NAME, self::FIELD_EMAIL, self::FIELD_AFFILIATION_ROW, self::FIELD_LASTVISIT, self::FIELD_TAGS, self::FIELD_PAPERS, self::FIELD_COLLABORATORS];
          default:
            return null;
        }
    }

    function footer($ncol, $hascolors) {
        if ($this->count == 0)
            return "";
        $lllgroups = [];

        // Begin linelinks
        $types = array("nameemail" => "Names and emails");
        if ($this->user->privChair) {
            $types["pcinfo"] = "PC info";
        }
        $lllgroups[] = ["", "Download",
            Ht::select("getaction", $types, null, ["class" => "want-focus"])
            . "&nbsp; " . Ht::submit("getgo", "Go")];

        if ($this->user->privChair) {
            $lllgroups[] = ["", "Tag",
                Ht::select("tagtype", array("a" => "Add", "d" => "Remove", "s" => "Define"), $this->qreq->tagtype)
                . ' &nbsp;tag(s) &nbsp;'
                . Ht::entry("tag", $this->qreq->tag, ["size" => 15, "class" => "want-focus js-autosubmit", "data-autosubmit-type" => "tagact"])
                . ' &nbsp;' . Ht::submit("tagact", "Go")];

            $mods = ["disableaccount" => "Disable", "enableaccount" => "Enable"];
            if ($this->user->can_change_password(null)) {
                $mods["resetpassword"] = "Reset password";
            }
            $mods["sendaccount"] = "Send account information";
            $lllgroups[] = ["", "Modify",
                Ht::select("modifytype", $mods, null, ["class" => "want-focus"])
                . "&nbsp; " . Ht::submit("modifygo", "Go")];
        }

        return "  <tfoot class=\"pltable" . ($hascolors ? " pltable-colored" : "")
            . "\">" . PaperList::render_footer_row(1, $ncol - 1,
                "<b>Select people</b> (or <a class=\"ui js-select-all\" href=\"\">select all {$this->count}</a>), then&nbsp; ",
                $lllgroups)
            . "</tfoot>\n";
    }

    function _rows() {
        // Collect paper data first
        $this->collect_paper_data();

        $mainwhere = [];
        if (isset($this->qopt["where"])) {
            $mainwhere[] = $this->qopt["where"];
        }
        if ($this->limit == "pc") {
            $mainwhere[] = "roles!=0 and (roles&" . Contact::ROLE_PC . ")!=0";
        } else if ($this->limit == "admin") {
            $mainwhere[] = "roles!=0 and (roles&" . (Contact::ROLE_ADMIN | Contact::ROLE_CHAIR) . ")!=0";
        } else if ($this->limit == "pcadmin" || $this->limit == "pcadminx") {
            $mainwhere[] = "roles!=0 and (roles&" . Contact::ROLE_PCLIKE . ")!=0";
        }
        if ($this->_limit_cids !== null) {
            $mainwhere[] = "contactId" . sql_in_int_list(array_keys($this->_limit_cids));
        }

        // make query
        $result = $this->conf->qe_raw("select * from ContactInfo" . (empty($mainwhere) ? "" : " where " . join(" and ", $mainwhere)));
        $rows = [];
        while (($row = Contact::fetch($result, $this->conf))) {
            if (!$row->is_anonymous_user()) {
                $rows[] = $row;
            }
        }
        Dbl::free($result);
        if (isset($this->qopt["topics"])) {
            Contact::load_topic_interests($rows);
        }
        return $rows;
    }

    function table_html($listname, $url, $listtitle = "", $foldsession = null) {
        global $contactListFields;

        // PC tags
        $listquery = $listname;
        $this->qopt = array();
        if (str_starts_with($listname, "#")) {
            $this->qopt["where"] = "(contactTags like " . Dbl::utf8ci("'% " . sqlq_for_like(substr($listname, 1)) . "#%'") . ")";
            $listquery = "pcadmin";
        }

        // get paper list
        if (!($baseFieldId = $this->listFields($listquery))) {
            Conf::msg_error("There is no people list query named “" . htmlspecialchars($listquery) . "”.");
            return null;
        }
        $this->limit = array_shift($baseFieldId);

        // get field array
        $fieldDef = array();
        $acceptable_fields = array();
        $this->any = (object) array("sel" => false);
        $ncol = 0;
        foreach ($baseFieldId as $fid) {
            if ($this->selector($fid) === false) {
                continue;
            }
            if (!($fieldDef[$fid] = $contactListFields[$fid] ?? null)) {
                $fieldDef[$fid] = $contactListFields[self::FIELD_SCORE];
            }
            $acceptable_fields[$fid] = true;
            if ($fieldDef[$fid][1] == 1) {
                $ncol++;
            }
        }

        // run query
        $rows = $this->_rows();
        if (empty($rows)) {
            return "No matching people";
        }

        // sort rows
        if (!$this->sortField || !get($acceptable_fields, $this->sortField)) {
            $this->sortField = self::FIELD_NAME;
        }
        $srows = $this->_sort($rows);

        // count non-callout columns
        $firstcallout = $lastcallout = null;
        $n = 0;
        foreach ($fieldDef as $fieldId => $fdef)
            if ($fdef[1] == 1) {
                if ($firstcallout === null && $fieldId < self::FIELD_SELECTOR)
                    $firstcallout = $n;
                if ($fieldId < self::FIELD_SCORE)
                    $lastcallout = $n + 1;
                ++$n;
            }
        $firstcallout = $firstcallout ? $firstcallout : 0;
        $lastcallout = ($lastcallout ? $lastcallout : $ncol) - $firstcallout;

        // collect row data
        $this->count = 0;
        $show_colors = $this->user->isPC;

        $anyData = array();
        $body = '';
        $extrainfo = $hascolors = false;
        $ids = array();
        foreach ($srows as $row) {
            if (($this->limit == "resub" || $this->limit == "extsub")
                && (!isset($this->_rect_data[$row->contactId])
                    || $this->_rect_data[$row->contactId][1] === 0)) {
                continue;
            }

            $trclass = "k" . ($this->count % 2);
            if ($show_colors && ($k = $row->viewable_color_classes($this->user))) {
                if (str_ends_with($k, " tagbg")) {
                    $trclass = $k;
                    $hascolors = true;
                } else {
                    $trclass .= " " . $k;
                }
            }
            if ($row->is_disabled() && $this->user->isPC) {
                $trclass .= " graytext";
            }
            $this->count++;
            $ids[] = (int) $row->contactId;

            // First create the expanded callout row
            $tt = "";
            foreach ($fieldDef as $fieldId => $fdef) {
                if ($fdef[1] >= 2
                    && ($d = $this->content($fieldId, $row)) !== "") {
                    $tt .= "<div";
                    //$t .= "  <tr class=\"pl_$fdef[0] pl_callout $trclass";
                    if ($fdef[1] >= 3) {
                        $tt .= " class=\"fx" . ($fdef[1] - 2) . "\"";
                    }
                    $tt .= '><em class="plx">' . $this->header($fieldId, -1, $row)
                        . ":</em> " . $d . "</div>";
                }
            }

            if ($tt !== "") {
                $x = "  <tr class=\"plx $trclass\">";
                if ($firstcallout > 0) {
                    $x .= "<td colspan=\"$firstcallout\"></td>";
                }
                $tt = $x . "<td class=\"plx\" colspan=\"" . ($lastcallout - $firstcallout)
                    . "\">" . $tt . "</td></tr>\n";
            }

            // Now the normal row
            $t = "  <tr class=\"pl $trclass" . ($tt !== "" ? "" : " plnx") . "\">\n";
            $n = 0;
            foreach ($fieldDef as $fieldId => $fdef) {
                if ($fdef[1] == 1) {
                    $c = $this->content($fieldId, $row);
                    $t .= "    <td class=\"pl pl_$fdef[0]\"";
                    if ($n >= $lastcallout && $tt != "") {
                        $t .= " rowspan=\"2\"";
                    }
                    $t .= ">" . $c . "</td>\n";
                    if ($c != "") {
                        $anyData[$fieldId] = 1;
                    }
                    ++$n;
                }
            }
            $t .= "  </tr>\n";

            $body .= $t . $tt;
        }

        $uldisplay = $this->user->session("uldisplay", " tags overAllMerit ");
        $foldclasses = array();
        foreach (self::$folds as $k => $fold) {
            if (get($this->have_folds, $fold) !== null) {
                $this->have_folds[$fold] = strpos($uldisplay, " $fold ") !== false;
                $foldclasses[] = "fold" . ($k + 1) . ($this->have_folds[$fold] ? "o" : "c");
            }
        }

        $x = "<table id=\"foldul\" class=\"pltable pltable-fullw";
        if ($foldclasses) {
            $x .= " " . join(" ", $foldclasses);
        }
        if ($foldclasses && $foldsession) {
            $fs = [];
            foreach (self::$folds as $k => $fold) {
                $fs[$k + 1] = $fold;
            }
            $x .= "\" data-fold-session=\"" . htmlspecialchars(json_encode_browser($fs)) . "\" data-fold-session-prefix=\"" . htmlspecialchars($foldsession);
        }
        $x .= "\">\n";

        if ($this->showHeader) {
            $x .= "  <thead class=\"pltable\">\n  <tr class=\"pl_headrow\">\n";
            $ord = 0;

            if ($this->sortable && $url) {
                $sortUrl = $url . (strpos($url, "?") ? "&amp;" : "?") . "sort=";
                $q = '<a class="pl_sort" rel="nofollow" href="' . $sortUrl;
                foreach ($fieldDef as $fieldId => $fdef) {
                    if ($fdef[1] != 1) {
                        continue;
                    } else if (!isset($anyData[$fieldId])) {
                        $x .= "    <th class=\"pl plh pl_$fdef[0]\"></th>\n";
                        continue;
                    }
                    $x .= "    <th class=\"pl plh pl_$fdef[0]\">";
                    $ftext = $this->header($fieldId, $ord++);
                    if ($fieldId == $this->sortField) {
                        $x .= '<a class="pl_sort pl_sorting' . ($this->reverseSort ? "_rev" : "_fwd") . '" rel="nofollow" href="' . $sortUrl . $fieldId . ($this->reverseSort ? "N" : "R") . '">' . $ftext . "</a>";
                    } else if ($fdef[2]) {
                        $x .= $q . $fieldId . "\">" . $ftext . "</a>";
                    } else {
                        $x .= $ftext;
                    }
                    $x .= "</th>\n";
                }

            } else {
                foreach ($fieldDef as $fieldId => $fdef) {
                    if ($fdef[1] == 1 && isset($anyData[$fieldId])) {
                        $x .= "    <th class=\"pl plh pl_$fdef[0]\">"
                            . $this->header($fieldId, $ord++) . "</th>\n";
                    } else if ($fdef[1] == 1) {
                        $x .= "    <th class=\"pl plh pl_$fdef[0]\"></th>\n";
                    }
                }
            }

            $x .= "  </tr></thead>\n";
        }

        reset($fieldDef);
        if (key($fieldDef) == self::FIELD_SELECTOR) {
            $x .= $this->footer($ncol, $hascolors);
        }

        $x .= "<tbody class=\"pltable" . ($hascolors ? " pltable-colored" : "");
        if ($this->user->privChair) {
            $listlink = $listname;
            if ($listlink === "pcadminx") {
                $listlink = "pcadmin";
            } else if ($listtitle === "") {
                if ($listlink === "pcadmin") {
                    $listtitle = "PC and admins";
                } else {
                    $listtitle = "Users";
                }
            }
            $l = new SessionList("u/" . $listlink, $ids, $listtitle,
                $this->conf->hoturl_site_relative_raw("users", ["t" => $listlink]));
            $x .= " has-hotlist\" data-hotlist=\"" . htmlspecialchars($l->info_string());
        }
        return $x . "\">" . $body . "</tbody></table>";
    }

    function rows($listname) {
        // PC tags
        $this->qopt = array();
        if (str_starts_with($listname, "#")) {
            $this->qopt["where"] = "(contactTags like " . Dbl::utf8ci("'% " . sqlq_for_like(substr($listname, 1)) . "#%'") . ")";
            $listname = "pc";
        }

        // get paper list
        if (!($baseFieldId = $this->listFields($listname))) {
            Conf::msg_error("There is no people list query named “" . htmlspecialchars($listname) . "”.");
            return null;
        }
        $this->limit = array_shift($baseFieldId);

        // run query
        return $this->_rows();
    }

}


global $contactListFields;
$contactListFields = array(
        ContactList::FIELD_SELECTOR => array('sel', 1, 0),
        ContactList::FIELD_SELECTOR_ON => array('sel', 1, 0),
        ContactList::FIELD_NAME => array('name', 1, 1),
        ContactList::FIELD_EMAIL => array('email', 1, 1),
        ContactList::FIELD_AFFILIATION => array('affiliation', 1, 1),
        ContactList::FIELD_AFFILIATION_ROW => array('affrow', 4, 0),
        ContactList::FIELD_LASTVISIT => array('lastvisit', 1, 1),
        ContactList::FIELD_HIGHTOPICS => array('topics', 3, 0),
        ContactList::FIELD_LOWTOPICS => array('topics', 3, 0),
        ContactList::FIELD_REVIEWS => array('revstat', 1, 1),
        ContactList::FIELD_REVIEW_RATINGS => array('revstat', 1, 1),
        ContactList::FIELD_PAPERS => array('papers', 1, 1),
        ContactList::FIELD_ACCEPTED_PAPERS => array('papers', 1, 1),
        ContactList::FIELD_REVIEW_PAPERS => array('papers', 1, 1),
        ContactList::FIELD_SCORE => array('uscores', 1, 1),
        ContactList::FIELD_LEADS => array('revstat', 1, 1),
        ContactList::FIELD_SHEPHERDS => array('revstat', 1, 1),
        ContactList::FIELD_TAGS => array('tags', 5, 0),
        ContactList::FIELD_COLLABORATORS => array('collab', 6, 0)
        );
