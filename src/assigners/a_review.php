<?php
// a_review.php -- HotCRP assignment helper classes
// Copyright (c) 2006-2019 Eddie Kohler; see LICENSE.

class Review_AssignmentParser extends AssignmentParser {
    private $rtype;
    function __construct(Conf $conf, $aj) {
        parent::__construct($aj->name);
        if ($aj->review_type)
            $this->rtype = (int) ReviewInfo::parse_type($aj->review_type);
        else
            $this->rtype = -1;
    }
    static function load_review_state(AssignmentState $state) {
        if ($state->mark_type("review", ["pid", "cid"], "Review_Assigner::make")) {
            $result = $state->conf->qe("select paperId, contactId, reviewType, reviewRound, reviewSubmitted, timeApprovalRequested from PaperReview where paperId?a", $state->paper_ids());
            while (($row = edb_row($result))) {
                $round = $state->conf->round_name($row[3]);
                $state->load([
                    "type" => "review", "pid" => +$row[0], "cid" => +$row[1],
                    "_rtype" => +$row[2], "_round" => $round,
                    "_rsubmitted" => $row[4] > 0 ? 1 : 0,
                    "_rnondraft" => $row[4] > 0 || $row[5] != 0 ? 1 : 0
                ]);
            }
            Dbl::free($result);
        }
    }
    function load_state(AssignmentState $state) {
        self::load_review_state($state);
        Conflict_AssignmentParser::load_conflict_state($state);
    }
    private function make_rdata($req, AssignmentState $state) {
        return ReviewAssigner_Data::make($req, $state, $this->rtype);
    }
    function user_universe($req, AssignmentState $state) {
        if ($this->rtype > REVIEW_EXTERNAL)
            return "pc";
        else if ($this->rtype == 0
                 || (($rdata = $this->make_rdata($req, $state))
                     && !$rdata->can_create_review()))
            return "reviewers";
        else
            return "any";
    }
    private function make_filter($fkey, $key, $value, $req, AssignmentState $state) {
        $rdata = $this->make_rdata($req, $state);
        if ($rdata->can_create_review())
            return null;
        return $state->make_filter($fkey, [
                "type" => "review", $key => $value,
                "_rtype" => $rdata->oldtype ? : null,
                "_round" => $rdata->oldround
            ]);
    }
    function paper_filter($contact, $req, AssignmentState $state) {
        return $this->make_filter("pid", "cid", $contact->contactId, $req, $state);
    }
    function expand_any_user(PaperInfo $prow, $req, AssignmentState $state) {
        $cf = $this->make_filter("cid", "pid", $prow->paperId, $req, $state);
        return $cf !== null ? $state->users_by_id(array_keys($cf)) : false;
    }
    function expand_missing_user(PaperInfo $prow, $req, AssignmentState $state) {
        return $this->expand_any_user($prow, $req, $state);
    }
    function expand_anonymous_user(PaperInfo $prow, $req, $user, AssignmentState $state) {
        if ($user === "anonymous-new") {
            $suf = "";
            while (($u = $state->user_by_email("anonymous" . $suf))
                   && $state->query(["type" => "review", "pid" => $prow->paperId,
                                     "cid" => $u->contactId]))
                $suf = $suf === "" ? 2 : $suf + 1;
            $user = "anonymous" . $suf;
        }
        if (preg_match('/\Aanonymous\d*\z/i', $user)
            && ($u = $state->user_by_email($user, true, [])))
            return [$u];
        else
            return false;
    }
    function allow_user(PaperInfo $prow, Contact $contact, $req, AssignmentState $state) {
        // User “none” is never allowed
        if (!$contact->contactId)
            return false;
        // PC reviews must be PC members
        $rdata = $this->make_rdata($req, $state);
        if ($rdata->newtype >= REVIEW_PC && !$contact->is_pc_member())
            return Text::user_html_nolink($contact) . " is not a PC member and cannot be assigned a PC review.";
        // Conflict allowed if we're not going to assign a new review
        if ($this->rtype == 0
            || $prow->has_reviewer($contact)
            || !$rdata->can_create_review())
            return true;
        // Check whether review assignments are acceptable
        if ($contact->is_pc_member()
            && !$contact->can_accept_review_assignment_ignore_conflict($prow))
            return Text::user_html_nolink($contact) . " cannot be assigned to review #{$prow->paperId}.";
        // Conflicts are checked later
        return true;
    }
    function apply(PaperInfo $prow, Contact $contact, $req, AssignmentState $state) {
        $rdata = $this->make_rdata($req, $state);
        if ($rdata->error)
            return $rdata->error;

        $revmatch = ["type" => "review", "pid" => $prow->paperId,
                     "cid" => $contact->contactId];
        $res = $state->remove($revmatch);
        assert(count($res) <= 1);
        $rev = empty($res) ? null : $res[0];

        if ($rev !== null
            && (($rdata->oldtype !== null && $rdata->oldtype !== $rev["_rtype"])
                || ($rdata->oldround !== null && $rdata->oldround !== $rev["_round"])
                || (!$rdata->newtype && $rev["_rsubmitted"]))) {
            $state->add($rev);
            return true;
        } else if (!$rdata->newtype
                   || ($rev === null && !$rdata->can_create_review())) {
            return true;
        }

        if ($rev === null) {
            $rev = $revmatch;
            $rev["_rtype"] = 0;
            $rev["_round"] = $rdata->newround;
            $rev["_rsubmitted"] = 0;
            $rev["_rnondraft"] = 0;
        }
        if (!$rev["_rtype"] || $rdata->newtype > 0) {
            $rev["_rtype"] = $rdata->newtype;
        }
        if ($rev["_rtype"] <= 0) {
            $rev["_rtype"] = REVIEW_EXTERNAL;
        }
        if ($rev["_rtype"] === REVIEW_EXTERNAL
            && $state->conf->pc_member_by_id($rev["cid"])) {
            $rev["_rtype"] = REVIEW_PC;
        }
        if ($rdata->newround !== null && $rdata->explicitround) {
            $rev["_round"] = $rdata->newround;
        }
        if ($rev["_rtype"] && isset($req["reason"])) {
            $rev["_reason"] = $req["reason"];
        }
        if (isset($req["override"]) && friendly_boolean($req["override"])) {
            $rev["_override"] = 1;
        }
        $state->add($rev);
        return true;
    }
}

class Review_Assigner extends Assigner {
    private $rtype;
    private $notify = false;
    private $unsubmit = false;
    private $token = false;
    static public $prefinfo = null;
    function __construct(AssignmentItem $item, AssignmentState $state) {
        parent::__construct($item, $state);
        $this->rtype = $item->get(false, "_rtype");
        $this->unsubmit = $item->get(true, "_rnondraft") && !$item->get(false, "_rnondraft");
        if (!$item->existed()
            && $this->rtype == REVIEW_EXTERNAL
            && !$this->contact->is_anonymous_user()
            && ($notify = get($state->defaults, "extrev_notify")))
            $this->notify = $notify;
    }
    static function make(AssignmentItem $item, AssignmentState $state) {
        if (!$item->get(true, "_rtype") && $item->get(false, "_rtype")) {
            Conflict_Assigner::check_unconflicted($item, $state);
        }
        return new Review_Assigner($item, $state);
    }
    function unparse_description() {
        return "review";
    }
    private function unparse_item(AssignmentSet $aset, $before) {
        if (!$this->item->get($before, "_rtype"))
            return "";
        $t = $aset->user->reviewer_html_for($this->contact) . ' '
            . review_type_icon($this->item->get($before, "_rtype"),
                               !$this->item->get($before, "_rsubmitted"));
        if (($round = $this->item->get($before, "_round")))
            $t .= ' <span class="revround" title="Review round">'
                . htmlspecialchars($round) . '</span>';
        if (self::$prefinfo
            && ($cpref = get(self::$prefinfo, $this->cid))
            && ($pref = get($cpref, $this->pid)))
            $t .= unparse_preference_span($pref);
        return $t;
    }
    private function icon($before) {
        return review_type_icon($this->item->get($before, "_rtype"),
                                !$this->item->get($before, "_rsubmitted"));
    }
    function unparse_display(AssignmentSet $aset) {
        $t = $aset->user->reviewer_html_for($this->contact);
        if ($this->item->deleted()) {
            $t = '<del>' . $t . '</del>';
        }
        if ($this->item->differs("_rtype") || $this->item->differs("_rsubmitted")) {
            if ($this->item->get(true, "_rtype"))
                $t .= ' <del>' . $this->icon(true) . '</del>';
            if ($this->item->get(false, "_rtype"))
                $t .= ' <ins>' . $this->icon(false) . '</ins>';
        } else if ($this->item["_rtype"]) {
            $t .= ' ' . $this->icon(false);
        }
        if ($this->item->differs("_round")) {
            if (($round = $this->item->get(true, "_round")))
                $t .= ' <del><span class="revround" title="Review round">' . htmlspecialchars($round) . '</span></del>';
            if (($round = $this->item->get(false, "_round")))
                $t .= ' <ins><span class="revround" title="Review round">' . htmlspecialchars($round) . '</span></ins>';
        } else if (($round = $this->item["_round"])) {
            $t .= ' <span class="revround" title="Review round">' . htmlspecialchars($round) . '</span>';
        }
        if (!$this->item->existed() && self::$prefinfo
            && ($cpref = get(self::$prefinfo, $this->cid))
            && ($pref = get($cpref, $this->pid))) {
            $t .= unparse_preference_span($pref);
        }
        return $t;
    }
    function unparse_csv(AssignmentSet $aset, AssignmentCsv $acsv) {
        $x = ["pid" => $this->pid, "action" => ReviewInfo::unparse_assigner_action($this->rtype),
              "email" => $this->contact->email, "name" => $this->contact->name()];
        if (($round = $this->item["_round"]))
            $x["round"] = $this->item["_round"];
        if ($this->token)
            $x["review_token"] = encode_token($this->token);
        $acsv->add($x);
        if ($this->unsubmit)
            $acsv->add(["action" => "unsubmitreview", "pid" => $this->pid,
                        "email" => $this->contact->email, "name" => $this->contact->name()]);
    }
    function account(AssignmentSet $aset, AssignmentCountSet $deltarev) {
        $aset->show_column("reviewers");
        if ($this->cid > 0) {
            $deltarev->rev = true;
            $ct = $deltarev->ensure($this->cid);
            ++$ct->ass;
            $oldtype = $this->item->get(true, "_rtype") ? : 0;
            $ct->rev += ($this->rtype != 0) - ($oldtype != 0);
            $ct->meta += ($this->rtype == REVIEW_META) - ($oldtype == REVIEW_META);
            $ct->pri += ($this->rtype == REVIEW_PRIMARY) - ($oldtype == REVIEW_PRIMARY);
            $ct->sec += ($this->rtype == REVIEW_SECONDARY) - ($oldtype == REVIEW_SECONDARY);
        }
    }
    function add_locks(AssignmentSet $aset, &$locks) {
        $locks["PaperReview"] = $locks["PaperReviewRefused"] = $locks["Settings"] = "write";
    }
    function execute(AssignmentSet $aset) {
        $extra = ["no_autosearch" => true];
        $round = $this->item->get(false, "_round");
        if ($round !== null && $this->rtype)
            $extra["round_number"] = (int) $aset->conf->round_number($round, true);
        if ($this->contact->is_anonymous_user()
            && (!$this->item->existed() || $this->item->deleted())) {
            $extra["token"] = true;
            $aset->cleanup_callback("rev_token", function ($aset, $vals) {
                $aset->conf->update_rev_tokens_setting(min($vals));
            }, $this->item->existed() ? 0 : 1);
        }
        $reviewId = $aset->user->assign_review($this->pid, $this->cid, $this->rtype, $extra);
        if ($this->unsubmit && $reviewId)
            $aset->user->unsubmit_review_row((object) ["paperId" => $this->pid, "contactId" => $this->cid, "reviewType" => $this->rtype, "reviewId" => $reviewId], ["no_autosearch" => true]);
        if (get($extra, "token") && $reviewId)
            $this->token = $aset->conf->fetch_ivalue("select reviewToken from PaperReview where paperId=? and reviewId=?", $this->pid, $reviewId);
    }
    function cleanup(AssignmentSet $aset) {
        if ($this->notify) {
            $reviewer = $aset->conf->user_by_id($this->cid);
            $prow = $aset->conf->fetch_paper($this->pid, $reviewer);
            HotCRPMailer::send_to($reviewer, $this->notify, $prow, [
                "requester_contact" => $aset->user,
                "reason" => $this->item["_reason"],
                "rrow" => $prow->fresh_review_of_user($this->cid)
            ]);
        }
    }
}
