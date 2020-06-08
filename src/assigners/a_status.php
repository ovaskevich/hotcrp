<?php
// a_status.php -- HotCRP assignment helper classes
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class Withdraw_AssignmentFinisher {
    // When withdrawing a paper, remove voting tags so people don't have
    // phantom votes.
    private $pid;
    private $ltag;
    function __construct($pid) {
        $this->pid = $pid;
    }
    function apply_finisher(AssignmentState $state) {
        $res = $state->query_items(["type" => "status", "pid" => $this->pid]);
        if (!$res
            || $res[0]["_withdrawn"] <= 0
            || $res[0]->pre("_withdrawn") > 0)
            return;
        $ltre = [];
        foreach ($state->conf->tags()->filter("votish") as $dt)
            $ltre[] = preg_quote(strtolower($dt->tag));
        $res = $state->query(["type" => "tag", "pid" => $this->pid]);
        $tag_re = '{\A(?:\d+~|)(?:' . join("|", $ltre) . ')\z}i';
        foreach ($res as $x) {
            if (preg_match($tag_re, $x["ltag"])) {
                $x["_index"] = 0.0;
                $x["_vote"] = true;
                $state->add($x);
            }
        }
    }
}

class Status_AssignmentParser extends UserlessAssignmentParser {
    private $xtype;
    function __construct(Conf $conf, $aj) {
        parent::__construct("status");
        $this->xtype = $aj->type;
    }
    function allow_paper(PaperInfo $prow, AssignmentState $state) {
        if (!$state->user->can_administer($prow)
            && !$state->user->act_author($prow))
            return "You can’t administer #{$prow->paperId}.";
        else
            return true;
    }
    static function load_status_state(AssignmentState $state) {
        if ($state->mark_type("status", ["pid"], "Status_Assigner::make")) {
            foreach ($state->prows() as $prow)
                $state->load(["type" => "status", "pid" => $prow->paperId,
                              "_submitted" => (int) $prow->timeSubmitted,
                              "_withdrawn" => (int) $prow->timeWithdrawn,
                              "_withdraw_reason" => $prow->withdrawReason]);
        }
    }
    function load_state(AssignmentState $state) {
        Decision_AssignmentParser::load_decision_state($state);
        Status_AssignmentParser::load_status_state($state);
    }
    function apply(PaperInfo $prow, Contact $contact, $req, AssignmentState $state) {
        global $Now;
        $m = $state->remove(["type" => "status", "pid" => $prow->paperId]);
        $res = $m[0];
        $ch = false;
        if ($this->xtype === "submit") {
            if ($res["_submitted"] === 0) {
                if (($whynot = $state->user->perm_finalize_paper($prow)))
                    return whyNotText($whynot);
                $res["_submitted"] = ($res["_withdrawn"] > 0 ? -$Now : $Now);
            }
        } else if ($this->xtype === "unsubmit") {
            if ($res["_submitted"] !== 0) {
                if (($whynot = $state->user->perm_update_paper($prow)))
                    return whyNotText($whynot);
                $res["_submitted"] = 0;
            }
        } else if ($this->xtype === "withdraw") {
            if ($res["_withdrawn"] === 0) {
                assert($res["_submitted"] >= 0);
                if (($whynot = $state->user->perm_withdraw_paper($prow)))
                    return whyNotText($whynot);
                $res["_withdrawn"] = $Now;
                $res["_submitted"] = -$res["_submitted"];
                if ($state->conf->tags()->has_votish) {
                    Tag_AssignmentParser::load_tag_state($state);
                    $state->finishers[] = new Withdraw_AssignmentFinisher($prow->paperId);
                }
            }
            $r = $req["withdraw_reason"];
            if ((string) $r !== ""
                && $state->user->can_withdraw_paper($prow))
                $res["_withdraw_reason"] = $r;
        } else if ($this->xtype === "revive") {
            if ($res["_withdrawn"] !== 0) {
                assert($res["_submitted"] <= 0);
                if (($whynot = $state->user->perm_revive_paper($prow)))
                    return whyNotText($whynot);
                $res["_withdrawn"] = 0;
                if ($res["_submitted"] === -100)
                    $res["_submitted"] = $Now;
                else
                    $res["_submitted"] = -$res["_submitted"];
                $res["_withdraw_reason"] = null;
            }
        }
        $state->add($res);
        return true;
    }
}

class Status_Assigner extends Assigner {
    function __construct(AssignmentItem $item, AssignmentState $state) {
        parent::__construct($item, $state);
    }
    static function make(AssignmentItem $item, AssignmentState $state) {
        return new Status_Assigner($item, $state);
    }
    private function status_html($type) {
        if ($this->item->get($type, "_withdrawn")) {
            return "Withdrawn";
        } else if ($this->item->get($type, "_submitted")) {
            return "Submitted";
        } else {
            return "Not ready";
        }
    }
    function unparse_display(AssignmentSet $aset) {
        return '<del>' . $this->status_html(true) . '</del> '
            . '<ins>' . $this->status_html(false) . '</ins>';
    }
    function unparse_csv(AssignmentSet $aset, AssignmentCsv $acsv) {
        if (($this->item->pre("_submitted") === 0) !== ($this->item["_submitted"] === 0)) {
            $acsv->add(["pid" => $this->pid, "action" => $this->item["_submitted"] === 0 ? "unsubmit" : "submit"]);
        }
        if ($this->item->pre("_withdrawn") === 0 && $this->item["_withdrawn"] !== 0) {
            $acsv->add(["pid" => $this->pid, "action" => "revive"]);
        } else if ($this->item->pre("_withdrawn") !== 0 && $this->item["_withdrawn"] === 0) {
            $x = ["pid" => $this->pid, "action" => "withdraw"];
            if ((string) $this->item["_withdraw_reason"] !== "") {
                $x["withdraw_reason"] = $this->item["_withdraw_reason"];
            }
            $acsv->add($x);
        }
        return null;
    }
    function add_locks(AssignmentSet $aset, &$locks) {
        $locks["Paper"] = "write";
    }
    function execute(AssignmentSet $aset) {
        global $Now;
        $submitted = $this->item["_submitted"];
        $old_submitted = $this->item->pre("_submitted");
        $withdrawn = $this->item["_withdrawn"];
        $old_withdrawn = $this->item->pre("_withdrawn");
        $aset->stage_qe("update Paper set timeSubmitted=?, timeWithdrawn=?, withdrawReason=? where paperId=?", $submitted, $withdrawn, $this->item["_withdraw_reason"], $this->pid);
        if (($withdrawn > 0) !== ($old_withdrawn > 0)) {
            $aset->user->log_activity($withdrawn > 0 ? "Paper withdrawn" : "Paper revived", $this->pid);
        } else if (($submitted > 0) !== ($old_submitted > 0)) {
            $aset->user->log_activity($submitted > 0 ? "Paper submitted" : "Paper unsubmitted", $this->pid);
        }
        if (($submitted > 0) !== ($old_submitted > 0)) {
            $aset->cleanup_callback("papersub", function ($aset, $vals) {
                $aset->conf->update_papersub_setting(min($vals));
            }, $submitted > 0 ? 1 : 0);
            $aset->cleanup_callback("paperacc", function ($aset, $vals) {
                $aset->conf->update_paperacc_setting(min($vals));
            }, 0);
        }
    }
}
