<?php
// a_conflict.php -- HotCRP assignment helper classes
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class Conflict_AssignmentParser extends AssignmentParser {
    private $remove;
    private $iscontact;
    function __construct(Conf $conf, $aj) {
        parent::__construct("conflict");
        $this->remove = $aj->remove;
        $this->iscontact = $aj->iscontact;
    }
    static function load_conflict_state(AssignmentState $state) {
        if ($state->mark_type("conflict", ["pid", "cid"], "Conflict_Assigner::make")) {
            $result = $state->conf->qe("select paperId, contactId, conflictType from PaperConflict where conflictType!=0 and paperId?a", $state->paper_ids());
            while (($row = $result->fetch_row())) {
                $state->load(["type" => "conflict", "pid" => +$row[0], "cid" => +$row[1], "_ctype" => +$row[2]]);
            }
            Dbl::free($result);
        }
    }
    function load_state(AssignmentState $state) {
        self::load_conflict_state($state);
    }
    function allow_paper(PaperInfo $prow, AssignmentState $state) {
        if (!$state->user->can_administer($prow)
            && !$state->user->privChair
            && !$state->user->act_author($prow)) {
            return "You can’t administer #{$prow->paperId}.";
        } else if (!$this->iscontact
                   && !$state->user->can_administer($prow)
                   && ($whyNot = $state->user->perm_update_paper($prow))) {
            return whyNotText($whyNot);
        } else {
            return true;
        }
    }
    /** @return ?CountMatcher */
    private function _matcher($req, Conf $conf) {
        if ($this->remove) {
            $min = $this->iscontact ? CONFLICT_CONTACTAUTHOR : CONFLICT_MAXUNCONFLICTED + 1;
            return new CountMatcher(">=$min");
        } else if (!$this->iscontact
                   && ($pos = strpos((string) $req["conflict"], ":")) !== false) {
            $x = strtolower(substr($req["conflict"], 0, $pos));
            if (in_array($x, ["", "any", "all", "y", "yes", "conflict", "conflicted"])) {
                return new CountMatcher(">" . CONFLICT_MAXUNCONFLICTED);
            } else if (($ct = $conf->conflict_types()->parse_assignment($x, 0)) !== false) {
                return new CountMatcher("=" . $ct);
            } else {
                return null;
            }
        } else {
            return null;
        }
    }
    function expand_any_user(PaperInfo $prow, $req, AssignmentState $state) {
        $matcher = $this->_matcher($req, $state->conf);
        if ($matcher && !$matcher->test(0)) {
            $m = $state->query(["type" => "conflict", "pid" => $prow->paperId]);
            $cids = array_map(function ($x) { return $x["cid"]; }, $m);
            return $state->users_by_id($cids);
        } else {
            return false;
        }
    }
    function allow_user(PaperInfo $prow, Contact $contact, $req, AssignmentState $state) {
        return $contact->contactId != 0;
    }
    function apply(PaperInfo $prow, Contact $contact, $req, AssignmentState $state) {
        $res = $state->remove(["type" => "conflict", "pid" => $prow->paperId, "cid" => $contact->contactId]);
        $old_ct = empty($res) ? 0 : $res[0]["_ctype"];
        $admin = $state->user->can_administer($prow);
        if ($this->remove) {
            $ct = 0;
        } else if ($this->iscontact) {
            $ct = CONFLICT_CONTACTAUTHOR;
        } else {
            $text = (string) $req["conflict"];
            if (($colon = strpos($text, ":")) !== false) {
                $text = substr($text, $colon + 1);
            }
            $old_ct_na = Conflict::nonauthor_part($old_ct);
            if ($text === "") {
                if ($old_ct_na <= CONFLICT_MAXUNCONFLICTED) {
                    $ct = Conflict::set_pinned(Conflict::GENERAL, $admin);
                } else {
                    $ct = $old_ct_na;
                }
            } else {
                $ct = $state->conf->conflict_types()->parse_assignment($text, $old_ct_na);
            }
            if ($ct === false || Conflict::is_author($ct)) {
                return "Bad conflict type “{$text}”.";
            }
            if (!$admin) {
                $ct = Conflict::set_pinned($ct, false);
            }
        }
        $mask = $this->iscontact ? CONFLICT_CONTACTAUTHOR : CONFLICT_AUTHOR - 1;
        $matcher = $this->_matcher($req, $state->conf);
        if (($matcher && !$matcher->test($old_ct & $mask))
            || (!$this->iscontact && Conflict::is_pinned($old_ct) && !$admin)) {
            $new_ct = $old_ct;
        } else {
            $new_ct = ($old_ct & ~$mask) | $ct;
        }
        if ($new_ct !== 0) {
            $state->add(["type" => "conflict", "pid" => $prow->paperId, "cid" => $contact->contactId, "_ctype" => $new_ct]);
        }
        return true;
    }
}

class Conflict_Assigner extends Assigner {
    private $ctype;
    function __construct(AssignmentItem $item, AssignmentState $state) {
        parent::__construct($item, $state);
        $this->ctype = $item->post("_ctype") ?? 0;
    }
    static function make(AssignmentItem $item, AssignmentState $state) {
        // cannot change CONFLICT_AUTHOR through assignment
        assert(!((($item->pre("ctype") ?? 0) ^ ($item->post("ctype") ?? 0)) & CONFLICT_AUTHOR));
        if ($item->pre("_ctype") >= CONFLICT_CONTACTAUTHOR
            && $item->post("_ctype") < CONFLICT_CONTACTAUTHOR) {
            $ncontacts = 0;
            foreach ($state->query(["type" => "conflict", "pid" => $item["pid"]]) as $m) {
                if ($m["_ctype"] >= CONFLICT_CONTACTAUTHOR)
                    ++$ncontacts;
            }
            if ($ncontacts === 0) {
                throw new Exception("Each submission must have at least one contact.");
            }
        }
        return new Conflict_Assigner($item, $state);
    }
    static function check_unconflicted($item, AssignmentState $state) {
        $pid = $item["pid"];
        $cid = isset($item["cid"]) ? $item["cid"] : $item["_cid"];
        $cflt = $state->query(["type" => "conflict", "pid" => $pid, "cid" => $cid]);
        if ($cflt && Conflict::is_conflicted($cflt[0]["_ctype"])) {
            $uname = $state->user_by_id($cid)->name_h(NAME_E);
            if (isset($item["_override"])
                && $state->user->can_administer($state->prow($pid))) {
                $state->warning("Overriding {$uname} conflict with #{$pid}.");
            } else if (($state->flags & AssignmentState::FLAG_CSV_CONTEXT) !== 0
                       && $state->user->allow_administer($state->prow($pid))) {
                throw new Exception("{$uname} has a conflict with #{$pid}. Set an “override” column to “yes” to assign the " . $item["type"] . " anyway.");
            } else {
                throw new Exception("{$uname} has a conflict with #{$pid}.");
            }
        }
    }

    function unparse_description() {
        return "conflict";
    }
    private function icon($before) {
        $ctype = $this->item->get($before, "_ctype") ?? 0;
        if (Conflict::is_author($ctype)) {
            return review_type_icon(-2);
        } else if (Conflict::is_conflicted($ctype)) {
            return review_type_icon(-1);
        } else {
            return "";
        }
    }
    function unparse_display(AssignmentSet $aset) {
        $t = $aset->user->reviewer_html_for($this->contact);
        if ($this->item->deleted()) {
            $t = '<del>' . $t . ' ' . $this->icon(true) . '</del>';
        } else if (!$this->item->existed()) {
            $t = '<ins>' . $t . ' ' . $this->icon(false) . '</ins>';
        } else {
            $t = $t . ' <del>' . $this->icon(true) . '</del> <ins>' . $this->icon(false) . '</ins>';
        }
        return $t;
    }
    function unparse_csv(AssignmentSet $aset, AssignmentCsv $acsv) {
        $old_ct = $this->item->pre("_ctype") ?? 0;
        if (($old_ct ^ $this->ctype) & (CONFLICT_AUTHOR - 1)) {
            $acsv->add([
                "pid" => $this->pid,
                "action" => "conflict",
                "email" => $this->contact->email,
                "name" => $this->contact->name(),
                "conflict" => $aset->conf->conflict_types()->unparse_assignment($this->ctype & (CONFLICT_AUTHOR - 1))
            ]);
        }
        if (($old_ct ^ $this->ctype) & CONFLICT_CONTACTAUTHOR) {
            $acsv->add([
                "pid" => $this->pid,
                "action" => $this->ctype & CONFLICT_CONTACTAUTHOR ? "clearcontact" : "contact",
                "email" => $this->contact->email,
                "name" => $this->contact->name()
            ]);
        }
    }
    function account(AssignmentSet $aset, AssignmentCountSet $deltarev) {
        $aset->show_column("pcconflicts");
    }
    function add_locks(AssignmentSet $aset, &$locks) {
        $locks["PaperConflict"] = "write";
    }
    function execute(AssignmentSet $aset) {
        if ($this->ctype) {
            $aset->stage_qe("insert into PaperConflict set paperId=?, contactId=?, conflictType=? on duplicate key update conflictType=values(conflictType)", $this->pid, $this->cid, $this->ctype);
        } else {
            $aset->stage_qe("delete from PaperConflict where paperId=? and contactId=?", $this->pid, $this->cid);
        }
    }
}
