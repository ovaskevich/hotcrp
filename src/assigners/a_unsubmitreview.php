<?php
// a_unsubmitreview.php -- HotCRP assignment helper classes
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class UnsubmitReview_AssignmentParser extends AssignmentParser {
    function __construct() {
        parent::__construct("unsubmitreview");
    }
    function load_state(AssignmentState $state) {
        Review_AssignmentParser::load_review_state($state);
    }
    function user_universe($req, AssignmentState $state) {
        return "reviewers";
    }
    function paper_filter($contact, $req, AssignmentState $state) {
        return $state->make_filter("pid", ["type" => "review", "cid" => $contact->contactId, "_rnondraft" => 1]);
    }
    function expand_any_user(PaperInfo $prow, $req, AssignmentState $state) {
        $cf = $state->make_filter("cid", ["type" => "review", "pid" => $prow->paperId, "_rnondraft" => 1]);
        return $state->users_by_id(array_keys($cf));
    }
    function expand_missing_user(PaperInfo $prow, $req, AssignmentState $state) {
        return $this->expand_any_user($prow, $req, $state);
    }
    function allow_user(PaperInfo $prow, Contact $contact, $req, AssignmentState $state) {
        return $contact->contactId != 0;
    }
    function apply(PaperInfo $prow, Contact $contact, $req, AssignmentState $state) {
        // parse round and reviewtype arguments
        $rarg0 = trim((string) $req["round"]);
        $oldround = null;
        if ($rarg0 !== ""
            && strcasecmp($rarg0, "any") != 0
            && ($oldround = $state->conf->sanitize_round_name($rarg0)) === false)
            return Conf::round_name_error($rarg0);
        $targ0 = trim((string) $req["reviewtype"]);
        $oldtype = null;
        if ($targ0 !== ""
            && ($oldtype = ReviewInfo::parse_type($targ0)) === false)
            return "Invalid review type.";

        // remove existing review
        $revmatch = ["type" => "review", "pid" => $prow->paperId,
                     "cid" => $contact->contactId,
                     "_rtype" => $oldtype, "_round" => $oldround, "_rnondraft" => 1];
        $matches = $state->remove($revmatch);
        foreach ($matches as $r) {
            $r["_rsubmitted"] = $r["_rnondraft"] = 0;
            $state->add($r);
        }
        return true;
    }
}
