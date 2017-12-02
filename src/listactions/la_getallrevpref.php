<?php
// listactions/la_getallrevpref.php -- HotCRP helper classes for list actions
// HotCRP is Copyright (c) 2006-2017 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

class GetAllRevpref_ListAction extends ListAction {
    function allow(Contact $user) {
        return $user->is_manager();
    }
    function run(Contact $user, $qreq, $ssel) {
        $result = $user->paper_result(["paperId" => $ssel->selection(), "allReviewerPreference" => 1, "allConflictType" => 1, "topics" => 1]);
        $texts = array();
        $pcm = $user->conf->pc_members();
        $has_conflict = $has_expertise = $has_topic_score = false;
        foreach (PaperInfo::fetch_all($result, $user) as $prow) {
            if (!$user->allow_administer($prow))
                continue;
            $conflicts = $prow->conflicts();
            foreach ($pcm as $cid => $p) {
                $pref = $prow->reviewer_preference($p);
                $cflt = get($conflicts, $cid);
                $tv = $prow->topicIds ? $prow->topic_interest_score($p) : 0;
                if ($pref[0] !== 0 || $pref[1] !== null || $cflt || $tv) {
                    $texts[$prow->paperId][] = array("paper" => $prow->paperId, "title" => $prow->title, "first" => $p->firstName, "last" => $p->lastName, "email" => $p->email,
                                "preference" => $pref[0] ? : "",
                                "expertise" => unparse_expertise($pref[1]),
                                "topic_score" => $tv ? : "",
                                "conflict" => ($cflt ? "conflict" : ""));
                    $has_conflict = $has_conflict || $cflt;
                    $has_expertise = $has_expertise || $pref[1] !== null;
                    $has_topic_score = $has_topic_score || $tv;
                }
            }
        }

        $headers = array("paper", "title", "first", "last", "email", "preference");
        if ($has_expertise)
            $headers[] = "expertise";
        if ($has_topic_score)
            $headers[] = "topic_score";
        if ($has_conflict)
            $headers[] = "conflict";
        return new Csv_SearchResult("allprefs", $headers, $ssel->reorder($texts), true);
    }
}
