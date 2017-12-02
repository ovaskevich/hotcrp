<?php
// listactions/la_getjsonrqc.php -- HotCRP helper classes for list actions
// HotCRP is Copyright (c) 2006-2017 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

class GetJsonRQC_ListAction extends ListAction {
    function allow(Contact $user) {
        return $user->is_manager();
    }
    function run(Contact $user, $qreq, $ssel) {
        $result = $user->paper_result(["paperId" => $ssel->selection(), "topics" => true, "options" => true]);
        $results = ["hotcrp_version" => HOTCRP_VERSION];
        if (($git_data = Conf::git_status()))
            $results["hotcrp_commit"] = $git_data[0];
        $rf = $user->conf->review_form();
        $results["reviewform"] = $rf->unparse_json(0, VIEWSCORE_REVIEWERONLY);
        $pj = [];
        $ps = new PaperStatus($user->conf, $user, ["forceShow" => true, "hide_docids" => true]);
        foreach (PaperInfo::fetch_all($result, $user) as $prow)
            if ($user->allow_administer($prow)) {
                $pj[$prow->paperId] = $j = $ps->paper_json($prow);
                $prow->ensure_full_reviews();
                foreach ($prow->viewable_submitted_reviews_by_display($user, true) as $rrow)
                    $j->reviews[] = $rf->unparse_review_json($prow, $rrow, $user, true, ReviewForm::RJ_NO_EDITABLE | ReviewForm::RJ_UNPARSE_RATINGS | ReviewForm::RJ_ALL_RATINGS | ReviewForm::RJ_NO_REVIEWERONLY);
            } else
                $pj[$prow->paperId] = (object) ["pid" => $prow->paperId, "error" => "You don’t have permission to administer this paper."];
        $pj = array_values($ssel->reorder($pj));
        $results["papers"] = $pj;
        header("Content-Type: application/json");
        header("Content-Disposition: attachment; filename=" . mime_quote_string($user->conf->download_prefix . "rqc.json"));
        echo json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
        exit;
    }
}
