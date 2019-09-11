<?php
// api_preference.php -- HotCRP preference API call
// Copyright (c) 2006-2019 Eddie Kohler; see LICENSE.

class Preference_API {
    static function pref_api(Contact $user, $qreq, $prow) {
        $overrides = $user->add_overrides(Contact::OVERRIDE_CONFLICT);
        $u = PaperAPI::get_reviewer($user, $qreq, $prow);
        $user->set_overrides($overrides);

        // PC members may enter preferences for withdrawn papers,
        // so we must special-case the paper check
        if (!$prow) {
            $whynot = $qreq->annex("paper_whynot");
            if (!isset($whynot["withdrawn"])
                || !($prow = $user->conf->fetch_paper(intval($qreq->p), $user)))
                return Conf::paper_error_json_result($whynot);
        }
        if (!$u->can_enter_preference($prow))
            return new JsonResult(403, "Can’t enter preference for #{$prow->paperId}.");

        if ($qreq->method() === "POST" || isset($qreq->pref)) {
            $aset = new AssignmentSet($user);
            $aset->set_overrides(true);
            $aset->enable_papers($prow);
            $aset->parse("paper,user,preference\n{$prow->paperId}," . CsvGenerator::quote($u->email) . "," . CsvGenerator::quote($qreq->pref, true));
            if (!$aset->execute())
                return $aset->json_result();
            $prow->load_reviewer_preferences();
        }

        $pref = $prow->reviewer_preference($u, true);
        $value = unparse_preference($pref[0], $pref[1]);
        $jr = new JsonResult(["ok" => true, "value" => $value === "0" ? "" : $value, "pref" => $pref[0]]);
        if ($pref[1] !== null)
            $jr->content["prefexp"] = unparse_expertise($pref[1]);
        if ($user->conf->has_topics())
            $jr->content["topic_score"] = $pref[2];
        if ($qreq->method() === "POST" && $prow->timeWithdrawn > 0)
            $jr->content["warning"] = whyNotText($prow->make_whynot(["withdrawn" => 1]));
        return $jr;
    }
}
