<?php
// listaction.php -- HotCRP helper class for paper search actions
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class ListAction {
    public $subname;
    const ENOENT = "No such action.";
    const EPERM = "Permission error.";
    function allow(Contact $user, Qrequest $qreq) {
        return true;
    }
    /** @param SearchSelection $ssel */
    function run(Contact $user, $qreq, $ssel) {
        return "Unsupported.";
    }

    /** @param string $name
     * @param SearchSelection|array<int> $selection */
    static private function do_call($name, Contact $user, Qrequest $qreq, $selection) {
        if ($qreq->method() !== "GET"
            && $qreq->method() !== "HEAD"
            && !$qreq->post_ok()) {
            return new JsonResult(403, "Missing credentials.");
        }
        $uf = $user->conf->list_action($name, $user, $qreq->method());
        if (!$uf) {
            if ($user->conf->has_list_action($name, $user, null)) {
                return new JsonResult(405, "Method not supported.");
            } else if ($user->conf->has_list_action($name, null, $qreq->method())) {
                return new JsonResult(403, "Permission error.");
            } else {
                return new JsonResult(404, "Function not found.");
            }
        }
        if (is_array($selection)) {
            $selection = new SearchSelection($selection);
        }
        if (($uf->paper ?? false) && $selection->is_empty()) {
            return new JsonResult(400, "No papers selected.");
        }
        if (!is_string($uf->callback)) {
            return new JsonResult(400, "Function not found.");
        } else if ($uf->callback[0] === "+") {
            $class = substr($uf->callback, 1);
            /** @phan-suppress-next-line PhanTypeExpectedObjectOrClassName */
            $action = new $class($user->conf, $uf);
        } else {
            $action = call_user_func($uf->callback, $user->conf, $uf);
        }
        if (!$action || !$action->allow($user, $qreq)) {
            return new JsonResult(403, "Permission error.");
        } else {
            return $action->run($user, $qreq, $selection);
        }
    }

    /** @param string $name
     * @param SearchSelection|array<int> $selection */
    static function call($name, Contact $user, Qrequest $qreq, $selection) {
        $res = self::do_call($name, $user, $qreq, $selection);
        if (is_string($res)) {
            $res = new JsonResult(400, ["ok" => false, "error" => $res]);
        }
        if ($res instanceof JsonResult) {
            if ($res->status >= 300 && !$qreq->ajax) {
                Conf::msg_error($res->content["error"]);
            } else {
                json_exit($res);
            }
        } else if ($res instanceof CsvGenerator) {
            csv_exit($res);
        }
    }


    /** @param list<int> $pids
     * @return array{list<string>,list<array{paper?:int,action?:string,title?:string,email?:string,round?:string,review_token?:string}>} */
    static function pcassignments_csv_data(Contact $user, $pids) {
        require_once("assignmentset.php");
        $pcm = $user->conf->pc_members();
        $token_users = [];

        $round_list = $user->conf->round_list();
        $any_round = $any_token = false;

        $texts = [];
        foreach ($user->paper_set(["paperId" => $pids, "reviewSignatures" => true]) as $prow) {
            if (!$user->allow_administer($prow)) {
                $texts[] = [];
                $texts[] = ["paper" => $prow->paperId,
                            "action" => "none",
                            "title" => "You cannot override your conflict with this paper"];
            } else {
                $any_this_paper = false;
                foreach ($prow->reviews_by_display($user) as $rrow) {
                    $cid = $rrow->contactId;
                    if ($rrow->reviewToken) {
                        if (!array_key_exists($cid, $token_users)) {
                            $token_users[$cid] = $user->conf->user_by_id($cid);
                        }
                        $u = $token_users[$cid];
                    } else if ($rrow->reviewType >= REVIEW_PC) {
                        $u = $pcm[$cid] ?? null;
                    } else {
                        $u = null;
                    }
                    if (!$u) {
                        continue;
                    }

                    if (!$any_this_paper) {
                        $texts[] = [];
                        $texts[] = ["paper" => $prow->paperId,
                                    "action" => "clearreview",
                                    "email" => "#pc",
                                    "round" => "any",
                                    "title" => $prow->title];
                        $any_this_paper = true;
                    }

                    $round = $rrow->reviewRound;
                    $d = ["paper" => $prow->paperId,
                          "action" => ReviewInfo::unparse_assigner_action($rrow->reviewType),
                          "email" => $u->email,
                          "round" => $round ? $round_list[$round] : "none"];
                    if ($rrow->reviewToken) {
                        $d["review_token"] = $any_token = encode_token((int) $rrow->reviewToken);
                    }
                    $texts[] = $d;
                    $any_round = $any_round || $round != 0;
                }
            }
        }

        $header = ["paper", "action", "email"];
        if ($any_round) {
            $header[] = "round";
        }
        if ($any_token) {
            $header[] = "review_token";
        }
        $header[] = "title";
        return [$header, $texts];
    }
}
