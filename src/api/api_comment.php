<?php
// api_comment.php -- HotCRP comment API call
// Copyright (c) 2008-2020 Eddie Kohler; see LICENSE.

class Comment_API {
    /** @return ?CommentInfo */
    static private function find_comment($query, PaperInfo $prow) {
        $cmts = $prow->fetch_comments($query);
        reset($cmts);
        return empty($cmts) ? null : current($cmts);
    }
    /** @return ?CommentInfo */
    static private function find_response($round, PaperInfo $prow) {
        return $round === false ? null : self::find_comment("(commentType&" . COMMENTTYPE_RESPONSE . ")!=0 and commentRound=" . (int) $round, $prow);
    }
    static private function save_success_message(CommentInfo $xcrow) {
        $what = $xcrow->commentId ? "saved" : "deleted";
        if (!$xcrow->is_response()) {
            return Ht::msg("Comment $what.", "confirm");
        } else {
            $rname = $xcrow->conf->resp_round_text($xcrow->commentRound);
            $rname = $rname ? "$rname response" : "Response";
            if ($xcrow->commentId && !($xcrow->commentType & COMMENTTYPE_DRAFT)) {
                return Ht::msg("$rname submitted.", "confirm");
            } else {
                return Ht::msg("$rname $what.", "confirm");
            }
        }
    }
    /** @param ?CommentInfo $crow */
    static function run_post(Contact $user, Qrequest $qreq, PaperInfo $prow, $crow) {
        // check response
        $round = false;
        if ($qreq->response) {
            $round = $prow->conf->resp_round_number($qreq->response);
            if ($round === false) {
                return [null, 404, "No such response round."];
            } else if ($crow && (!$crow->is_response() || $crow->commentRound != $round)) {
                return [null, 400, "Improper response."];
            }
        } else if ($crow && $crow->is_response()) {
            return [null, 400, "Improper response."];
        }

        // create skeleton
        if ($crow) {
            $xcrow = $crow;
        } else if ($round === false) {
            $xcrow = new CommentInfo(null, $prow);
        } else {
            $xcrow = CommentInfo::make_response_template($round, $prow);
        }

        // request skeleton
        $ok = true;
        $msg = false;
        $response = $xcrow->is_response();
        $req = [
            "visibility" => $qreq->visibility,
            "submit" => $response && !$qreq->draft,
            "text" => rtrim(cleannl((string) $qreq->text)),
            "blind" => $qreq->blind,
            "docs" => $crow ? $crow->attachments() : []
        ];

        // check if response changed
        $changed = true;
        if ($response
            && $req["text"] === rtrim(cleannl((string) ($xcrow->commentOverflow ? : $xcrow->comment)))) {
            $changed = false;
        }

        // tags
        if (!$response) {
            $req["tags"] = $qreq->tags;
        }

        // attachments in request
        for ($i = count($req["docs"]) - 1; $i >= 0; --$i) {
            if ($qreq["remove_cmtdoc_{$req["docs"][$i]->paperStorageId}_{$i}"]) {
                array_splice($req["docs"], $i, 1);
                $changed = true;
            }
        }
        for ($i = 1; $qreq["has_cmtdoc_new_$i"] && count($req["docs"]) < 1000; ++$i) {
            if (($doc = DocumentInfo::make_request($qreq, "cmtdoc_new_$i", $prow->paperId, DTYPE_COMMENT, $prow->conf))) {
                if ($doc->save()) {
                    $req["docs"][] = $doc;
                    $changed = true;
                } else {
                    $msg = Ht::msg("Error uploading attachment.", 2);
                    $ok = false;
                    break;
                }
            }
        }

        // empty
        if ($ok
            && $req["text"] === ""
            && empty($req["docs"])) {
            if (!$qreq->delete && (!$xcrow->commentId || !isset($qreq->text))) {
                $msg = Ht::msg("Empty comment.", 2);
                $ok = false;
            } else {
                $qreq->delete = true;
                $changed = true;
            }
        }

        // check permission, other errors
        $submit_value = $response && !$changed ? 2 : true;
        if (($whyNot = $user->perm_comment($prow, $xcrow, $submit_value))) {
            return [null, 403, whyNotText($whyNot)];
            // null, new JsonResult(403, ["ok" => false, "msg" => whyNotText($whyNot)]);
        }

        // save
        if ($ok) {
            // check for review token
            $suser = $user;
            if (($token = $qreq->review_token)
                && ($token = decode_token($token, "V"))
                && in_array($token, $user->review_tokens())
                && ($rrow = $prow->review_of_token($token))) {
                $suser = $prow->conf->user_by_id($rrow->contactId);
            }

            // check for delete
            if ($qreq->delete) {
                $req["text"] = false;
                $req["docs"] = [];
            }

            // save
            $ok = $xcrow->save($req, $suser);

            // check for response simultaneity
            if (!$ok
                && $xcrow->is_response()
                && ($ocrow = self::find_response((int) $xcrow->commentRound, $prow))) {
                if ($ocrow->comment === $req["text"]
                    && $ocrow->attachment_ids() == $xcrow->attachment_ids()) {
                    $xcrow = $ocrow;
                    $ok = true;
                } else {
                    $msg = Ht::msg("A response was entered concurrently by another user. Reload to see it.", 2);
                }
            }

            // generate save response
            if ($ok) {
                $msg = self::save_success_message($xcrow);
            }
        }

        return [$xcrow, $ok, $msg];
    }

    /** @return array{?CommentInfo,string} */
    static private function lookup(Qrequest $qreq, PaperInfo $prow) {
        if (ctype_digit($qreq->c)) {
            $crow = self::find_comment("commentId=" . intval($qreq->c), $prow);
            return [$crow, "No such comment."];
        } else if (str_ends_with($qreq->c, "response")) {
            $rname = substr($qreq->c, 0, -8);
        } else if (str_starts_with($qreq->c, "response")) {
            $rname = substr($qreq->c, 8);
        } else {
            return [null, "No such comment."];
        }
        $round = $prow->conf->resp_round_number($rname);
        return [self::find_response($round, $prow), "No such response."];
    }

    static function run(Contact $user, Qrequest $qreq, PaperInfo $prow) {
        // check parameters
        if ((!isset($qreq->text) && !isset($qreq->delete) && $qreq->is_post())
            || ($qreq->c === "new" && !$qreq->is_get())) {
            return new JsonResult(400, "Bad request.");
        }

        // find comment
        $crow = $msg = $response_name = null;
        if (!$qreq->c && $qreq->response && $qreq->is_get()) {
            $qreq->c = ($qreq->response === "1" ? "" : $qreq->response) . "response";
        }
        if ($qreq->c && $qreq->c !== "new") {
            list($crow, $msg) = self::lookup($qreq, $prow);
            if (!$crow) {
                return new JsonResult(404, $msg);
            }
        }

        if ($qreq->is_post()) {
            list($crow, $status, $msg) = self::run_post($user, $qreq, $prow, $crow);
        } else {
            $status = 200;
        }

        if (is_bool($status)) {
            $status = $status ? 200 : 400;
        }
        $j = ["ok" => $status <= 299];
        if ($crow && $crow->commentId) {
            $j["cmt"] = $crow->unparse_json($user);
        }
        if ($msg) {
            $j["msg"] = $msg;
        }
        return new JsonResult($status, $j);
    }
}
