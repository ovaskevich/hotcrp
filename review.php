<?php
// review.php -- HotCRP paper review display/edit page
// Copyright (c) 2006-2019 Eddie Kohler; see LICENSE.

require_once("src/initweb.php");
require_once("src/papertable.php");

$rf = $Conf->review_form();
$Me->add_overrides(Contact::OVERRIDE_CHECK_TIME);


// header
function confHeader() {
    global $paperTable, $Qreq;
    PaperTable::do_header($paperTable, "review", $Qreq->mode, $Qreq);
}

function errorMsgExit($msg) {
    global $Conf;
    confHeader();
    Ht::stash_script("shortcut().add()");
    $msg && Conf::msg_error($msg);
    Conf::$g->footer();
    exit;
}


// collect paper ID
function loadRows() {
    global $Conf, $Me, $Qreq, $prow, $paperTable;
    if (!($prow = PaperTable::fetch_paper_request($Qreq, $Me)))
        errorMsgExit(whyNotText($Qreq->annex("paper_whynot") + ["listViewable" => true]));
    $paperTable = new PaperTable($prow, $Qreq);
    $paperTable->resolveReview(true);
}

loadRows();


// general error messages
if ($Qreq->post && $Qreq->post_empty()) {
    $Conf->post_missing_msg();
} else if ($Qreq->post && $Qreq->default) {
    if ($Qreq->has_file("uploadedFile"))
        $Qreq->uploadForm = 1;
    else
        $Qreq->update = 1;
} else if (isset($Qreq->submitreview)) {
    $Qreq->update = $Qreq->ready = 1;
} else if (isset($Qreq->savedraft)) {
    $Qreq->update = 1;
    unset($Qreq->ready);
}


// upload review form action
if (isset($Qreq->uploadForm)
    && $Qreq->has_file("uploadedFile")
    && $Qreq->post_ok()) {
    // parse form, store reviews
    $tf = ReviewValues::make_text($rf, $Qreq->file_contents("uploadedFile"),
            $Qreq->file_filename("uploadedFile"));
    if ($tf->parse_text($Qreq->override))
        $tf->check_and_save($Me, $prow, $paperTable->editrrow);
    if (!$tf->has_error() && $tf->parse_text($Qreq->override))
        $tf->msg(null, 'Only the first review form in the file was parsed. <a href="' . hoturl("offline") . '">Upload multiple-review files here.</a>', MessageSet::WARNING);
    $tf->report();
    loadRows();
} else if (isset($Qreq->uploadForm))
    Conf::msg_error("Select a review form to upload.");


// check review submit requirements
if (isset($Qreq->unsubmitreview)
    && $paperTable->editrrow
    && ($paperTable->editrrow->reviewSubmitted || $paperTable->editrrow->timeApprovalRequested != 0)
    && $Me->can_administer($prow)
    && $Qreq->post_ok()) {
    $result = $Me->unsubmit_review_row($paperTable->editrrow);
    if ($result) {
        $Me->log_activity_for($paperTable->editrrow->contactId, "Unsubmitted review {$paperTable->editrrow->reviewId}", $prow);
        $Conf->confirmMsg("Unsubmitted review.");
    }
    $Conf->self_redirect($Qreq);             // normally does not return
    loadRows();
} else if (isset($Qreq->update)
           && $paperTable->editrrow
           && $paperTable->editrrow->reviewSubmitted)
    $Qreq->ready = 1;


// update review action
if (isset($Qreq->update) && $Qreq->post_ok()) {
    $tf = new ReviewValues($rf);
    $tf->paperId = $prow->paperId;
    if (($whyNot = $Me->perm_submit_review($prow, $paperTable->editrrow)))
        $tf->msg(null, whyNotText($whyNot), MessageSet::ERROR);
    else if ($tf->parse_web($Qreq, $Qreq->override)
             && $tf->check_and_save($Me, $prow, $paperTable->editrrow)
             && !$tf->has_problem_at("ready")) {
        $tf->report();
        $Conf->self_redirect($Qreq); // normally does not return
    }
    loadRows();
    $tf->report();
    $paperTable->set_review_values($tf);
} else if ($Qreq->has_annex("after_login")) {
    $tf = new ReviewValues($rf);
    $tf->parse_web($Qreq, $Qreq->override);
    $paperTable->set_review_values($tf);
}


// adopt review action
if (isset($Qreq->adoptreview) && $Qreq->post_ok()) {
    $tf = new ReviewValues($rf);
    $tf->paperId = $prow->paperId;
    $my_rrow = $prow->review_of_user($Me);
    if (($whyNot = $Me->perm_submit_review($prow, $my_rrow))) {
        $tf->msg(null, whyNotText($whyNot), MessageSet::ERROR);
    } else if ($tf->parse_web($Qreq, $Qreq->override)) {
        $tf->set_ready($Qreq->adoptsubmit);
        if ($tf->check_and_save($Me, $prow, $my_rrow)
            && !$tf->has_problem_at("ready")) {
            $tf->report();

            // mark the review as approved
            $tfx = new ReviewValues($rf);
            $tfx->set_adopt();
            $tfx->check_and_save($Me, $prow, $paperTable->editrrow);
        }
    }
    if (($my_rrow = $prow->fresh_review_of_user($Me)))
        $Qreq->r = $my_rrow->reviewId;
    $Conf->self_redirect($Qreq); // normally does not return
}


// delete review action
if (isset($Qreq->deletereview)
    && $Qreq->post_ok()
    && $Me->can_administer($prow)) {
    if (!$paperTable->editrrow)
        Conf::msg_error("No review to delete.");
    else {
        $result = $Conf->qe("delete from PaperReview where paperId=? and reviewId=?", $prow->paperId, $paperTable->editrrow->reviewId);
        if ($result) {
            $Me->log_activity_for($paperTable->editrrow->contactId, "Deleted review {$paperTable->editrrow->reviewId}", $prow);
            $Conf->confirmMsg("Deleted review.");
            $Conf->qe("delete from ReviewRating where paperId=? and reviewId=?", $prow->paperId, $paperTable->editrrow->reviewId);
            if ($paperTable->editrrow->reviewToken != 0)
                $Conf->update_rev_tokens_setting(-1);
            if ($paperTable->editrrow->reviewType == REVIEW_META)
                $Conf->update_metareviews_setting(-1);

            // perhaps a delegatee needs to redelegate
            if ($paperTable->editrrow->reviewType < REVIEW_SECONDARY && $paperTable->editrrow->requestedBy > 0)
                $Me->update_review_delegation($paperTable->editrrow->paperId, $paperTable->editrrow->requestedBy, -1);

            unset($Qreq->r, $Qreq->reviewId);
            $Qreq->paperId = $Qreq->p = $paperTable->editrrow->paperId;
            go(hoturl("paper", ["p" => $Qreq->paperId]));
        }
        $Conf->self_redirect($Qreq);         // normally does not return
        loadRows();
    }
}


// download review form action
function downloadForm($qreq) {
    global $rf, $Conf, $Me, $prow, $paperTable;
    $rrow = $paperTable->rrow;
    $use_request = (!$rrow || $rrow->contactId == $Me->contactId)
        && $prow->review_type($Me) > 0;
    $text = $rf->textFormHeader(false) . $rf->textForm($prow, $rrow, $Me, $use_request ? $qreq : null);
    $filename = "review-{$prow->paperId}";
    if ($rrow && $rrow->reviewOrdinal)
        $filename .= unparseReviewOrdinal($rrow->reviewOrdinal);
    downloadText($text, $filename, false);
}

if (isset($Qreq->downloadForm))
    downloadForm($Qreq);


function download_all_text_reviews() {
    global $rf, $Conf, $Me, $prow, $paperTable;
    $lastrc = null;
    $text = "";
    foreach ($prow->viewable_submitted_reviews_and_comments($Me) as $rc) {
        $text .= PaperInfo::review_or_comment_text_separator($lastrc, $rc);
        if (isset($rc->reviewId))
            $text .= $rf->pretty_text($prow, $rc, $Me, false, true);
        else
            $text .= $rc->unparse_text($Me, true);
        $lastrc = $rc;
    }
    if ($text === "") {
        $whyNot = $Me->perm_view_review($prow, null) ? : $prow->make_whynot();
        return Conf::msg_error(whyNotText($whyNot));
    }
    $text = $Conf->short_name . " Paper #{$prow->paperId} Reviews and Comments\n"
        . str_repeat("=", 75) . "\n"
        . prefix_word_wrap("", "Paper #{$prow->paperId} {$prow->title}", 0, 75)
        . "\n\n" . $text;
    downloadText($text, "reviews-{$prow->paperId}", true);
}

function download_one_text_review(ReviewInfo $rrow) {
    global $rf, $Conf, $Me, $prow, $paperTable;
    $filename = "review-{$prow->paperId}";
    if ($rrow->reviewOrdinal)
        $filename .= unparseReviewOrdinal($rrow->reviewOrdinal);
    downloadText($rf->pretty_text($prow, $rrow, $Me), $filename, true);
}

if (isset($Qreq->text)) {
    if ($paperTable->rrow)
        download_one_text_review($paperTable->rrow);
    else
        download_all_text_reviews();
}


// retract review request
if ((isset($Qreq->refuse) || isset($Qreq->decline))
    && ($Qreq->post_ok() || $Me->capability("@ra" . $prow->paperId))) {
    if ($paperTable->editrrow)
        $Qreq->email = $paperTable->editrrow->email;
    $result = RequestReview_API::declinereview($Me, $Qreq, $prow);
    $result = JsonResult::make($result);
    if ($result->content["ok"]) {
        if (($Qreq->refuse === "1" || $Qreq->decline === "1")
            && $paperTable->editrrow
            && !isset($Qreq->reason)) {
            $Conf->confirmMsg("<p>Thank you for telling us that you cannot complete your review. If you’d like, you may enter a brief explanation here.</p>"
                . Ht::form(hoturl_post("api/declinereview", ["p" => $prow->paperId, "email" => $Me->email, "redirect" => $Conf->hoturl("index")]))
                . Ht::textarea("reason", "", ["rows" => 3, "cols" => 40, "spellcheck" => true])
                . '<hr class="c">'
                . Ht::submit("Update explanation", ["class" => "btn-primary"])
                . '</form>');
        } else {
            $Conf->confirmMsg("Review declined. Thank you for telling us that you cannot complete your review.");
        }
        unset($Qreq->email, $Qreq->firstName, $Qreq->lastName, $Qreq->affiliation, $Qreq->round, $Qreq->reason, $Qreq->override, $Qreq->retract);
        $Conf->self_redirect($Qreq);
    } else {
        $result->export_errors();
        loadRows();
    }
}

if (isset($Qreq->accept)
    && ($Qreq->post_ok() || $Me->capability("@ra" . $prow->paperId))) {
    $rrow = $paperTable->editrrow;
    if (!$rrow
        || (!$Me->is_my_review($rrow) && !$Me->can_administer($prow))) {
        Conf::msg_error("This review was not assigned to you, so you cannot confirm your intention to write it.");
    } else {
        if ($rrow->reviewModified <= 0) {
            Dbl::qe("update PaperReview set reviewModified=1, timeRequestNotified=greatest(?,timeRequestNotified)
                where paperId=? and reviewId=? and coalesce(reviewModified,0)<=0",
                $Now, $prow->paperId, $rrow->reviewId);
            if ($Me->is_signed_in())
                $rrow->delete_acceptor();
            $Me->log_activity_for($rrow->contactId, "Accepted review {$rrow->reviewId}", $prow);
        }
        $Conf->confirmMsg("Thank you for confirming your intention to finish this review. You can download the paper and review form below.");
        $Conf->self_redirect($Qreq);
        loadRows();
    }
}


// can we view/edit reviews?
$viewAny = $Me->can_view_review($prow, null);
$editAny = $Me->can_review($prow, null);


// can we see any reviews?
if (!$viewAny && !$editAny) {
    if (($whyNotPaper = $Me->perm_view_paper($prow)))
        errorMsgExit(whyNotText($whyNotPaper + ["listViewable" => true]));
    if (isset($Qreq->reviewId)) {
        Conf::msg_error("You can’t see the reviews for this paper. "
                        . whyNotText($Me->perm_view_review($prow, null)));
        go(hoturl("paper", "p=$prow->paperId"));
    }
}


// mode
$paperTable->fixReviewMode();
if ($paperTable->mode == "edit")
    go(hoturl("paper", ["p" => $prow->paperId]));


// paper table
confHeader();

$paperTable->initialize(false, false);
$paperTable->paptabBegin();
$paperTable->resolveComments();

if (!$viewAny
    && !$editAny
    && (!$paperTable->rrow
        || !$Me->can_view_review($prow, $paperTable->rrow))) {
    $paperTable->paptabEndWithReviewMessage();
} else {
    if ($paperTable->mode === "re") {
        $paperTable->paptabEndWithEditableReview();
        $paperTable->paptabComments();
    } else {
        $paperTable->paptabEndWithReviewsAndComments();
    }
}

echo "</div>\n";
$Conf->footer();
