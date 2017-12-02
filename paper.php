<?php
// paper.php -- HotCRP paper view and edit page
// HotCRP is Copyright (c) 2006-2017 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

$ps = null;
require_once("src/initweb.php");
require_once("src/papertable.php");
if ($Me->is_empty())
    $Me->escape();
if (check_post() && !$Me->has_database_account()) {
    if (isset($_REQUEST["update"]) && $Me->can_start_paper())
        $Me = $Me->activate_database_account();
    else
        $Me->escape();
}
$useRequest = isset($_REQUEST["after_login"]) && isset($_REQUEST["title"]);
foreach (array("emailNote", "reason") as $x)
    if (isset($_REQUEST[$x]) && $_REQUEST[$x] == "Optional explanation")
        unset($_REQUEST[$x], $_GET[$x], $_POST[$x]);
if (!isset($_REQUEST["p"]) && !isset($_REQUEST["paperId"])
    && preg_match(',\A(?:new|\d+)\z,i', Navigation::path_component(0))) {
    $_REQUEST["p"] = $_GET["p"] = Navigation::path_component(0);
    if (!isset($_REQUEST["m"]) && ($x = Navigation::path_component(1)))
        $_REQUEST["m"] = $_GET["m"] = $x;
    if (isset($_REQUEST["m"]) && $_REQUEST["m"] === "api"
        && !isset($_REQUEST["fn"])
        && ($x = Navigation::path_component(2)))
        $_REQUEST["fn"] = $_GET["fn"] = $x;
} else if (!Navigation::path() && isset($_REQUEST["p"])
           && $_REQUEST["p"] && ctype_digit($_REQUEST["p"])
           && !check_post())
    go(selfHref());


// header
function confHeader() {
    global $paperTable;
    $mode = $paperTable ? $paperTable->mode : "p";
    PaperTable::do_header($paperTable, "paper_" . ($mode == "edit" ? "edit" : "view"), $mode);
}

function errorMsgExit($msg) {
    global $Conf;
    if (req("ajax")) {
        Conf::msg_error($msg);
        json_exit(["ok" => false]);
    } else {
        confHeader();
        Ht::stash_script("shortcut().add()");
        $msg && Conf::msg_error($msg);
        Conf::$g->footer();
        exit;
    }
}


// collect paper ID: either a number or "new"
$newPaper = (defval($_REQUEST, "p") == "new"
             || defval($_REQUEST, "paperId") == "new");


// general error messages
if (isset($_GET["post"]) && $_GET["post"] && !count($_POST))
    $Conf->post_missing_msg();


// grab paper row
function loadRows() {
    global $prow, $Conf;
    $Conf->paper = $prow = PaperTable::paperRow($whyNot);
    if (!$prow)
        errorMsgExit(whyNotText($whyNot, "view", true));
}
$prow = null;
if (!$newPaper)
    loadRows();


// paper actions
if ($prow && isset($_GET["m"]) && $_GET["m"] === "api"
    && isset($_GET["fn"]) && $Conf->has_api($_GET["fn"])) {
    $Qreq = make_qreq();
    $Conf->call_api_exit($Qreq->fn, $Me, $Qreq, $prow);
}


// withdraw and revive actions
if (isset($_REQUEST["withdraw"]) && !$newPaper && check_post()) {
    if (!($whyNot = $Me->perm_withdraw_paper($prow))) {
        $reason = defval($_REQUEST, "reason", "");
        if ($reason == "" && $Me->privChair && defval($_REQUEST, "doemail") > 0)
            $reason = defval($_REQUEST, "emailNote", "");
        Dbl::qe("update Paper set timeWithdrawn=$Now, timeSubmitted=if(timeSubmitted>0,-timeSubmitted,0), withdrawReason=? where paperId=$prow->paperId", $reason != "" ? $reason : null);
        $Conf->update_papersub_setting(-1);
        loadRows();

        // email contact authors themselves
        if (!$Me->privChair || defval($_REQUEST, "doemail") > 0)
            HotCRPMailer::send_contacts(($prow->conflictType >= CONFLICT_AUTHOR ? "@authorwithdraw" : "@adminwithdraw"),
                                        $prow, array("reason" => $reason, "infoNames" => 1));

        // email reviewers
        if ($prow->reviews_by_id())
            HotCRPMailer::send_reviewers("@withdrawreviewer", $prow, array("reason" => $reason));

        // remove voting tags so people don't have phantom votes
        if ($Conf->tags()->has_vote) {
            // XXX should do this in a_status.php
            $acsv = ["paper,action,tag"];
            foreach ($Conf->tags()->filter("vote") as $vt) {
                array_push($acsv, "{$prow->paperId},cleartag,{$vt->tag}",
                           "{$prow->paperId},cleartag,all~{$vt->tag}");
            }
            $assignset = new AssignmentSet($Conf->site_contact());
            $assignset->enable_papers($prow);
            $assignset->parse(join("\n", $acsv));
            $assignset->execute();
        }

        $Me->log_activity("Withdrew", $prow->paperId);
        redirectSelf();
    } else
        Conf::msg_error(whyNotText($whyNot, "withdraw"));
}
if (isset($_REQUEST["revive"]) && !$newPaper && check_post()) {
    if (!($whyNot = $Me->perm_revive_paper($prow))) {
        Dbl::qe("update Paper set timeWithdrawn=0, timeSubmitted=if(timeSubmitted=-100,$Now,if(timeSubmitted<-100,-timeSubmitted,0)), withdrawReason=null where paperId=$prow->paperId");
        $Conf->update_papersub_setting(0);
        loadRows();
        $Me->log_activity("Revived", $prow->paperId);
        redirectSelf();
    } else
        Conf::msg_error(whyNotText($whyNot, "revive"));
}


// send watch messages
global $Qreq;
$Qreq = make_qreq();

function final_submit_watch_callback($prow, $minic) {
    if ($minic->can_view_paper($prow))
        HotCRPMailer::send_to($minic, "@finalsubmitnotify", $prow);
}

function update_paper(PaperStatus $ps, $pj, $opj, $qreq, $action, $diffs) {
    global $Conf, $Me, $prow;
    // XXX lock tables

    $saved = $ps->save_paper_json($pj);

    if (!$saved && !$prow && $qreq->has_files())
        $ps->error_at("paper", "<strong>Your uploaded files were ignored.</strong>");

    if (!$saved) {
        $emsg = $ps->messages();
        Conf::msg_error(space_join($Conf->_("There were errors in saving your paper."), $Conf->_("Please fix them and try again."), count($emsg) ? "<ul><li>" . join("</li><li>", $emsg) . "</li></ul>" : ""));
        return false;
    }

    // submit paper if no error so far
    $_REQUEST["paperId"] = $_GET["paperId"] = $qreq->paperId = $pj->pid;
    loadRows();
    if ($action === "final") {
        $submitkey = "timeFinalSubmitted";
        $storekey = "finalPaperStorageId";
    } else {
        $submitkey = "timeSubmitted";
        $storekey = "paperStorageId";
    }
    $wasSubmitted = $opj && get($opj, "submitted");
    if (get($pj, "submitted") || $Conf->can_pc_see_all_submissions())
        $Conf->update_papersub_setting(1);

    // confirmation message
    if ($action == "final") {
        $actiontext = "Updated final";
        $template = "@submitfinalpaper";
    } else if (get($pj, "submitted") && !$wasSubmitted) {
        $actiontext = "Submitted";
        $template = "@submitpaper";
    } else if (!$opj) {
        $actiontext = "Registered";
        $template = "@registerpaper";
    } else {
        $actiontext = "Updated";
        $template = "@updatepaper";
    }
    if ($opj)
        $difftext = join(", ", array_keys($diffs));
    else // only mark submission
        $difftext = join(", ", array_intersect(array_keys($diffs), ["submission", "final"]));

    // additional information
    $notes = array();
    if ($action == "final") {
        if ($prow->$submitkey === null || $prow->$submitkey <= 0)
            $notes[] = $Conf->_("The final version has not yet been submitted.");
        $deadline = $Conf->printableTimeSetting("final_soft", "span");
        if ($deadline != "N/A" && $Conf->deadlinesAfter("final_soft")) {
            $x = $Conf->_("The deadline for submitting final versions was %s.", $deadline);
            if ($x != "")
                $notes[] = "<strong>$x</strong>";
        } else if ($deadline != "N/A")
            $notes[] = $Conf->_("You have until %s to make further changes.", $deadline);
    } else {
        if (get($pj, "submitted"))
            $notes[] = $Conf->_("You will receive email when reviews are available.");
        else if ($prow->size == 0 && !opt("noPapers"))
            $notes[] = $Conf->_("The submission has not yet been uploaded.");
        else if ($Conf->setting("sub_freeze") > 0)
            $notes[] = $Conf->_("The submission has not yet been completed.");
        else
            $notes[] = $Conf->_("The submission is marked as not ready for review.");
        $deadline = $Conf->printableTimeSetting("sub_update", "span");
        if ($deadline != "N/A" && ($prow->timeSubmitted <= 0 || $Conf->setting("sub_freeze") <= 0))
            $notes[] = $Conf->_("Further updates are allowed until %s.", $deadline);
        $deadline = $Conf->printableTimeSetting("sub_sub", "span");
        if ($deadline != "N/A" && $prow->timeSubmitted <= 0) {
            if ($Conf->setting("sub_freeze") > 0)
                $x = $Conf->_("If the submission is not completed by %s, it will not be considered.", $deadline);
            else
                $x = $Conf->_("If the submission is not ready for review by %s, it will not be considered.", $deadline);
            if ($x != "")
                $notes[] = "<strong>$x</strong>";
        }
    }
    $notes = join(" ", array_filter($notes, function ($n) { return $n !== ""; }));

    $webnotes = "";
    if (count($ps->messages()))
        $webnotes .= " <ul><li>" . join("</li><li>", $ps->messages()) . "</li></ul>";

    if ($wasSubmitted != get($pj, "submitted"))
        $diffs["ready"] = true;

    $logtext = $actiontext . ($difftext ? " $difftext" : "");
    $Me->log_activity($logtext, $prow->paperId);

    // HTML confirmation
    if (empty($diffs))
        $webmsg = $Conf->_("No changes to submission #%d.", $prow->paperId);
    else
        $webmsg = $Conf->_("$actiontext submission #%d.", $prow->paperId);
    if ($notes || $webnotes)
        $webmsg .= " " . $notes . $webnotes;
    $Conf->msg($prow->$submitkey > 0 ? "confirm" : "warning", $webmsg);

    // No mail if no change
    if (empty($diffs))
        return true;

    // mail confirmation to all contact authors
    if (!$Me->privChair || $qreq->doemail > 0) {
        $options = array("infoNames" => 1);
        if ($Me->privChair && $prow->conflictType < CONFLICT_AUTHOR)
            $options["adminupdate"] = true;
        if ($Me->privChair && isset($qreq->emailNote))
            $options["reason"] = $qreq->emailNote;
        if ($notes !== "")
            $options["notes"] = preg_replace(",</?(?:span.*?|strong)>,", "", $notes) . "\n\n";
        HotCRPMailer::send_contacts($template, $prow, $options);
    }

    // other mail confirmations
    if ($action == "final" && !Dbl::has_error() && !$ps->has_error())
        $prow->notify(WATCHTYPE_FINAL_SUBMIT, "final_submit_watch_callback", $Me);
    return true;
}


if (($Qreq->update || $Qreq->submitfinal) && check_post($Qreq)) {
    // choose action
    $action = "update";
    if ($Qreq->submitfinal && !$newPaper)
        $action = "final";
    else if ($Qreq->submitpaper
             && (($prow && $prow->size > 0)
                 || $Qreq->has_file("paperUpload")
                 || opt("noPapers")))
        $action = "submit";

    $ps = new PaperStatus($Conf, $Me);
    $opj = $prow ? $ps->paper_json($prow, ["forceShow" => true]) : null;
    $pj = PaperSaver::apply_all($Me, $prow, $opj, $Qreq, $action);
    $diffs = PaperSaver::diffs_all($Me, $pj, $opj);

    // check deadlines
    if ($newPaper)
        // we know that can_start_paper implies can_finalize_paper
        $whyNot = $Me->perm_start_paper();
    else if ($action == "final")
        $whyNot = $Me->perm_submit_final_paper($prow);
    else {
        $whyNot = $Me->perm_update_paper($prow);
        if ($whyNot && $action == "submit"
            && (empty($diffs) || join(" ", array_keys($diffs)) === "contacts"))
            $whyNot = $Me->perm_finalize_paper($prow);
    }

    // actually update
    if (!$whyNot) {
        if (update_paper($ps, $pj, $opj, $Qreq, $action, $diffs))
            redirectSelf(array("p" => $prow->paperId, "m" => "edit"));
    } else {
        if ($action == "final")
            $adescription = "submit final version for";
        else
            $adescription = $prow ? "update" : "register";
        Conf::msg_error(whyNotText($whyNot, $adescription));
    }

    // If we get here, we failed to update.
    // Use the request unless the request failed because updates
    // aren't allowed.
    $useRequest = !$whyNot || !$prow
        || !($action != "final" && !$Me->can_update_paper($prow)
             && $Me->can_finalize_paper($prow));
}

if ($Qreq->updatecontacts && check_post($Qreq) && $prow) {
    if ($Me->can_administer($prow) || $Me->act_author_view($prow)) {
        $ps = new PaperStatus($Conf, $Me);
        $opj = $ps->paper_json($prow, ["forceShow" => true]);
        $pj = PaperStatus::clone_json($opj);
        PaperSaver::replace_contacts($pj, $Qreq);
        if (!PaperSaver::diffs_all($Me, $pj, $opj))
            Conf::msg_warning($Conf->_("No changes to submission #%d.", $prow->paperId));
        else if ($ps->save_paper_json($pj, $opj)) {
            Conf::msg_confirm($Conf->_("Updated contacts for submission #%d.", $prow->paperId));
            $Me->log_activity("Updated contacts", $prow->paperId);
            redirectSelf();
        } else
            Conf::msg_error("<ul><li>" . join("</li><li>", $ps->messages()) . "</li></ul>");
    } else
        Conf::msg_error(whyNotText(array("permission" => 1), "update contacts for"));

    // use request?
    $useRequest = true;
}


// delete action
if ($Qreq->delete && check_post()) {
    if ($newPaper)
        $Conf->confirmMsg("Paper deleted.");
    else if (!$Me->privChair)
        Conf::msg_error("Only the program chairs can permanently delete papers. Authors can withdraw papers, which is effectively the same.");
    else {
        // mail first, before contact info goes away
        if (!$Me->privChair || $Qreq->doemail > 0)
            HotCRPMailer::send_contacts("@deletepaper", $prow, array("reason" => (string) $Qreq->emailNote, "infoNames" => 1));
        // XXX email self?
        $rrows = $prow->reviews_by_id();

        $error = false;
        $tables = array('Paper', 'PaperStorage', 'PaperComment', 'PaperConflict', 'PaperReview', 'PaperReviewPreference', 'PaperTopic', 'PaperTag', "PaperOption");
        foreach ($tables as $table) {
            $result = Dbl::qe_raw("delete from $table where paperId=$prow->paperId");
            $error |= ($result == false);
        }
        if (!$error) {
            $Conf->confirmMsg("Paper #$prow->paperId deleted.");
            $Conf->update_papersub_setting(-1);
            if ($prow->outcome > 0)
                $Conf->update_paperacc_setting(-1);
            if ($prow->leadContactId > 0 || $prow->shepherdContactId > 0)
                $Conf->update_paperlead_setting(-1);
            if ($prow->managerContactId > 0)
                $Conf->update_papermanager_setting(-1);
            if ($rrows && array_filter($rrows, function ($rrow) { return $rrow->reviewToken > 0; }))
                $Conf->update_rev_tokens_setting(-1);
            if ($rrows && array_filter($rrows, function ($rrow) { return $rrow->reviewType == REVIEW_META; }))
                $Conf->update_metareviews_setting(-1);
            $Me->log_activity("Deleted", $prow->paperId);
        }

        $prow = null;
        errorMsgExit("");
    }
}


// correct modes
$paperTable = new PaperTable($prow, $Qreq);
$paperTable->resolveComments();
if ($paperTable->can_view_reviews() || $paperTable->mode == "re") {
    $paperTable->resolveReview(false);
    $paperTable->fixReviewMode();
}


// prepare paper table
if ($paperTable->mode == "edit") {
    if ($newPaper)
        $editable = true;
    else {
        $old_overrides = $Me->set_overrides($Me->overrides() | Contact::OVERRIDE_TIME);
        $editable = $Me->can_update_paper($prow);
        if ($prow->outcome > 0 && $Conf->collectFinalPapers() && $Me->can_submit_final_paper($prow))
            $editable = "f";
        $Me->set_overrides($old_overrides);
    }
} else
    $editable = false;

$paperTable->initialize($editable, $editable && $useRequest);
if ($ps && $paperTable->mode === "edit")
    $paperTable->set_edit_status($ps);
else if ($prow && $paperTable->mode === "edit") {
    $ps = new PaperStatus($Conf, $Me, ["forceShow" => true]);
    $ps->paper_json($prow, ["msgs" => true]);
    $paperTable->set_edit_status($ps);
}

// produce paper table
confHeader();
$paperTable->paptabBegin();

if ($paperTable->mode === "edit")
    $paperTable->paptabEndWithReviewMessage();
else {
    if ($paperTable->mode === "re") {
        $paperTable->paptabEndWithEditableReview();
        $paperTable->paptabComments();
    } else if ($paperTable->can_view_reviews())
        $paperTable->paptabEndWithReviewsAndComments();
    else {
        $paperTable->paptabEndWithReviewMessage();
        $paperTable->paptabComments();
    }
    // restore comment across logout bounce
    if (req("editcomment")) {
        $cid = req("c");
        $preferred_resp_round = false;
        if (($x = req("response")))
            $preferred_resp_round = $Conf->resp_round_number($x);
        if ($preferred_resp_round === false)
            $preferred_resp_round = $Me->preferred_resp_round_number($prow);
        $j = null;
        foreach ($paperTable->viewable_comments() as $crow) {
            if ($crow->commentId == $cid
                || ($cid === null
                    && ($crow->commentType & COMMENTTYPE_RESPONSE) != 0
                    && $crow->commentRound === $preferred_resp_round))
                $j = $crow->unparse_json($Me, true);
        }
        if (!$j) {
            $j = (object) ["is_new" => true, "editable" => true];
            if ($Me->act_author_view($prow))
                $j->by_author = true;
            if ($preferred_resp_round !== false)
                $j->response = $Conf->resp_round_name($preferred_resp_round);
        }
        if (($x = req("comment")) !== null) {
            $j->text = $x;
            $j->visibility = req("visibility");
            $tags = trim((string) req("commenttags"));
            $j->tags = $tags === "" ? [] : preg_split('/\s+/', $tags);
            $j->blind = !!req("blind");
            $j->draft = !!req("draft");
        }
        Ht::stash_script("papercomment.edit(" . json_encode_browser($j) . ")");
    }
}

$Conf->footer();
