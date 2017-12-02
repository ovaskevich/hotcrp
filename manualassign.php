<?php
// manualassign.php -- HotCRP chair's paper assignment page
// HotCRP is Copyright (c) 2006-2017 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

require_once("src/initweb.php");
require_once("src/papersearch.php");
if (!$Me->is_manager())
    $Me->escape();
$Me->set_overrides($Me->overrides() | Contact::OVERRIDE_CONFLICT);

// request cleaning
$qreq = make_qreq();

$tOpt = PaperSearch::manager_search_types($Me);
if (!$qreq->t || !isset($tOpt[$qreq->t])) {
    reset($tOpt);
    $qreq->t = key($tOpt);
}

if ($qreq->kind != "a" && $qreq->kind != "c")
    $qreq->kind = "a";

if (!$qreq->q || trim($qreq->q) == "(All)")
    $qreq->q = "";

if (!$qreq->p && $qreq->pap)
    $qreq->p = $qreq->pap;
if (is_string($qreq->p))
    $qreq->p = preg_split('/\s+/', $qreq->p);

if (is_string($qreq->papx))
    $qreq->papx = preg_split('/\s+/', $qreq->papx);

$reviewer = $Me;
if (isset($qreq->reviewer)) {
    foreach ($Conf->full_pc_members() as $pcm)
        if (strcasecmp($pcm->email, $qreq->reviewer) == 0
            || (string) $pcm->contactId === $qreq->reviewer) {
            $reviewer = $pcm;
            break;
        }
}
if (!($reviewer->roles & Contact::ROLE_PC))
    $reviewer = null;

$qreq->assrev = array();
foreach ($qreq as $k => $v)
    if (str_starts_with($k, "assrev")) {
        $suf = substr($k, 6);
        if (($upos = strpos($suf, "u")) !== false
            && substr($suf, $upos + 1) == $reviewer->contactId)
            $suf = substr($suf, 0, $upos);
        if (($p = cvtint($suf)) > 0)
            $qreq->assrev[$p] = $v;
    }
if (is_array($qreq->papx)) {
    foreach ($qreq->papx as $p)
        if (($p = cvtint($p)) > 0 && !isset($qreq->assrev[$p]))
            $qreq->assrev[$p] = 0;
}

if (is_array($qreq->p) && $qreq->kind == "c") {
    foreach ($qreq->p as $p)
        if (($p = cvtint($p)) > 0)
            $qreq->assrev[$p] = -1;
}

$qreq->rev_round = (string) $Conf->sanitize_round_name($qreq->rev_round);


function saveAssignments($qreq, $reviewer) {
    global $Conf, $Me, $Now;
    $round_number = null;

    if (!count($qreq->assrev))
        return;

    $result = $Me->paper_result(["paperId" => array_keys($qreq->assrev)]);

    $lastPaperId = -1;
    $del = $ins = "";
    while (($row = PaperInfo::fetch($result, $Me))) {
        $conflict_type = $row->conflict_type($reviewer);
        if ($row->paperId == $lastPaperId
            || !$Me->can_administer($row)
            || $conflict_type >= CONFLICT_AUTHOR
            || !isset($qreq->assrev[$row->paperId]))
            continue;
        $lastPaperId = $row->paperId;
        $type = $qreq->assrev[$row->paperId];
        if ($type >= 0 && $conflict_type > 0 && $conflict_type < CONFLICT_AUTHOR)
            $del .= " or paperId=$row->paperId";
        if ($type < 0 && $conflict_type < CONFLICT_CHAIRMARK)
            $ins .= ", ($row->paperId, {$reviewer->contactId}, " . CONFLICT_CHAIRMARK . ")";
        if ($qreq->kind == "a" && $type != $row->review_type($reviewer)
            && ($type <= 0 || $reviewer->can_accept_review_assignment_ignore_conflict($row))) {
            if ($type > 0 && $round_number === null)
                $round_number = (int) $Conf->round_number($qreq->rev_round, true);
            $Me->assign_review($row->paperId, $reviewer->contactId, $type,
                               array("round_number" => $round_number));
        }
    }

    if ($ins)
        $Conf->qe_raw("insert into PaperConflict (paperId, contactId, conflictType) values " . substr($ins, 2) . " on duplicate key update conflictType=greatest(conflictType,values(conflictType))");
    if ($del)
        $Conf->qe_raw("delete from PaperConflict where contactId={$reviewer->contactId} and (" . substr($del, 4) . ")");

    if ($Conf->setting("rev_tokens") === -1)
        $Conf->update_rev_tokens_setting(0);

    if ($Conf->setting("pcrev_assigntime") == $Now)
        $Conf->confirmMsg("Assignments saved! You may want to <a href=\"" . hoturl("mail", "template=newpcrev") . "\">send mail about the new assignments</a>.");
    redirectSelf(["kind" => $qreq->kind]);
}


if ($qreq->update && $reviewer && check_post())
    saveAssignments($qreq, $reviewer);
else if ($qreq->update)
    Conf::msg_error("You need to select a reviewer.");


$Conf->header("Assignments &nbsp;&#x2215;&nbsp; <strong>Manual</strong>", "assignpc", actionBar());
echo '<div class="psmode">',
    '<div class="papmode"><a href="', hoturl("autoassign"), '">Automatic</a></div>',
    '<div class="papmodex"><a href="', hoturl("manualassign"), '">Manual</a></div>',
    '<div class="papmode"><a href="', hoturl("bulkassign"), '">Bulk update</a></div>',
    '</div><hr class="c" />';


// Help list
echo "<div class='helpside'><div class='helpinside'>
Assignment methods:
<ul><li><a href='", hoturl("autoassign"), "'>Automatic</a></li>
 <li><a href='", hoturl("manualassign"), "' class='q'><strong>Manual by PC member</strong></a></li>
 <li><a href='", hoturl("assign"), "'>Manual by paper</a></li>
 <li><a href='", hoturl("bulkassign"), "'>Bulk update</a></li>
</ul>
<hr class='hr' />\n";
if ($qreq->kind == "a")
    echo "Types of PC review:
<dl><dt>" . review_type_icon(REVIEW_PRIMARY) . " Primary</dt><dd>Mandatory review</dd>
  <dt>" . review_type_icon(REVIEW_SECONDARY) . " Secondary</dt><dd>May be delegated to external reviewers</dd>
  <dt>" . review_type_icon(REVIEW_PC) . " Optional</dt><dd>May be declined</dd>
  <dt>" . review_type_icon(REVIEW_META) . " Metareview</dt><dd>Can view all other reviews before completing their own</dd></dl>
<hr class='hr' />\n";
echo "<dl><dt>Potential conflicts</dt><dd>Matches between PC member collaborators and paper authors, or between PC member and paper authors or collaborators</dd>\n";
if ($qreq->kind == "a")
    echo "<dt>Preference</dt><dd><a href='", hoturl("reviewprefs"), "'>Review preference</a></dd>
  <dt>Topic score</dt><dd>High value means PC member has interest in many paper topics</dd>
  <dt>Desirability</dt><dd>High values mean many PC members want to review the paper</dd>\n";
echo "</dl>\nClick a heading to sort.\n</div></div>";


if ($reviewer)
    echo "<h2 style='margin-top:1em'>Assignments for ", $Me->name_html_for($reviewer), ($reviewer->affiliation ? " (" . htmlspecialchars($reviewer->affiliation) . ")" : ""), "</h2>\n";
else
    echo "<h2 style='margin-top:1em'>Assignments by PC member</h2>\n";


// Change PC member
echo "<table><tr><td><div class='aahc assignpc_pcsel'>",
    Ht::form_div(hoturl("manualassign"), array("method" => "get", "id" => "selectreviewerform"));
Ht::stash_script('hiliter_children("#selectreviewerform")');

$result = $Conf->qe_raw("select ContactInfo.contactId, count(reviewId)
                from ContactInfo
                left join PaperReview on (PaperReview.contactId=ContactInfo.contactId and PaperReview.reviewType>=" . REVIEW_SECONDARY . ")
                where roles!=0 and (roles&" . Contact::ROLE_PC . ")!=0
                group by ContactInfo.contactId");
$rev_count = array();
while (($row = edb_row($result)))
    $rev_count[$row[0]] = $row[1];

$rev_opt = array();
if (!$reviewer)
    $rev_opt[0] = "(Select a PC member)";
$textarg = array("lastFirst" => $Conf->sort_by_last);
foreach ($Conf->pc_members() as $pc)
    $rev_opt[$pc->email] = Text::name_html($pc, $textarg) . " ("
        . plural(defval($rev_count, $pc->contactId, 0), "assignment") . ")";

echo "<table><tr><td><strong>PC member:</strong> &nbsp;</td>",
    "<td>", Ht::select("reviewer", $rev_opt, $reviewer ? $reviewer->email : 0), "</td></tr>",
    "<tr><td colspan='2'><div class='g'></div></td></tr>\n";

// Paper selection
echo "<tr><td>Paper selection: &nbsp;</td><td>",
    Ht::entry("q", $qreq->q,
              ["id" => "manualassignq", "size" => 40, "placeholder" => "(All)",
               "title" => "Paper numbers or search terms"]),
    " &nbsp;in &nbsp;";
if (count($tOpt) > 1)
    echo Ht::select("t", $tOpt, $qreq->t);
else
    echo join("", $tOpt);
echo "</td></tr>\n",
    "<tr><td colspan='2'><div class='g'></div>\n";

echo Ht::radio("kind", "a", $qreq->kind == "a"),
    "&nbsp;", Ht::label("Assign reviews and/or conflicts"), "<br />\n",
    Ht::radio("kind", "c", $qreq->kind == "c"),
    "&nbsp;", Ht::label("Assign conflicts only (and limit papers to potential conflicts)"), "</td></tr>\n";

echo '<tr><td colspan="2"><div class="aab aabr">',
    '<div class="aabut">', Ht::submit("Go", ["class" => "btn btn-default"]), '</div>',
    '</div></td></tr>',
    "</table>\n</div></form></div></td></tr></table>\n";


// Current PC member information
if ($reviewer) {
    // search outline from old CRP, done here in a very different way
    $hlsearch = [];
    foreach ($reviewer->aucollab_matchers() as $index => $matcher) {
        $text = "match:\"" . str_replace("\"", "", $matcher->nameaff_text()) . "\"";
        $hlsearch[] = "au" . $text;
        if (!$index && $Conf->setting("sub_collab"))
            $hlsearch[] = "co" . $text;
    }

    // Topic links
    $interest = [[], []];
    foreach ($reviewer->topic_interest_map() as $topic => $ti)
        $interest[$ti > 0 ? 1 : 0][$topic] = $ti;
    if (!empty($interest[1]) && $qreq->kind !== "c")
        echo '<div class="f-i"><div class="f-c">High interest topics</div>',
            '<div class="f-e">',
            PaperInfo::unparse_topic_list_html($Conf, $interest[1], true),
            "</div></div>";
    if (!empty($interest[0]) && $qreq->kind !== "c")
        echo '<div class="f-i"><div class="f-c">Low interest topics</div>',
            '<div class="f-e">',
            PaperInfo::unparse_topic_list_html($Conf, $interest[0], true),
            "</div></div>";

    // Conflict information
    if ($reviewer->collaborators) {
        echo '<div class="f-i"><div class="f-c">Collaborators</div>',
            '<div class="f-e">';
        $cos = [];
        foreach (explode("\n", $reviewer->collaborators) as $co)
            if ($co !== "")
                $cos[] = htmlspecialchars(trim($co));
        echo join("; ", $cos), '</div></div>';
    }

    echo '<div class="f-i"><div class="f-e">',
        '<a href="', hoturl("search", "q=" . urlencode(join(" OR ", $hlsearch) . " show:au" . ($Conf->setting("sub_collab") ? " show:co" : "")) . '&amp;linkto=assign'),
        '">Search for potential conflicts</a></div></div>';

    // main assignment form
    $search = new PaperSearch($Me, ["t" => $qreq->t, "q" => $qreq->q,
                                    "urlbase" => hoturl_site_relative_raw("manualassign", ["reviewer" => $reviewer->email])],
                              $reviewer);
    if (!empty($hlsearch))
        $search->set_field_highlighter_query(join(" OR ", $hlsearch));
    $paperList = new PaperList($search, ["sort" => true, "display" => ($qreq->kind == "c" ? "show:topics" : "show:topics show:reviewers")], make_qreq());
    echo "<div class='aahc'><form class='assignpc' method='post' action=\"", hoturl_post("manualassign", ["reviewer" => $reviewer->email, "kind" => $qreq->kind, "sort" => $qreq->sort]),
        "\" enctype='multipart/form-data' accept-charset='UTF-8'><div>\n",
        Ht::hidden("t", $qreq->t),
        Ht::hidden("q", $qreq->q),
        Ht::hidden("papx", join(" ", $search->paper_ids())),
        "<div class=\"aa\">",
        Ht::submit("update", "Save assignments");
    if ($qreq->kind != "c") {
        $rev_rounds = $Conf->round_selector_options();
        if (count($rev_rounds) > 1)
            echo '<span style="padding-left:2em">Review round: &nbsp;',
                Ht::select("rev_round", $rev_rounds, $qreq->rev_round ? : "unnamed", array("id" => "assrevround")),
                '</span>';
        else if (!get($rev_rounds, "unnamed"))
            echo '<span style="padding-left:2em">Review round: ', $Conf->assignment_round_name(false), '</span>';
    }
    $paperList->set_table_id_class("foldpl", "pltable_full");
    $paperList->set_view("allrevtopicpref", false);
    echo "<span style='padding-left:2em'>",
        Ht::checkbox(false, false, true, array("id" => "assrevimmediate")),
        "&nbsp;", Ht::label("Automatically save assignments", "assrevimmediate"),
        "</span></div>\n",
        $paperList->table_html(($qreq->kind == "c" ? "conflict" : "reviewAssignment"),
                               ["header_links" => true, "nofooter" => true, "list" => true]),
        "<div class='aa'>",
        Ht::submit("update", "Save assignments"),
        "</div></div></form></div>\n";
}

echo '<hr class="c" />';
$Conf->footer();
