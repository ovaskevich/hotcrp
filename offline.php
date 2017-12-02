<?php
// offline.php -- HotCRP offline review management page
// HotCRP is Copyright (c) 2006-2017 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

require_once("src/initweb.php");
if (!$Me->email)
    $Me->escape();
$rf = $Conf->review_form();


// general error messages
if (defval($_REQUEST, "post") && !count($_POST))
    $Conf->post_missing_msg();


// download blank review form action
if (isset($_REQUEST["downloadForm"])) {
    $text = $rf->textFormHeader("blank") . $rf->textForm(null, null, $Me, null) . "\n";
    downloadText($text, "review");
}


// upload review form action
if (isset($_REQUEST["uploadForm"])
    && file_uploaded($_FILES["uploadedFile"])
    && check_post()) {
    $tf = ReviewValues::make_text($rf, file_get_contents($_FILES["uploadedFile"]["tmp_name"]),
                         $_FILES["uploadedFile"]["name"]);
    while ($tf->parse_text(req("override")))
        $tf->check_and_save($Me, null, null);
    $tf->report();
    // Uploading forms may have completed the reviewer's task; recheck roles.
    Contact::update_rights();
} else if (isset($_REQUEST["uploadForm"]))
    Conf::msg_error("Choose a file first.");


// upload tag indexes action
function saveTagIndexes($tag, $filename, &$settings, &$titles, &$linenos, &$errors) {
    global $Conf, $Me, $Error;

    $result = $Me->paper_result(["paperId" => array_keys($settings)]);
    while (($row = PaperInfo::fetch($result, $Me)))
        if ($settings[$row->paperId] !== null
            && !$Me->can_change_tag($row, $tag, null, 1)) {
            $errors[$linenos[$row->paperId]] = "You cannot rank paper #$row->paperId.";
            unset($settings[$row->paperId]);
        } else if ($titles[$row->paperId] !== ""
                   && strcmp($row->title, $titles[$row->paperId]) != 0
                   && strcasecmp($row->title, simplify_whitespace($titles[$row->paperId])) != 0)
            $errors[$linenos[$row->paperId]] = "Warning: Title doesn’t match";

    if (!$tag)
        defappend($Error["tags"], "No tag defined");
    else if (count($settings)) {
        $x = array("paper,tag,lineno");
        foreach ($settings as $pid => $value)
            $x[] = "$pid,$tag#" . ($value === null ? "clear" : $value) . "," . $linenos[$pid];
        $assigner = new AssignmentSet($Me);
        $assigner->parse(join("\n", $x) . "\n", $filename);
        $assigner->report_errors();
        $assigner->execute();
    }

    $settings = $titles = $linenos = array();
}

function check_tag_index_line(&$line) {
    if ($line && count($line) >= 2
        && preg_match('/\A\s*(|[Xx=]|>*|\(?([-+]?\d+)\)?)\s*\z/', $line[0], $m1)
        && preg_match('/\A\s*(\d+)\s*\z/', $line[1], $m2)) {
        $line[0] = isset($m1[2]) && $m1[2] !== "" ? $m1[2] : $m1[1];
        $line[1] = $m2[1];
        return true;
    } else
        return false;
}

function setTagIndexes() {
    global $Conf, $Me, $Error;
    $filename = null;
    if (isset($_REQUEST["upload"]) && file_uploaded($_FILES["file"])) {
        if (($text = file_get_contents($_FILES["file"]["tmp_name"])) === false) {
            Conf::msg_error("Internal error: cannot read file.");
            return;
        }
        $filename = @$_FILES["file"]["name"];
    } else if (!($text = defval($_REQUEST, "data"))) {
        Conf::msg_error("Choose a file first.");
        return;
    }

    $RealMe = $Me;
    $tagger = new Tagger;
    if (($tag = defval($_REQUEST, "tag")))
        $tag = $tagger->check($tag, Tagger::NOVALUE);
    $curIndex = 0;
    $lineno = 1;
    $settings = $titles = $linenos = $errors = array();
    $csvp = new CsvParser("", CsvParser::TYPE_GUESS);
    foreach (explode("\n", rtrim(cleannl($text))) as $l) {
        if (substr($l, 0, 4) == "Tag:" || substr($l, 0, 6) == "# Tag:") {
            if (!$tag)
                $tag = $tagger->check(trim(substr($l, ($l[0] == "#" ? 6 : 4))), Tagger::NOVALUE);
        } else if (trim($l) !== "" && $l[0] !== "#") {
            $csvp->unshift($l);
            $line = $csvp->next();
            if ($line && check_tag_index_line($line)) {
                if (isset($settings[$line[1]]))
                    $errors[$lineno] = "Paper #$line[1] already given on line " . $linenos[$line[1]];
                if ($line[0] === "X" || $line[0] === "x")
                    $settings[$line[1]] = null;
                else if ($line[0] === "" || $line[0] === ">")
                    $settings[$line[1]] = $curIndex = $curIndex + 1;
                else if (is_numeric($line[0]))
                    $settings[$line[1]] = $curIndex = intval($line[0]);
                else if ($line[0] === "=")
                    $settings[$line[1]] = $curIndex;
                else
                    $settings[$line[1]] = $curIndex = $curIndex + strlen($line[0]);
                $titles[$line[1]] = trim(get($line, 2, ""));
                $linenos[$line[1]] = $lineno;
            } else
                $errors[$lineno] = "Syntax error";
        }
        ++$lineno;
    }

    if (count($settings) && $Me)
        saveTagIndexes($tag, $filename, $settings, $titles, $linenos, $errors);
    $Me = $RealMe;

    if (count($errors)) {
        ksort($errors);
        if ($filename)
            foreach ($errors as $lineno => &$error)
                $error = '<span class="lineno">' . htmlspecialchars($filename) . ':' . $lineno . ':</span> ' . $error;
        $Error["tags"] = '<div class="parseerr"><p>' . join("</p>\n<p>", $errors) . '</p></div>';
    }
    if (isset($Error["tags"]))
        Conf::msg_error($Error["tags"]);
    else if (isset($_REQUEST["setvote"]))
        $Conf->confirmMsg("Votes saved.");
    else {
        $dtag = $tagger->unparse($tag);
        $Conf->confirmMsg("Ranking saved.  To view it, <a href='" . hoturl("search", "q=order:" . urlencode($dtag)) . "'>search for “order:{$dtag}”</a>.");
    }
}
if ((isset($_REQUEST["setvote"]) || isset($_REQUEST["setrank"]))
    && $Me->is_reviewer() && check_post())
    setTagIndexes();


$pastDeadline = !$Conf->time_review(null, $Me->isPC, true);

if (!$Conf->time_review_open() && !$Me->privChair) {
    Conf::msg_error("The site is not open for review.");
    go(hoturl("index"));
}

$Conf->header("Offline reviewing", "offline", actionBar());

if ($Me->is_reviewer()) {
    if (!$Conf->time_review_open())
        $Conf->infoMsg("The site is not open for review.");
    $Conf->infoMsg("Use this page to download a blank review form, or to upload review forms you’ve already filled out.");
    if (!$Me->can_clickthrough("review")) {
        echo '<div class="js-clickthrough-container">';
        PaperTable::echo_review_clickthrough();
        echo '</div>';
    }
} else
    $Conf->infoMsg("You aren’t registered as a reviewer or PC member for this conference, but for your information, you may download the review form anyway.");


echo "<table id='offlineform'>";

// Review forms
echo "<tr><td><h3>Download forms</h3>\n<div>";
if ($Me->is_reviewer()) {
    echo "<a href='", hoturl("search", "fn=get&amp;getfn=revform&amp;q=&amp;t=r&amp;p=all"), "'>Your reviews</a><br />\n";
    if ($Me->has_outstanding_review())
        echo "<a href='", hoturl("search", "fn=get&amp;getfn=revform&amp;q=&amp;t=rout&amp;p=all"), "'>Your incomplete reviews</a><br />\n";
    echo "<a href='", hoturl("offline", "downloadForm=1"), "'>Blank form</a></div>
<div class='g'></div>
<span class='hint'><strong>Tip:</strong> Use <a href='", hoturl("search", "q="), "'>Search</a> &gt; Download to choose individual papers.\n";
} else
    echo "<a href='", hoturl("offline", "downloadForm=1"), "'>Blank form</a></div>\n";
echo "</td>\n";
if ($Me->is_reviewer()) {
    $disabled = ($pastDeadline && !$Me->privChair ? " disabled='disabled'" : "");
    echo "<td><h3>Upload filled-out forms</h3>\n",
        Ht::form_div(hoturl_post("offline", "uploadForm=1")),
        Ht::hidden("postnonempty", 1),
        "<input type='file' name='uploadedFile' accept='text/plain' size='30' $disabled/>&nbsp; ",
        Ht::submit("Go", array("disabled" => !!$disabled));
    if ($pastDeadline && $Me->privChair)
        echo "<br />", Ht::checkbox("override"), "&nbsp;", Ht::label("Override&nbsp;deadlines");
    echo "<br /><span class='hint'><strong>Tip:</strong> You may upload a file containing several forms.</span>";
    echo "</div></form></td>\n";
}
echo "</tr>\n";


// Ranks
if ($Conf->setting("tag_rank") && $Me->is_reviewer()) {
    $ranktag = $Conf->setting_data("tag_rank");
    echo "<tr><td><div class='g'></div></td></tr>\n",
        "<tr><td><h3>Download ranking file</h3>\n<div>";
    echo "<a href=\"", hoturl("search", "fn=get&amp;getfn=rank&amp;tag=%7E$ranktag&amp;q=&amp;t=r&amp;p=all"), "\">Your reviews</a>";
    if ($Me->isPC)
        echo "<br />\n<a href=\"", hoturl("search", "fn=get&amp;getfn=rank&amp;tag=%7E$ranktag&amp;q=&amp;t=s&amp;p=all"), "\">All submitted papers</a>";
    echo "</div></td>\n";

    $disabled = ($pastDeadline && !$Me->privChair ? " disabled='disabled'" : "");
    echo "<td><h3>Upload ranking file</h3>\n",
        Ht::form_div(hoturl_post("offline", "setrank=1&amp;tag=%7E$ranktag")),
        Ht::hidden("upload", 1),
        "<input type='file' name='file' accept='text/plain' size='30' $disabled/>&nbsp; ",
        Ht::submit("Go", array("disabled" => !!$disabled));
    if ($pastDeadline && $Me->privChair)
        echo "<br />", Ht::checkbox("override"), "&nbsp;", Ht::label("Override&nbsp;deadlines");
    echo "<br /><span class='hint'><strong>Tip:</strong> Use “<a href='", hoturl("search", "q=" . urlencode("editsort:#~$ranktag")), "'>editsort:#~$ranktag</a>” to drag and drop your ranking.</span>";
    echo "<br /><span class='hint'><strong>Tip:</strong> “<a href='", hoturl("search", "q=order:%7E$ranktag"), "'>order:~$ranktag</a>” searches by your ranking.</span>";
    echo "</div></form></td>\n";
    echo "</tr>\n";
}

echo "</table>\n";


$Conf->footer();
