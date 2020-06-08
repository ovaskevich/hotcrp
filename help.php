<?php
// help.php -- HotCRP help page
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

require_once("src/initweb.php");

$help_topics = new GroupedExtensions($Me, [
    '{"name":"topics","title":"Help topics","position":-1000000,"priority":1000000,"render_callback":"show_help_topics"}',
    "etc/helptopics.json"
], $Conf->opt("helpTopics"));

if (!$Qreq->t && preg_match('/\A\/\w+\/*\z/i', $Qreq->path())) {
    $Qreq->t = $Qreq->path_component(0);
}
$topic = $Qreq->t ? : "topics";
$want_topic = $help_topics->canonical_group($topic);
if (!$want_topic) {
    $want_topic = "topics";
}
if ($want_topic !== $topic) {
    $Conf->self_redirect($Qreq, ["t" => $want_topic]);
}
$topicj = $help_topics->get($topic);

$Conf->header("Help", "help", ["title_div" => '<hr class="c">', "body_class" => "leftmenu"]);

$hth = new HelpRenderer($help_topics, $Me);


function show_help_topics($hth) {
    echo "<dl>\n";
    foreach ($hth->groups() as $ht) {
        if ($ht->name !== "topics" && isset($ht->title)) {
            echo '<dt><strong><a href="', $hth->conf->hoturl("help", "t=$ht->name"), '">', $ht->title, '</a></strong></dt>';
            if (isset($ht->description))
                echo '<dd>', get($ht, "description", ""), '</dd>';
            echo "\n";
        }
    }
    echo "</dl>\n";
}


echo '<div class="leftmenu-left"><nav class="leftmenu-menu"><h1 class="leftmenu">Help</h1><div class="leftmenu-list">';
foreach ($help_topics->groups() as $gj) {
    if (isset($gj->title)) {
        echo '<div class="leftmenu-item',
            ($gj->name === "topics" ? " mb-3" : ""),
            ($gj->name === $topic ? ' active">' : ' ui js-click-child">');
        if ($gj->name === $topic) {
            echo $gj->title;
        } else {
            echo Ht::link($gj->title, $Conf->hoturl("help", "t=$gj->name"));
        }
        echo '</div>';
    }
}
echo "</div></nav></div>\n",
    '<main id="helpcontent" class="leftmenu-content main-column">',
    '<h2 class="leftmenu">', $topicj->title, '</h2>';
$hth->render_group($topic, true);
echo "</main>\n";


$Conf->footer();
