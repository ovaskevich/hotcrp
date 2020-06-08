<?php
// src/help/h_bulkassign.php -- HotCRP help functions
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class BulkAssign_HelpTopic {
    static function render($hth) {
        echo "
<p>The ", $hth->hotlink("bulk assignments page", "bulkassign"), " offers
fine-grained control over review assignments, tags, leads, shepherds, and many
other aspects of site operation. Users upload a CSV (comma-separated value
file) to prepare an assignment. HotCRP will display the consequences of the
requested assignment for confirmation and approval.</p>

<p>Assignment CSVs contain <code>pid</code> and <code>action</code> columns,
where <code>pid</code> determines which papers are affected and
<code>action</code> determines what kind of assignment is performed. The
<code>pid</code> column can be a simple submission number, like “10”, or a
search description, like “#manny OR #ramirez”. Other parameter columns depend
on action. For instance, the <code>tag</code> action uses the <code>tag</code>
column to determine what tag to add. Actions requiring a user locate that user
via the <code>email</code>, <code>name</code>, <code>first name</code>,
<code>last name</code>, and/or <code>user</code> columns.</p>

<p>This example file clears existing R1 review assignments for papers tagged
#redo, then assigns two primary reviews for submission #1 and one secondary
review for submission #2:</p>

<pre class=\"entryexample\">pid,action,email,round
#redo,clearreview,all,R1
1,primary,man@alice.org
2,secondary,slugger@manny.com
1,primary,slugger@manny.com</pre>

<p>Errors will be reported if <code>man@alice.org</code> or
<code>slugger@manny.com</code> aren’t PC members, or if they have conflicts
with their assigned papers.</p>

<p>Assignment files are parsed from top to bottom, but applied as a unit. For
example, if a file clears and then recreates a existing review assignment,
HotCRP will leave the existing assignment alone.</p>";

        echo $hth->subhead("Action overview");
        self::echo_actions($hth->user, $hth);
        echo '<p><em>Notes:</em> The <code>user</code> parameter can be
replaced by a combination of <code>email</code>, <code>name</code>,
<code>first name</code>, and <code>last name</code>. <code>tag</code>
columns can contain a tag value, using “tag#value” syntax, or the value
can be supplied separately.</p>';

        $hth->render_group("bulkassignactions");
    }

    static function render_action_review($hth) {
        echo "<p>The <code>review</code> action assigns reviews. The
<code>review type</code> column sets the review type; it can be
<code>primary</code>, <code>secondary</code>, <code>pcreview</code> (optional
PC review), <code>meta</code>, or <code>external</code>, or <code>clear</code>
to unassign the review. The optional <code>round</code> or <code>review
round</code> column sets the review round.</p>

<p>Only PC members can be assigned primary, secondary, meta-, and optional PC
reviews. Accounts will be created for new external reviewers as necessary. The
<code>clear</code> action doesn’t delete reviews that have already been
entered.</p>

<p>The following file will create a primary review for
<code>drew@harvard.edu</code> in review round R2, or, if Drew already has a
review assignment for submission #1, modify that review’s type and round:</p>

<pre class=\"entryexample\">paper,action,email,reviewtype,round
1,review,drew@harvard.edu,primary,R2</pre>

<p>To avoid modifying an existing review, use this syntax, which means “ignore
this assignment unless the current review type is ‘none’”:</p>

<pre class=\"entryexample\">paper,action,email,reviewtype,round
1,review,drew@harvard.edu,none:primary,R2</pre>

<p>To modify an existing review (the “<code>any</code>” review type only
matches existing reviews):</p>

<pre class=\"entryexample\">paper,action,email,reviewtype,round
1,review,drew@harvard.edu,any,R2</pre>

<p>To change an existing review from round R1 to round R2:</p>

<pre class=\"entryexample\">paper,action,email,reviewtype,round
1,review,drew@harvard.edu,any,R1:R2</pre>

<p>To change all round-R1 primary reviews to round R2:</p>

<pre class=\"entryexample\">paper,action,email,reviewtype,round
all,review,all,primary,R1:R2</pre>

<p>The <code>primary</code>, <code>secondary</code>, <code>pcreview</code>,
<code>metareview</code>, and <code>external</code> actions are shorthand for
the corresponding review types.</p>";
    }

   static function render_action_tag($hth) {
        echo "<p>The <code>tag</code> action controls ",
            $hth->help_link("tags", "tags") . ". The <code>tag</code>
column names the tag to add; it can contain a ",
            $hth->help_link("tag value", "tags#values"), ", using “tag#value”
syntax, or the value can be specified using the optional <code>tag
value</code> column.</p>

<p>To clear a tag, use action <code>cleartag</code> or tag value
<code>none</code>. For example, this file clears all #p tags with value
less than 10:</p>

<pre class=\"entryexample\">paper,action,tag
all,cleartag,p#&lt;10</pre>

<p>To add to a tag order, use action <code>nexttag</code>; to add to a gapless
tag order, use <code>seqnexttag</code>. For example, this file creates a
tag order in tag #p containing submissions 4, 3, 2, 9, 10, and 6:</p>

<pre class=\"entryexample\">paper,action,tag
all,cleartag,p
4,nexttag,p
3,nexttag,p
2,nexttag,p
9,nexttag,p
10,nexttag,p
6,nexttag,p</pre>";
    }

    static function render_action_follow($hth) {
        echo "<p>The <code>following</code> column can be “yes” (to receive
email notifications on updates to reviews and comments), “no” (to block
notifications), or “default” (to revert to the default, which is based
on the user’s site preferences).</p>";
    }

    static function render_action_conflict($hth) {
        echo "<p>The <code>conflict type</code> column can be “yes”, “no”, or
a conflict type, such as “advisor” or “institutional”.</p>";
    }

    static function add_bulk_assignment_action(&$apx, $uf, $hth) {
        if (!isset($uf->alias)) {
            $t = '<tr><td class="pad';
            if ($uf->group !== $uf->name) {
                $t .= ' padl';
            }
            $t .= '">';
            $n = '<code>' . htmlspecialchars($uf->name) . '</code>';
            if ($hth
                && ($xt = $hth->member("bulkassignactions/{$uf->name}"))
                && $xt->anchorid) {
                $n = '<a href="#' . $xt->anchorid . '">' . $n . '</a>';
            }
            $t .= $n . '</td><td class="pad"><code>pid</code>';
            foreach (get($uf, "parameters", []) as $param) {
                $t .= ', ';
                if ($param[0] === "[") {
                    $t .= '[<code>' . substr($param, 1, -1) . '</code>]';
                } else {
                    $t .= '<code>' . $param . '</code>';
                }
            }
            $t .= '</td><td class="pad">';
            if (isset($uf->description_html)) {
                $t .= $uf->description_html;
            } else {
                $t .= htmlspecialchars($uf->description ?? "");
            }
            $apx[] = $t . '</td></tr>';
        }
    }

    static function echo_actions(Contact $user, $hth = null) {
        $apge = new GroupedExtensions($user, "etc/assignmentparsers.json", $user->conf->opt("assignmentParsers"));
        $apx = [];
        foreach ($apge->groups() as $ufg) {
            self::add_bulk_assignment_action($apx, $ufg, $hth);
            foreach ($apge->members($ufg->name) as $uf) {
                self::add_bulk_assignment_action($apx, $uf, $hth);
            }
        }
        if (!empty($apx)) {
            echo '<table class="p table-striped"><thead>',
                '<tr><th class="pll">Action name</th><th class="pll">Parameter columns</th><th class="pll">Description</th></tr></thead>',
                '<tbody>', join('', $apx), '</tbody></table>';
        }
        return !empty($apx);
    }
}
