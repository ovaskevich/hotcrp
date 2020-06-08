<?php
// pc_reviewerlist.php -- HotCRP helper classes for paper list content
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class ReviewerList_PaperColumn extends PaperColumn {
    private $pref = false;
    private $topics = false;
    function __construct(Conf $conf, $cj) {
        parent::__construct($conf, $cj);
        if (isset($cj->options) && in_array("pref", $cj->options)) {
            $this->pref = true;
            $this->topics = in_array("topics", $cj->options)
                || in_array("topic", $cj->options);
        }
    }
    function prepare(PaperList $pl, $visible) {
        if (!$pl->user->can_view_some_review_identity()) {
            return false;
        }
        if ($this->pref && !$pl->user->allow_view_preference(null)) {
            $this->pref = false;
        }
        $pl->qopts["reviewSignatures"] = true;
        if ($visible && $this->pref) {
            $pl->qopts["allReviewerPreference"] = true;
            if ($this->topics && $pl->conf->has_topics())
                $pl->qopts["topics"] = true;
        }
        if ($pl->conf->review_blindness() === Conf::BLIND_OPTIONAL
            || $this->pref) {
            $this->override = PaperColumn::OVERRIDE_BOTH;
        } else {
            $this->override = PaperColumn::OVERRIDE_IFEMPTY;
        }
        return true;
    }
    function content_empty(PaperList $pl, PaperInfo $row) {
        return !$pl->user->can_view_review_identity($row, null);
    }
    function content(PaperList $pl, PaperInfo $row) {
        // see also search.php > getaction == "reviewers"
        $x = [];
        $pref = $pl->user->can_view_preference($row);
        foreach ($row->reviews_by_display($pl->user) as $xrow) {
            if ($pl->user->can_view_review_identity($row, $xrow)) {
                $ranal = $pl->make_review_analysis($xrow, $row);
                $t = $pl->user->reviewer_html_for($xrow) . " " . $ranal->icon_html(false);
                if ($pref) {
                    $t .= unparse_preference_span($row->preference($xrow->contactId, $this->topics), true);
                }
                $x[] = $t;
            }
        }
        if ($x) {
            return '<span class="nb">' . join(',</span> <span class="nb">', $x) . '</span>';
        } else {
            return "";
        }
    }
    function text(PaperList $pl, PaperInfo $row) {
        $x = [];
        $pref = $pl->user->can_view_preference($row);
        foreach ($row->reviews_by_display($pl->user) as $xrow) {
            if ($pl->user->can_view_review_identity($row, $xrow)) {
                $t = $pl->user->reviewer_text_for($xrow);
                if ($pref) {
                    $pf = $row->preference($xrow->contactId, $this->topics);
                    $t .= " P" . unparse_number_pm_text($pf[0]) . unparse_expertise($pf[1]);
                    if ($this->topics && $pf[2] && !$pf[0]) {
                        $t .= " T" . unparse_number_pm_text($pf[2]);
                    }
                }
                $x[] = $t;
            }
        }
        return join("; ", $x);
    }
}
