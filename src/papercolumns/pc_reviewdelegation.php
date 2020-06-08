<?php
// pc_reviewdelegation.php -- HotCRP helper classes for paper list content
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class ReviewDelegation_PaperColumn extends PaperColumn {
    private $requester;
    function __construct(Conf $conf, $cj) {
        parent::__construct($conf, $cj);
    }
    function prepare(PaperList $pl, $visible) {
        if (!$pl->user->isPC) {
            return false;
        }
        $pl->qopts["reviewSignatures"] = true;
        $this->requester = $pl->reviewer_user();
        return true;
    }
    function content(PaperList $pl, PaperInfo $row) {
        global $Now;
        $rx = [];
        $row->ensure_reviewer_names();
        $old_overrides = $pl->user->add_overrides(Contact::OVERRIDE_CONFLICT);
        foreach ($row->reviews_by_display($pl->user) as $rrow) {
            if ($rrow->reviewType == REVIEW_EXTERNAL
                && $rrow->requestedBy == $this->requester->contactId) {
                if (!$pl->user->can_view_review_assignment($row, $rrow)) {
                    continue;
                }
                if ($pl->user->can_view_review_identity($row, $rrow)) {
                    $t = $pl->user->reviewer_html_for($rrow);
                } else {
                    $t = "review";
                }
                $ranal = $pl->make_review_analysis($rrow, $row);
                $d = $rrow->status_description();
                if ($rrow->reviewOrdinal) {
                    $d = rtrim("#" . $rrow->unparse_ordinal() . " " . $d);
                }
                $d = $ranal->wrap_link($d, "uu nw");
                if (!$rrow->reviewSubmitted
                    && $rrow->timeApprovalRequested == 0) {
                    if ($rrow->reviewNeedsSubmit >= 0) {
                        $d = '<strong class="overdue">' . $d . '</strong>';
                    }
                    $pl->mark_has("need_review");
                    $row->ensure_reviewer_last_login();
                    if (!$rrow->reviewLastLogin) {
                        $login = 'never logged in';
                    } else {
                        $login = 'activity ' . $pl->conf->unparse_time_relative((int) $rrow->reviewLastLogin);
                    }
                    $d .= ' <span class="hint">(' . $login . ')</span>';
                } else if (!$rrow->reviewSubmitted
                           && $rrow->timeApprovalRequested > 0) {
                    $d = '<strong>' . $d . '</strong>';
                }
                $rx[] = $t . ', ' . $d;
            }
        }
        $pl->user->set_overrides($old_overrides);
        return join('; ', $rx);
    }
}
