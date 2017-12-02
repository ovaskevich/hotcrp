<?php
// pc_topics.php -- HotCRP helper classes for paper list content
// HotCRP is Copyright (c) 2006-2017 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

class Topics_PaperColumn extends PaperColumn {
    private $interest_contact;
    function __construct($cj) {
        parent::__construct($cj);
    }
    function prepare(PaperList $pl, $visible) {
        if (!$pl->conf->has_topics())
            return false;
        if ($visible)
            $pl->qopts["topics"] = 1;
        // only managers can see other users’ topic interests
        $this->interest_contact = $pl->reviewer_user();
        if ($this->interest_contact->contactId !== $pl->user->contactId
            && !$pl->user->is_manager())
            $this->interest_contact = null;
        return true;
    }
    function header(PaperList $pl, $is_text) {
        return "Topics";
    }
    function content_empty(PaperList $pl, PaperInfo $row) {
        return !isset($row->topicIds) || $row->topicIds == "";
    }
    function content(PaperList $pl, PaperInfo $row) {
        return $row->unparse_topics_html(true, $this->interest_contact);
    }
    function text(PaperList $pl, PaperInfo $row) {
        return $row->unparse_topics_text();
    }
}
