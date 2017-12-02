<?php
// pc_desirability.php -- HotCRP helper classes for paper list content
// HotCRP is Copyright (c) 2006-2017 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

class Desirability_PaperColumn extends PaperColumn {
    function __construct($cj) {
        parent::__construct($cj);
    }
    function prepare(PaperList $pl, $visible) {
        if (!$pl->user->privChair)
            return false;
        if ($visible)
            $pl->qopts["desirability"] = 1;
        return true;
    }
    function compare(PaperInfo $a, PaperInfo $b, ListSorter $sorter) {
        return $b->desirability < $a->desirability ? -1 : ($b->desirability > $a->desirability ? 1 : 0);
    }
    function header(PaperList $pl, $is_text) {
        return "Desirability";
    }
    function content(PaperList $pl, PaperInfo $row) {
        return htmlspecialchars($this->text($pl, $row));
    }
    function text(PaperList $pl, PaperInfo $row) {
        return get($row, "desirability") + 0;
    }
}
