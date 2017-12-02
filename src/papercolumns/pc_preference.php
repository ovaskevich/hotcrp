<?php
// pc_preference.php -- HotCRP helper classes for paper list content
// HotCRP is Copyright (c) 2006-2017 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

class Preference_PaperColumn extends PaperColumn {
    private $editable;
    private $contact;
    private $viewer_contact;
    private $not_me;
    private $show_conflict;
    private $prefix;
    function __construct($cj, Conf $conf = null) {
        parent::__construct($cj);
        $this->override = PaperColumn::OVERRIDE_FOLD;
        $this->editable = !!get($cj, "edit");
        if ($conf && isset($cj->user))
            $this->contact = $conf->pc_member_by_email($cj->user);
    }
    function make_editable(PaperList $pl) {
        if (!($fj = (array) $pl->conf->basic_paper_column("editpref", $pl->user)))
            return $this;
        $fj["name"] = $this->name;
        return new Preference_PaperColumn((object) $fj, $pl->conf);
    }
    function prepare(PaperList $pl, $visible) {
        $this->viewer_contact = $pl->user;
        $reviewer = $pl->reviewer_user();
        $this->contact = $this->contact ? : $reviewer;
        $this->not_me = $this->contact->contactId !== $pl->user->contactId;
        if (!$pl->user->isPC
            || (($this->not_me || !$this->name /* user factory */)
                && !$pl->user->is_manager()))
            return false;
        if ($visible)
            $pl->qopts["topics"] = 1;
        if ($this->editable && $visible > 0 && ($tid = $pl->table_id()))
            $pl->add_header_script("add_revpref_ajax(" . json_encode_browser("#$tid") . ")", "revpref_ajax_$tid");
        $this->prefix =  "";
        if ($this->row)
            $this->prefix = $pl->user->reviewer_html_for($this->contact);
        return true;
    }
    private function preference_values($row) {
        if ($this->not_me && !$this->viewer_contact->allow_administer($row))
            return [null, null];
        else
            return $row->reviewer_preference($this->contact);
    }
    function compare(PaperInfo $a, PaperInfo $b, ListSorter $sorter) {
        list($ap, $ae) = $this->preference_values($a);
        list($bp, $be) = $this->preference_values($b);
        if ($ap === null || $bp === null)
            return $ap === $bp ? 0 : ($ap === null ? 1 : -1);
        if ($ap != $bp)
            return $ap < $bp ? 1 : -1;

        if ($ae !== $be) {
            if (($ae === null) !== ($be === null))
                return $ae === null ? 1 : -1;
            return (float) $ae < (float) $be ? 1 : -1;
        }

        $at = $a->topic_interest_score($this->contact);
        $bt = $b->topic_interest_score($this->contact);
        if ($at != $bt)
            return $at < $bt ? 1 : -1;
        return 0;
    }
    function analyze(PaperList $pl, &$rows, $fields) {
        $this->show_conflict = true;
        foreach ($fields as $fdef)
            if ($fdef instanceof ReviewerType_PaperColumn
                && $fdef->is_visible
                && $fdef->contact()->contactId == $this->contact->contactId)
                $this->show_conflict = false;
    }
    function header(PaperList $pl, $is_text) {
        if (!$this->not_me || $this->row)
            return "Preference";
        else if ($is_text)
            return $pl->user->name_text_for($this->contact) . " preference";
        else
            return $pl->user->name_html_for($this->contact) . "<br />preference";
    }
    function content_empty(PaperList $pl, PaperInfo $row) {
        return $this->not_me && !$pl->user->can_administer($row);
    }
    function content(PaperList $pl, PaperInfo $row) {
        $has_cflt = $row->has_conflict($this->contact);
        $pv = $this->preference_values($row);
        $ptext = unparse_preference($pv);
        $editable = $this->editable && $this->contact->can_become_reviewer_ignore_conflict($row);
        if (!$editable)
            $ptext = str_replace("-", "−" /* U+2122 */, $ptext);
        if ($this->row) {
            if ($ptext !== "")
                $ptext = $this->prefix . " <span class=\"asspref" . ($pv[0] < 0 ? "-1" : "1") . "\">P" . $ptext . "</span>";
            return $ptext;
        } else if ($has_cflt && ($editable ? !$pl->user->allow_administer($row) : $ptext === "0"))
            return $this->show_conflict ? review_type_icon(-1) : "";
        else if ($editable) {
            $iname = "revpref" . $row->paperId;
            if ($this->not_me)
                $iname .= "u" . $this->contact->contactId;
            return '<input name="' . $iname . '" class="revpref" value="' . ($ptext !== "0" ? $ptext : "") . '" type="text" size="4" tabindex="2" placeholder="0" />' . ($this->show_conflict && $has_cflt ? "&nbsp;" . review_type_icon(-1) : "");
        } else
            return $ptext;
    }
    function text(PaperList $pl, PaperInfo $row) {
        return unparse_preference($this->preference_values($row));
    }
}

class Preference_PaperColumnFactory {
    static function expand($name, Conf $conf, $xfj, $m) {
        if (!($fj = (array) $conf->basic_paper_column("pref", $conf->xt_user)))
            return null;
        if ($m[2]) {
            $fj["row"] = true;
            $fj["column"] = false;
        }
        $rs = [];
        foreach (ContactSearch::make_pc($m[1], $conf->xt_user)->ids as $cid) {
            $u = $conf->cached_user_by_id($cid);
            $fj["name"] = "pref:" . $u->email . $m[2];
            $fj["user"] = $u->email;
            $rs[] = (object) $fj;
        }
        if (empty($rs))
            $conf->xt_factory_error("No PC member matches “" . htmlspecialchars($m[1]) . "”.");
        return $rs;
    }
}
