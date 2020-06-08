<?php
// formulas/f_reviewermatch.php -- HotCRP helper class for formula expressions
// Copyright (c) 2009-2020 Eddie Kohler; see LICENSE.

class ReviewerMatch_Fexpr extends Fexpr {
    private $user;
    private $arg;
    private $flags;
    private $istag;
    private $csearch;
    private static $tagmap = array();
    private static $tagmap_conf = null;
    function __construct(Contact $user, $arg) {
        parent::__construct("reviewermatch");
        $this->user = $user;
        $this->_format = self::FBOOL;
        $this->arg = $arg;
        $this->istag = $arg[0] === "#" || ($arg[0] !== "\"" && $user->conf->pc_tag_exists($arg));
        $flags = ContactSearch::F_USER;
        if ($user->can_view_user_tags()) {
            $flags |= ContactSearch::F_TAG;
        }
        if ($arg[0] === "\"") {
            $flags |= ContactSearch::F_QUOTED;
            $arg = str_replace("\"", "", $arg);
        }
        $this->csearch = new ContactSearch($flags, $arg, $user);
    }
    function inferred_index() {
        return self::IDX_REVIEW;
    }
    function view_score(Contact $user) {
        if ($this->istag) {
            return VIEWSCORE_PC;
        } else if (!$user->conf->setting("rev_blind")) {
            return VIEWSCORE_AUTHOR;
        } else if ($user->conf->setting("pc_seeblindrev")) {
            return VIEWSCORE_REVIEWERONLY;
        } else {
            return VIEWSCORE_PC;
        }
    }
    function compile(FormulaCompiler $state) {
        assert($state->user === $this->user);
        // NB the following case also catches attempts to view a non-viewable
        // user tag (the csearch will return nothing).
        if ($this->csearch->is_empty()) {
            return "null";
        }
        $state->queryOptions["reviewSignatures"] = true;
        if ($this->istag) {
            assert($state->user->can_view_user_tags());
            $tag = $this->arg[0] === "#" ? substr($this->arg, 1) : $this->arg;
            return "ReviewerMatch_Fexpr::check_tagmap(\$contact->conf, " . $state->loop_cid() . ", " . json_encode($tag) . ")";
        } else {
            return '(' . $state->_prow() . '->can_view_review_identity_of(' . $state->loop_cid() . ', $contact) ? array_search(' . $state->loop_cid() . ", [" . join(", ", $this->csearch->user_ids()) . "]) !== false : null)";
        }
    }
    function matches_at_most_once() {
        return count($this->csearch->user_ids()) <= 1;
    }
    static function check_tagmap(Conf $conf, $cid, $tag) {
        if ($conf !== self::$tagmap_conf) {
            self::$tagmap = [];
            self::$tagmap_conf = $conf;
        }
        if (($a = get(self::$tagmap, $tag)) === null) {
            $a = array();
            foreach ($conf->pc_members() as $pc) {
                if (($v = $pc->tag_value($tag)) !== false) {
                    $a[$pc->contactId] = $v ? : true;
                }
            }
            self::$tagmap[$tag] = $a;
        }
        return get($a, $cid) ? : false;
    }
}
