<?php
// search/st_topic.php -- HotCRP helper class for searching for papers
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class Topic_SearchTerm extends SearchTerm {
    private $topics;
    private $negated;

    function __construct($topics, $negated) {
        parent::__construct("topic");
        $this->topics = $topics;
        $this->negated = $negated;
    }
    static function parse($word, SearchWord $sword, PaperSearch $srch) {
        $value = null;
        $negated = false;
        $word = simplify_whitespace($word);
        if (strcasecmp($word, "any") === 0) {
            $value = true;
        } else if (strcasecmp($word, "none") === 0) {
            $value = true;
            $negated = true;
        } else if ($word === "") {
            $srch->warn("Topic missing.");
            return new False_SearchTerm;
        } else {
            $tam = $srch->conf->topic_abbrev_matcher();
            $value = [];
            $pword = "";
            if (($colon = strpos($word, ":")) !== false) {
                $pword = ltrim(substr($word, $colon + 1));
            }
            if (strcasecmp($pword, "any") === 0
                && ($value = $tam->find_all(substr($word, 0, $colon)))) {
            } else if (strcasecmp($pword, "none") === 0
                       && ($value = $tam->find_all(substr($word, 0, $colon)))) {
                $negated = true;
            } else {
                $value = $tam->find_all($word);
            }
            if (empty($value)) {
                $srch->warn("“" . htmlspecialchars($word) . "” does not match any defined paper topic.");
            }
        }
        return new Topic_SearchTerm($value, $negated);
    }
    function trivial_rights(Contact $user, PaperSearch $srch) {
        return true;
    }
    function sqlexpr(SearchQueryInfo $sqi) {
        $tm = "";
        if ($this->topics === [])
            return "false";
        else if (is_array($this->topics))
            $tm = " and topicId in (" . join(",", $this->topics) . ")";
        $t = "exists (select * from PaperTopic where paperId=Paper.paperId$tm)";
        if ($this->negated)
            $t = "not $t";
        return $t;
    }
    function exec(PaperInfo $row, PaperSearch $srch) {
        if ($this->topics === []) {
            return false;
        } else if ($this->topics === true) {
            $v = $row->has_topics();
        } else {
            $v = !!array_intersect($this->topics, $row->topic_list());
        }
        return $this->negated ? !$v : $v;
    }
    function compile_condition(PaperInfo $row, PaperSearch $srch) {
        $o = (object) ["type" => "topic", "topics" => $this->topics];
        if ($this->negated)
            $o = (object) ["type" => "not", "child" => [$o]];
        return $o;
    }
}
