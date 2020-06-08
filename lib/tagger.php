<?php
// tagger.php -- HotCRP helper class for dealing with tags
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

// Note that tags MUST NOT contain HTML or URL special characters:
// no "'&<>.  If you add PHP-protected characters, such as $, make sure you
// check for uses of eval().

class TagInfo {
    /** @var string */
    public $tag;
    /** @var Conf */
    public $conf;
    /** @var false|string */
    public $pattern = false;
    public $pattern_instance = false;
    public $pattern_version = 0;
    public $is_private = false;
    public $chair = false;
    public $readonly = false;
    public $hidden = false;
    public $track = false;
    public $votish = false;
    public $vote = false;
    public $approval = false;
    public $sitewide = false;
    public $rank = false;
    public $public_peruser = false;
    public $order_anno = false;
    /** @var ?list<TagAnno> */
    private $_order_anno_list;
    /** @var int */
    private $_order_anno_search = 0;
    public $colors;
    public $basic_color = false;
    public $badges;
    public $emoji;
    public $autosearch;
    /** @param string $tag */
    function __construct($tag, TagMap $tagmap) {
        $this->conf = $tagmap->conf;
        $this->set_tag($tag, $tagmap);
    }
    /** @param string $tag */
    function set_tag($tag, TagMap $tagmap) {
        $this->tag = $tag;
        if (($color = $tagmap->known_style($tag))) {
            $this->colors[] = $color;
            $this->basic_color = true;
        }
        if ($tag[0] === "~") {
            if ($tag[1] !== "~") {
                $this->is_private = true;
            } else {
                $this->chair = true;
            }
        }
    }
    function merge(TagInfo $t) {
        foreach (["chair", "readonly", "hidden", "track", "votish", "vote", "approval", "sitewide", "rank", "public_peruser", "autosearch"] as $property) {
            if ($t->$property)
                $this->$property = $t->$property;
        }
        foreach (["colors", "badges", "emoji"] as $property) {
            if ($t->$property)
                $this->$property = array_unique(array_merge($this->$property ? : [], $t->$property));
        }
    }
    function tag_regex() {
        $t = preg_quote($this->tag);
        if ($this->pattern) {
            $t = str_replace("\\*", "[^\\s#]*", $t);
        }
        if ($this->is_private) {
            $t = "\\d*" . $t;
        }
        return $t;
    }
    /** @return list<TagAnno> */
    function order_anno_list() {
        if ($this->_order_anno_list === null) {
            $this->_order_anno_list = [];
            $this->_order_anno_search = 0;
            $result = $this->conf->qe("select * from PaperTagAnno where tag=?", $this->tag);
            while (($ta = TagAnno::fetch($result, $this->conf))) {
                $this->_order_anno_list[] = $ta;
            }
            Dbl::free($result);
            $this->_order_anno_list[] = TagAnno::make_tag_fencepost($this->tag);
            usort($this->_order_anno_list, function ($a, $b) {
                if ($a->tagIndex != $b->tagIndex) {
                    return $a->tagIndex < $b->tagIndex ? -1 : 1;
                } else if (($x = strcasecmp($a->heading, $b->heading)) != 0) {
                    return $x;
                } else {
                    return $a->annoId < $b->annoId ? -1 : 1;
                }
            });
            $last_la = null;
            foreach ($this->_order_anno_list as $i => $la) {
                $la->annoIndex = $i;
                if ($last_la) {
                    $last_la->endTagIndex = $la->tagIndex;
                }
                $last_la = $la;
            }
        }
        return $this->_order_anno_list;
    }
    /** @param int $i
     * @return ?TagAnno */
    function order_anno_entry($i) {
        return ($this->order_anno_list())[$i] ?? null;
    }
    /** @param int|float $tagIndex
     * @return ?TagAnno */
    function order_anno_search($tagIndex) {
        $ol = $this->order_anno_list();
        $i = $this->_order_anno_search;
        if ($i > 0 && $tagIndex < $ol[$i - 1]->tagIndex) {
            $i = 0;
        }
        while ($tagIndex >= $ol[$i]->tagIndex) {
            ++$i;
        }
        $this->_order_anno_search = $i;
        return $i ? $ol[$i - 1] : null;
    }
    /** @return bool */
    function has_order_anno() {
        return count($this->order_anno_list()) > 1;
    }
}

class_alias("TagInfo", "TagMapItem");

class TagAnno implements JsonSerializable {
    public $tag;
    public $annoId;
    public $tagIndex;
    public $heading;
    public $annoFormat;
    public $infoJson;

    public $annoIndex;      // index in array
    public $endTagIndex;    // tagIndex of next anno
    public $pos;
    public $count;

    /** @return bool */
    function is_empty() {
        return $this->heading === null || strcasecmp($this->heading, "none") === 0;
    }
    /** @return bool */
    function is_fencepost() {
        return $this->tagIndex >= (float) TAG_INDEXBOUND;
    }
    /** @return ?TagAnno */
    static function fetch($result, Conf $conf) {
        $ta = $result ? $result->fetch_object("TagAnno") : null;
        '@phan-var ?TagAnno $ta';
        if ($ta) {
            $ta->annoId = (int) $ta->annoId;
            $ta->tagIndex = (float) $ta->tagIndex;
            if ($ta->annoFormat !== null)
                $ta->annoFormat = (int) $ta->annoFormat;
        }
        return $ta;
    }
    /** @return TagAnno */
    static function make_empty() {
        return new TagAnno;
    }
    /** @return TagAnno */
    static function make_heading($h) {
        $ta = new TagAnno;
        $ta->heading = $h;
        return $ta;
    }
    /** @return TagAnno */
    static function make_tag_fencepost($tag) {
        $ta = new TagAnno;
        $ta->tag = $tag;
        $ta->tagIndex = $ta->endTagIndex = (float) TAG_INDEXBOUND;
        $ta->heading = "Untagged";
        return $ta;
    }
    function jsonSerialize() {
        global $Conf;
        $j = [];
        if ($this->pos !== null) {
            $j["pos"] = $this->pos;
        }
        $j["annoid"] = $this->annoId;
        if ($this->tag) {
            $j["tag"] = $this->tag;
        }
        if ($this->tagIndex !== null) {
            $j["tagval"] = $this->tagIndex;
        }
        if ($this->is_empty()) {
            $j["empty"] = true;
        }
        if ($this->heading !== null) {
            $j["heading"] = $this->heading;
        }
        if ($this->heading !== null
            && $this->heading !== ""
            && ($format = $Conf->check_format($this->annoFormat, $this->heading))) {
            $j["format"] = +$format;
        }
        return $j;
    }
}

class TagMap implements IteratorAggregate {
    /** @var Conf */
    public $conf;
    public $has_pattern = false;
    public $has_chair = true;
    public $has_readonly = true;
    public $has_hidden = false;
    public $has_public_peruser = false;
    public $has_votish = false;
    public $has_vote = false;
    public $has_approval = false;
    public $has_sitewide = false;
    public $has_rank = false;
    public $has_colors = false;
    public $has_badges = false;
    public $has_emoji = false;
    public $has_decoration = false;
    public $has_order_anno = false;
    public $has_autosearch = false;
    /** @var array<string,TagInfo> */
    private $storage = array();
    private $sorted = false;
    private $pattern_re;
    /** @var list<TagInfo> */
    private $pattern_storage = [];
    private $pattern_version = 0; // = count($pattern_storage)
    private $color_re;
    private $badge_re;
    private $emoji_re;
    private $hidden_re;
    private $sitewide_re_part;
    private $public_peruser_re_part;

    const STYLE_FG = 1;
    const STYLE_BG = 2;
    const STYLE_FG_BG = 3;
    const STYLE_SYNONYM = 4;
    private $style_info_lmap = [];
    private $canonical_style_lmap = [];
    private $basic_badges;

    private static $emoji_code_map = null;
    private static $multicolor_map = [];

    function __construct(Conf $conf) {
        $this->conf = $conf;

        $basic_colors = "red&|orange&|yellow&|green&|blue&|purple&|violet=purple|gray&|grey=gray|white&|bold|italic|underline|strikethrough|big|small|dim";
        if (($o = $conf->opt("tagBasicColors"))) {
            if (str_starts_with($o, "|")) {
                $basic_colors .= $o;
            } else {
                $basic_colors = $o;
            }
        }
        preg_match_all('/([a-z@_.][-a-z0-9!@_:.\/]*)(\&?)(?:=([a-z@_.][-a-z0-9!@_:.\/]*))?/', strtolower($basic_colors), $ms, PREG_SET_ORDER);
        foreach ($ms as $m) {
            $m[3] = isset($m[3]) ? $m[3] : $m[1];
            while (isset($this->style_info_lmap[$m[3]])
                   && ($this->style_info_lmap[$m[3]] & self::STYLE_SYNONYM)) {
                $m[3] = $this->canonical_style_lmap[$m[3]];
            }
            if ($m[3] !== $m[1] && isset($this->style_info_lmap[$m[3]])) {
                $this->style_info_lmap[$m[1]] = $this->style_info_lmap[$m[3]] | self::STYLE_SYNONYM;
                $this->canonical_style_lmap[$m[1]] = $m[3];
            } else {
                $this->style_info_lmap[$m[1]] = $m[2] ? self::STYLE_BG : self::STYLE_FG;
                $this->canonical_style_lmap[$m[1]] = $m[1];
            }
        }

        $this->basic_badges = "normal|red|orange|yellow|green|blue|purple|white|pink|gray";
        if (($o = $conf->opt("tagBasicBadges"))) {
            if (str_starts_with($o, "|")) {
                $this->basic_badges .= $o;
            } else {
                $this->basic_badges = $o;
            }
        }
    }
    function check_emoji_code($ltag) {
        $len = strlen($ltag);
        if ($len >= 3 && $ltag[0] === ":" && $ltag[$len - 1] === ":") {
            $m = $this->conf->emoji_code_map();
            return $m[substr($ltag, 1, $len - 2)] ?? false;
        } else {
            return false;
        }
    }
    private function update_patterns($tag, $ltag, TagInfo $t = null) {
        if (!$this->pattern_re) {
            $a = [];
            foreach ($this->pattern_storage as $p) {
                $a[] = strtolower($p->tag_regex());
            }
            $this->pattern_re = "{\A(?:" . join("|", $a) . ")\z}";
        }
        if (preg_match($this->pattern_re, $ltag)) {
            $version = $t ? $t->pattern_version : 0;
            foreach ($this->pattern_storage as $i => $p) {
                if ($i >= $version && preg_match($p->pattern, $ltag)) {
                    if (!$t) {
                        $t = clone $p;
                        $t->set_tag($tag, $this);
                        $t->pattern = false;
                        $t->pattern_instance = true;
                        $this->storage[$ltag] = $t;
                        $this->sorted = false;
                    } else {
                        $t->merge($p);
                    }
                }
            }
        }
        if ($t) {
            $t->pattern_version = $this->pattern_version;
        }
        return $t;
    }
    /** @param string $tag
     * @return ?TagInfo */
    function check($tag) {
        $ltag = strtolower($tag);
        $t = $this->storage[$ltag] ?? null;
        if (!$t && $ltag && $ltag[0] === ":" && $this->check_emoji_code($ltag)) {
            $t = $this->add($tag);
        }
        if ($this->has_pattern
            && (!$t || $t->pattern_version < $this->pattern_version)) {
            $t = $this->update_patterns($tag, $ltag, $t);
        }
        return $t;
    }
    /** @param string $tag
     * @return ?TagInfo */
    function check_base($tag) {
        return $this->check(Tagger::base($tag));
    }
    /** @param string $tag
     * @return TagInfo */
    function add($tag) {
        $ltag = strtolower($tag);
        $t = $this->storage[$ltag] ?? null;
        if (!$t) {
            $t = new TagInfo($tag, $this);
            if (!Tagger::basic_check($ltag)) {
                return $t;
            }
            $this->storage[$ltag] = $t;
            $this->sorted = false;
            if ($ltag[0] === ":" && ($e = $this->check_emoji_code($ltag))) {
                $t->emoji[] = $e;
                $this->has_emoji = $this->has_decoration = true;
            }
            if (strpos($ltag, "*") !== false) {
                $t->pattern = "{\A" . strtolower(str_replace("\\*", "[^\\s#]*", $t->tag_regex())) . "\z}";
                $this->has_pattern = true;
                $this->pattern_storage[] = $t;
                $this->pattern_re = null;
                ++$this->pattern_version;
            }
        }
        if ($this->has_pattern
            && !$t->pattern
            && $t->pattern_version < $this->pattern_version) {
            $t = $this->update_patterns($tag, $ltag, $t);
            '@phan-var TagInfo $t';
        }
        return $t;
    }
    private function sort_storage() {
        ksort($this->storage);
        $this->sorted = true;
    }
    function getIterator() {
        $this->sorted || $this->sort_storage();
        return new ArrayIterator($this->storage);
    }
    /** @param string $property
     * @return array<string,TagInfo> */
    function filter($property) {
        $k = "has_{$property}";
        if (!$this->$k) {
            return [];
        }
        $this->sorted || $this->sort_storage();
        return array_filter($this->storage, function ($t) use ($property) { return $t->$property; });
    }
    /** @param callable $f
     * @return array<string,TagInfo> */
    function filter_by($f) {
        $this->sorted || $this->sort_storage();
        return array_filter($this->storage, $f);
    }
    /** @param string $tag
     * @param non-empty-string $property
     * @return ?TagInfo */
    function check_property($tag, $property) {
        $k = "has_{$property}";
        return $this->$k
            && ($t = $this->check(Tagger::base($tag)))
            && $t->$property
            ? $t : null;
    }


    /** @param string $tag */
    function is_chair($tag) {
        if ($tag[0] === "~") {
            return $tag[1] === "~";
        } else {
            return !!$this->check_property($tag, "chair");
        }
    }
    /** @param string $tag */
    function is_readonly($tag) {
        return !!$this->check_property($tag, "readonly");
    }
    /** @param string $tag */
    function is_hidden($tag) {
        return !!$this->check_property($tag, "hidden");
    }
    /** @param string $tag */
    function is_sitewide($tag) {
        return !!$this->check_property($tag, "sitewide");
    }
    /** @param string $tag */
    function is_public_peruser($tag) {
        return !!$this->check_property($tag, "public_peruser");
    }
    /** @param string $tag */
    function is_votish($tag) {
        return !!$this->check_property($tag, "votish");
    }
    /** @param string $tag */
    function is_vote($tag) {
        return !!$this->check_property($tag, "vote");
    }
    /** @param string $tag */
    function is_approval($tag) {
        return !!$this->check_property($tag, "approval");
    }
    /** @param string $tag */
    function votish_base($tag) {
        if (!$this->has_votish
            || ($twiddle = strpos($tag, "~")) === false) {
            return false;
        }
        $tbase = substr(Tagger::base($tag), $twiddle + 1);
        $t = $this->check($tbase);
        return $t && $t->votish ? $tbase : false;
    }
    /** @param string $tag */
    function is_rank($tag) {
        return !!$this->check_property($tag, "rank");
    }
    /** @param string $tag */
    function is_emoji($tag) {
        return !!$this->check_property($tag, "emoji");
    }
    /** @param string $tag */
    function is_autosearch($tag) {
        return !!$this->check_property($tag, "autosearch");
    }


    private function sitewide_regex_part() {
        if ($this->sitewide_re_part === null) {
            $x = [];
            foreach ($this->filter("sitewide") as $t) {
                $x[] = $t->tag_regex() . "#";
            }
            $this->sitewide_re_part = join("|", $x);
        }
        return $this->sitewide_re_part;
    }

    private function hidden_regex_part() {
        if ($this->hidden_re === null) {
            $x = [];
            foreach ($this->filter("hidden") as $t) {
                $x[] = $t->tag_regex() . "#";
            }
            $this->hidden_re = join("|", $x);
        }
        return $this->hidden_re;
    }

    private function public_peruser_regex_part() {
        if ($this->public_peruser_re_part === null) {
            $x = [];
            foreach ($this->filter("public_peruser") as $t) {
                $x[] = '\d+~' . $t->tag_regex() . "#";
            }
            $this->public_peruser_re_part = join("|", $x);
        }
        return $this->public_peruser_re_part;
    }


    function known_styles() {
        return array_keys($this->style_info_lmap);
    }
    function known_style($tag) {
        return $this->canonical_style_lmap[strtolower($tag)] ?? false;
    }
    function is_known_style($tag, $match = self::STYLE_FG_BG) {
        return (($this->style_info_lmap[strtolower($tag)] ?? 0) & $match) !== 0;
    }
    function is_style($tag, $match = self::STYLE_FG_BG) {
        $ltag = strtolower($tag);
        if (($t = $this->check($ltag))) {
            foreach ($t->colors ? : [] as $k) {
                if ($this->style_info_lmap[$k] & $match)
                    return true;
            }
            return false;
        } else {
            return (($this->style_info_lmap[$ltag] ?? 0) & $match) !== 0;
        }
    }

    function color_regex() {
        if (!$this->color_re) {
            $re = "{(?:\\A| )(?:\\d*~|~~|)(" . join("|", array_keys($this->style_info_lmap));
            foreach ($this->filter("colors") as $t)
                $re .= "|" . $t->tag_regex();
            $this->color_re = $re . ")(?=\\z|[# ])}i";
        }
        return $this->color_re;
    }

    function styles($tags, $match = 0, $no_pattern_fill = false) {
        if (is_array($tags)) {
            $tags = join(" ", $tags);
        }
        if (!$tags
            || $tags === " "
            || !preg_match_all($this->color_regex(), $tags, $m)) {
            return null;
        }
        $classes = [];
        $info = 0;
        foreach ($m[1] as $tag) {
            $ltag = strtolower($tag);
            $t = $this->check($ltag);
            $ks = $t ? $t->colors : [$ltag];
            foreach ($ks as $k) {
                if ($match === 0 || ($this->style_info_lmap[$k] & $match)) {
                    $classes[] = $this->canonical_style_lmap[$k] . "tag";
                    $info |= $this->style_info_lmap[$k];
                }
            }
        }
        if (empty($classes)) {
            return null;
        }
        if (count($classes) > 1) {
            sort($classes);
            $classes = array_unique($classes);
        }
        if ($info & self::STYLE_BG) {
            $classes[] = "tagbg";
        }
        // This seems out of place---it's redundant if we're going to
        // generate JSON, for example---but it is convenient.
        if (!$no_pattern_fill
            && count($classes) > ($info & self::STYLE_BG ? 2 : 1)) {
            self::mark_pattern_fill($classes);
        }
        return $classes;
    }

    static function mark_pattern_fill($classes) {
        $key = is_array($classes) ? join(" ", $classes) : $classes;
        if (!isset(self::$multicolor_map[$key]) && strpos($key, " ") !== false) {
            Ht::stash_script("make_pattern_fill(" . json_encode_browser($key) . ")");
            self::$multicolor_map[$key] = true;
        }
    }

    function color_classes($tags, $no_pattern_fill = false) {
        $s = $this->styles($tags, 0, $no_pattern_fill);
        return $s ? join(" ", $s) : "";
    }

    function canonical_colors() {
        $colors = [];
        foreach ($this->canonical_style_lmap as $ltag => $canon_ltag) {
            if ($ltag === $canon_ltag)
                $colors[] = $ltag;
        }
        return $colors;
    }


    function badge_regex() {
        if (!$this->badge_re) {
            $re = "{(?:\\A| )(?:\\d*~|)(";
            foreach ($this->filter("badges") as $t)
                $re .= $t->tag_regex() . "|";
            $this->badge_re = substr($re, 0, -1) . ")(?:#[-\\d.]+)?(?=\\z| )}i";
        }
        return $this->badge_re;
    }

    function canonical_badges() {
        return explode("|", $this->basic_badges);
    }

    function emoji_regex() {
        if (!$this->badge_re) {
            $re = "{(?:\\A| )(?:\\d*~|~~|)(:\\S+:";
            foreach ($this->filter("emoji") as $t) {
                $re .= "|" . $t->tag_regex();
            }
            $this->emoji_re = $re . ")(?:#[\\d.]+)?(?=\\z| )}i";
        }
        return $this->emoji_re;
    }


    static function is_tag_string($s, $strict = false) {
        return (string) $s === ""
            || preg_match($strict ? '/\A(?: [^#\s]+#-?[\d.]+)+\z/' : '/\A(?: \S+)+\z/', $s);
    }

    static function assert_tag_string($tags, $strict = false) {
        if (!self::is_tag_string($tags, $strict)) {
            trigger_error("Bad tag string $tags");
            error_log(json_encode(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS)));
        }
    }

    /** @param ?string $tags */
    private function strip_nonsearchable($tags, Contact $user, PaperInfo $prow = null) {
        // Prerequisite: self::assert_tag_string($tags, true);
        if ($tags !== null
            && $tags !== ""
            && (!$prow || !$user->allow_administer($prow))
            && ($this->has_hidden || strpos($tags, "~") !== false)) {
            $re = "(?:";
            if ($user->contactId > 0) {
                $re .= "(?!" . $user->contactId . "~)";
            }
            if ($this->has_public_peruser) {
                $re .= "(?!" . $this->public_peruser_regex_part() . ")";
            }
            $re .= "\\d+~";
            if (!$user->privChair) {
                $re .= "|~";
            }
            if ($this->has_hidden && !$user->can_view_hidden_tags($prow)) {
                $re .= "|" . $this->hidden_regex_part();
            }
            $re .= ")\\S+";
            $tags = preg_replace("{ " . $re . "}i", "", $tags);
        }
        return $tags;
    }

    /** @param ?string $tags */
    private function strip_nonviewable($tags, Contact $user, PaperInfo $prow = null) {
        // Prerequisite: self::assert_tag_string($tags, true);
        if ($tags !== null
            && $tags !== ""
            && ($this->has_hidden || strpos($tags, "~") !== false)) {
            $re = "(?:";
            if ($user->contactId > 0) {
                $re .= "(?!" . $user->contactId . "~)";
            }
            $re .= "\\d+~";
            if (!$user->privChair) {
                $re .= "|~";
            }
            if ($this->has_hidden
                && ($prow ? !$user->can_view_hidden_tags($prow) : !$user->privChair)) {
                $re .= "|" . $this->hidden_regex_part();
            }
            $re .= ")\\S+";
            if ($tags[0] !== " ") { // XXX remove this
                $tags = " " . $tags;
            }
            $tags = preg_replace("{ " . $re . "}i", "", $tags);
        }
        return $tags;
    }

    private function strip_nonviewable_chair_conflict($tags, Contact $user) {
        // XXX Should called only if `!can_view_most_tags && can_view_tags`.
        // Prerequisite: self::assert_tag_string($tags, true);
        $chair = $user->privChair ? "" : "|~";
        return preg_replace('{ (?:(?!' . $user->contactId . '~)\d+~'
            . $chair . '|(?!' . $this->sitewide_regex_part() . '))\S*}', "", $tags);
    }

    const CENSOR_SEARCH = 0;
    const CENSOR_VIEW = 1;
    function censor($ctype, $tags, Contact $user, PaperInfo $prow = null) {
        if ((string) $tags === "") {
            return "";
        } else if ($user->can_view_most_tags($prow)) {
            if ($ctype) {
                return $this->strip_nonviewable($tags, $user, $prow);
            } else {
                return $this->strip_nonsearchable($tags, $user, $prow);
            }
        } else if ($user->privChair && $this->has_sitewide) {
            return $this->strip_nonviewable_chair_conflict($tags, $user);
        } else {
            return "";
        }
    }

    /** @param list<string> $tags
     * @return list<string> */
    function sort_array($tags) {
        if (count($tags) > 1) {
            $this->conf->collator()->sort($tags);
        }
        return $tags;
    }

    /** @param string $tags
     * @return string */
    function sort_string($tags) {
        if ($tags !== "") {
            // XXX remove assert_tag_string
            self::assert_tag_string($tags);
            $tags = join(" ", $this->sort_array(explode(" ", $tags)));
        }
        return $tags;
    }

    const UNPARSE_HASH = 1;
    const UNPARSE_TEXT = 2;
    function unparse($tag, $value, Contact $viewer, $flags = 0) {
        $prefix = "";
        $suffix = $value ? "#$value" : "";
        $hash = ($flags & self::UNPARSE_HASH ? "#" : "");
        if (($twiddle = strpos($tag, "~")) > 0) {
            $cid = (int) substr($tag, 0, $twiddle);
            if ($cid !== 0 && $cid === $viewer->contactId) {
                $tag = substr($tag, $twiddle);
            } else if (($p = $viewer->conf->cached_user_by_id($cid))) {
                if ($flags & self::UNPARSE_TEXT) {
                    return $hash . $p->email . substr($tag, $twiddle) . $suffix;
                }
                if (($cc = $p->viewable_color_classes($viewer))) {
                    $prefix = $hash . "<span class=\"" . $cc
                        . " taghh\">" . htmlspecialchars($p->email) . "</span>";
                    $hash = "";
                } else {
                    $hash .= htmlspecialchars($p->email);
                }
                $tag = substr($tag, $twiddle);
            }
        }
        if (($flags & self::UNPARSE_TEXT)
            || !($cc = $this->styles($tag))) {
            return $prefix . $hash . $tag . $suffix;
        } else {
            return $prefix . "<span class=\""  . join(" ", $cc)
                . " taghh\">" . $hash . $tag . $suffix . "</span>";
        }
    }


    static function make(Conf $conf) {
        $map = new TagMap($conf);
        $ct = $conf->setting_data("tag_chair") ?? "";
        foreach (Tagger::split_unpack($ct) as $ti) {
            $t = $map->add($ti[0]);
            $t->chair = $t->readonly = true;
        }
        foreach ($conf->track_tags() as $tn) {
            $t = $map->add(Tagger::base($tn));
            $t->chair = $t->readonly = $t->track = true;
        }
        $ct = $conf->setting_data("tag_hidden") ?? "";
        foreach (Tagger::split_unpack($ct) as $ti) {
            $map->add($ti[0])->hidden = $map->has_hidden = true;
        }
        $ct = $conf->setting_data("tag_sitewide") ?? "";
        foreach (Tagger::split_unpack($ct) as $ti) {
            $map->add($ti[0])->sitewide = $map->has_sitewide = true;
        }
        $ppu = $conf->setting("tag_vote_private_peruser")
            || $conf->opt("secretPC");
        $vt = $conf->setting_data("tag_vote") ?? "";
        foreach (Tagger::split_unpack($vt) as $ti) {
            $t = $map->add($ti[0]);
            $t->vote = ($ti[1] ? : 1);
            $map->has_vote = true;
            $t->votish = $map->has_votish = true;
            if (!$ppu) {
                $t->public_peruser = $map->has_public_peruser = true;
            }
        }
        $vt = $conf->setting_data("tag_approval") ?? "";
        foreach (Tagger::split_unpack($vt) as $ti) {
            $t = $map->add($ti[0]);
            $t->approval = $map->has_approval = true;
            $t->votish = $map->has_votish = true;
            if (!$ppu) {
                $t->public_peruser = $map->has_public_peruser = true;
            }
        }
        $rt = $conf->setting_data("tag_rank") ?? "";
        foreach (Tagger::split_unpack($rt) as $ti) {
            $t = $map->add($ti[0]);
            $t->rank = $map->has_rank = true;
            if (!$ppu) {
                $t->public_peruser = $map->has_public_peruser = true;
            }
        }
        $ct = $conf->setting_data("tag_color") ?? "";
        if ($ct !== "") {
            foreach (explode(" ", $ct) as $k) {
                if ($k !== "" && ($p = strpos($k, "=")) !== false
                    && ($kk = $map->known_style(substr($k, $p + 1)))) {
                    $map->add(substr($k, 0, $p))->colors[] = $kk;
                    $map->has_colors = true;
                }
            }
        }
        $bt = $conf->setting_data("tag_badge") ?? "";
        if ($bt !== "") {
            foreach (explode(" ", $bt) as $k) {
                if ($k !== "" && ($p = strpos($k, "=")) !== false) {
                    $map->add(substr($k, 0, $p))->badges[] = substr($k, $p + 1);
                    $map->has_badges = true;
                }
            }
        }
        $bt = $conf->setting_data("tag_emoji") ?? "";
        if ($bt !== "") {
            foreach (explode(" ", $bt) as $k) {
                if ($k !== "" && ($p = strpos($k, "=")) !== false) {
                    $map->add(substr($k, 0, $p))->emoji[] = substr($k, $p + 1);
                    $map->has_emoji = true;
                }
            }
        }
        $tx = $conf->setting_data("tag_autosearch") ?? "";
        if ($tx !== "") {
            foreach (json_decode($tx) ? : [] as $tag => $search) {
                $map->add($tag)->autosearch = $search->q;
                $map->has_autosearch = true;
            }
        }
        if (($od = $conf->opt("definedTags"))) {
            foreach (is_string($od) ? [$od] : $od as $ods) {
                foreach (json_decode($ods) as $tag => $data) {
                    $t = $map->add($tag);
                    if ($data->chair ?? false) {
                        $t->chair = $t->readonly = true;
                    }
                    if ($data->readonly ?? false) {
                        $t->readonly = true;
                    }
                    if ($data->hidden ?? false) {
                        $t->hidden = $map->has_hidden = true;
                    }
                    if ($data->sitewide ?? false) {
                        $t->sitewide = $map->has_sitewide = true;
                    }
                    if (($x = $data->autosearch ?? null)) {
                        $t->autosearch = $x;
                        $map->has_autosearch = true;
                    }
                    if (($x = $data->color ?? null)) {
                        foreach (is_string($x) ? [$x] : $x as $c) {
                            if (($kk = $map->known_style($c))) {
                                $t->colors[] = $kk;
                                $map->has_colors = true;
                            }
                        }
                    }
                    if (($x = $data->badge ?? null)) {
                        foreach (is_string($x) ? [$x] : $x as $c) {
                            $t->badges[] = $c;
                            $map->has_badges = true;
                        }
                    }
                    if (($x = $data->emoji ?? null)) {
                        foreach (is_string($x) ? [$x] : $x as $c) {
                            $t->emoji[] = $c;
                            $map->has_emoji = true;
                        }
                    }
                }
            }
        }
        if ($map->has_badges || $map->has_emoji || $conf->setting("has_colontag")) {
            $map->has_decoration = true;
        }
        return $map;
    }
}

class Tagger {
    const ALLOWRESERVED = 1;
    const NOPRIVATE = 2;
    const NOVALUE = 4;
    const NOCHAIR = 8;
    const ALLOWSTAR = 16;
    const ALLOWCONTACTID = 32;
    const NOTAGKEYWORD = 64;

    public $error_html = false;
    /** @var Conf */
    private $conf;
    /** @var Contact */
    private $contact;
    /** @var int */
    private $_contactId = 0;

    private static $value_increment_map = array(1, 1, 1, 1, 1, 2, 2, 2, 3, 4);


    function __construct(Contact $contact) {
        $this->conf = $contact->conf;
        $this->contact = $contact;
        if ($contact->contactId > 0) {
            $this->_contactId = $contact->contactId;
        }
    }


    /** @param string $tag
     * @return string */
    static function base($tag) {
        if (($pos = strpos($tag, "#")) > 0
            || ($pos = strpos($tag, "=")) > 0) {
            return substr($tag, 0, $pos);
        } else {
            return $tag;
        }
    }

    /** @param string $tag
     * @return array{false|string,false|float} */
    static function unpack($tag) {
        if (!$tag) {
            return [false, false];
        } else if (!($pos = strpos($tag, "#")) && !($pos = strpos($tag, "="))) {
            return [$tag, false];
        } else if ($pos === strlen($tag) - 1) {
            return [substr($tag, 0, $pos), false];
        } else {
            return [substr($tag, 0, $pos), (float) substr($tag, $pos + 1)];
        }
    }

    /** @param string $taglist
     * @return list<string> */
    static function split($taglist) {
        preg_match_all('/\S+/', $taglist, $m);
        return $m[0];
    }

    /** @param string $taglist
     * @return list<array{false|string,false|float}> */
    static function split_unpack($taglist) {
        return array_map("Tagger::unpack", self::split($taglist));
    }

    /** @param string $tag
     * @return bool */
    static function basic_check($tag) {
        return $tag !== "" && strlen($tag) <= TAG_MAXLEN
            && preg_match('{\A' . TAG_REGEX . '\z}', $tag);
    }

    /** @param bool $sequential */
    static function value_increment($sequential) {
        return $sequential ? 1 : self::$value_increment_map[mt_rand(0, 9)];
    }

    /** @param array{int,float} $a
     * @param array{int,float} $b */
    static function id_index_compar($a, $b) {
        if ($a[1] != $b[1]) {
            return $a[1] < $b[1] ? -1 : 1;
        } else {
            return $a[0] - $b[0];
        }
    }


    /** @return false */
    private function set_error_html($e) {
        $this->error_html = $e;
        return false;
    }

    /** @param ?string $tag
     * @param int $flags
     * @return string|false */
    function check($tag, $flags = 0) {
        if ($tag === null || $tag === "" || $tag === "#") {
            return $this->set_error_html("Tag missing.");
        }
        if (!$this->contact->privChair) {
            $flags |= self::NOCHAIR;
        }
        if ($tag[0] === "#") {
            $tag = substr($tag, 1);
        }
        if (!preg_match('/\A(|~|~~|[1-9][0-9]*~)(' . TAG_REGEX_NOTWIDDLE . ')(|[#=](?:-?\d+(?:\.\d*)?|-?\.\d+|))\z/', $tag, $m)) {
            if (preg_match('/\A([-a-zA-Z0-9!@*_:.\/#=]+)[\s,]+\S+/', $tag, $m)
                && $this->check($m[1], $flags)) {
                return $this->set_error_html("Expected a single tag.");
            } else {
                return $this->set_error_html("Invalid tag.");
            }
        }
        if (!($flags & self::ALLOWSTAR) && strpos($tag, "*") !== false) {
            return $this->set_error_html("Wildcards aren’t allowed here.");
        }
        // After this point we know `$tag` contains no HTML specials
        if ($m[1] === "") {
            // OK
        } else if ($m[1] === "~~") {
            if ($flags & self::NOCHAIR) {
                return $this->set_error_html("Tag #{$tag} is exclusively for chairs.");
            }
        } else {
            if ($flags & self::NOPRIVATE) {
                return $this->set_error_html("Twiddle tags aren’t allowed here.");
            } else if ($m[1] === "~") {
                if ($this->_contactId) {
                    $m[1] = $this->_contactId . "~";
                }
            } else if ($m[1] !== $this->_contactId . "~"
                       && !($flags & self::ALLOWCONTACTID)) {
                return $this->set_error_html("Other users’ twiddle tags are off limits.");
            }
        }
        if ($m[3] !== "" && ($flags & self::NOVALUE)) {
            return $this->set_error_html("Tag values aren’t allowed here.");
        }
        if (!($flags & self::ALLOWRESERVED)
            && (!strcasecmp("none", $m[2]) || !strcasecmp("any", $m[2]))) {
            return $this->set_error_html("Tag #{$m[2]} is reserved.");
        }
        $t = $m[1] . $m[2];
        if (strlen($t) > TAG_MAXLEN) {
            return $this->set_error_html("Tag #{$tag} is too long.");
        }
        if ($m[3] !== "") {
            $t .= "#" . substr($m[3], 1);
        }
        return $t;
    }

    function expand($tag) {
        if (strlen($tag) > 2 && $tag[0] === "~" && $tag[1] !== "~" && $this->_contactId) {
            return $this->_contactId . $tag;
        } else {
            return $tag;
        }
    }

    static function check_tag_keyword($text, Contact $user, $flags = 0) {
        $re = '/\A(?:#|tagval:\s*'
            . ($flags & self::NOTAGKEYWORD ? '' : '|tag:\s*')
            . ')(\S+)\z/i';
        if (preg_match($re, $text, $m)) {
            $tagger = new Tagger($user);
            return $tagger->check($m[1], $flags);
        } else {
            return false;
        }
    }

    function view_score($tag) {
        if ($tag === false) {
            return VIEWSCORE_EMPTY;
        } else if (($pos = strpos($tag, "~")) !== false) {
            if (($pos == 0 && $tag[1] === "~")
                || substr($tag, 0, $pos) != $this->_contactId) {
                return VIEWSCORE_ADMINONLY;
            } else {
                return VIEWSCORE_REVIEWERONLY;
            }
        } else {
            return VIEWSCORE_PC;
        }
    }


    function unparse($tags) {
        if ($tags === "" || (is_array($tags) && count($tags) == 0)) {
            return "";
        }
        if (is_array($tags)) {
            $tags = join(" ", $tags);
        }
        $tags = str_replace("#0 ", " ", " $tags ");
        if ($this->_contactId) {
            $tags = str_replace(" " . $this->_contactId . "~", " ~", $tags);
        }
        return trim($tags);
    }

    function unparse_hashed($tags) {
        if (($tags = $this->unparse($tags)) !== "") {
            $tags = str_replace(" ", " #", "#" . $tags);
        }
        return $tags;
    }

    static function unparse_emoji_html($e, $count) {
        $b = '<span class="tagemoji">';
        if ($count == 0 || $count == 1) {
            $b .= $e;
        } else if ($count >= 5.0625) {
            $b .= str_repeat($e, 5) . "<sup>+</sup>";
        } else {
            $f = floor($count + 0.0625);
            $d = round(max($count - $f, 0) * 8);
            $b .= str_repeat($e, (int) $f);
            if ($d) {
                $b .= '<span style="display:inline-block;overflow-x:hidden;vertical-align:bottom;position:relative;bottom:0;width:' . ($d / 8) . 'em">' . $e . '</span>';
            }
        }
        return $b . '</span>';
    }

    const DECOR_PAPER = 0;
    const DECOR_USER = 1;
    function unparse_decoration_html($tags, $type = 0) {
        if (is_array($tags)) {
            $tags = join(" ", $tags);
        }
        if (!$tags || $tags === " ") {
            return "";
        }
        $dt = $this->conf->tags();
        $x = "";
        if ($dt->has_decoration
            && preg_match_all($dt->emoji_regex(), $tags, $m, PREG_SET_ORDER)) {
            $emoji = [];
            foreach ($m as $mx) {
                if (($t = $dt->check($mx[1])) && $t->emoji) {
                    foreach ($t->emoji as $e)
                        $emoji[$e][] = ltrim($mx[0]);
                }
            }
            foreach ($emoji as $e => $ts) {
                $links = [];
                $count = 0;
                foreach ($ts as $t) {
                    if (($link = $this->link_base($t)))
                        $links[] = "#" . $link;
                    list($base, $value) = Tagger::unpack($t);
                    $count = max($count, (float) $value);
                }
                $b = self::unparse_emoji_html($e, $count);
                if ($type === self::DECOR_PAPER && !empty($links)) {
                    $b = '<a class="qq" href="' . $this->conf->hoturl("search", ["q" => join(" OR ", $links)]) . '">' . $b . '</a>';
                }
                if ($x === "") {
                    $x = " ";
                }
                $x .= $b;
            }
        }
        if ($dt->has_badges
            && preg_match_all($dt->badge_regex(), $tags, $m, PREG_SET_ORDER)) {
            foreach ($m as $mx) {
                if (($t = $dt->check($mx[1])) && $t->badges) {
                    $klass = ' class="badge ' . $t->badges[0] . 'badge"';
                    $tag = $this->unparse(trim($mx[0]));
                    if ($type === self::DECOR_PAPER && ($link = $this->link($tag))) {
                        $b = '<a href="' . $link . '"' . $klass . '>#' . $tag . '</a>';
                    } else {
                        if ($type !== self::DECOR_USER) {
                            $tag = '#' . $tag;
                        }
                        $b = '<span' . $klass . '>' . $tag . '</span>';
                    }
                    $x .= ' ' . $b;
                }
            }
        }
        return $x === "" ? "" : '<span class="tagdecoration">' . $x . '</span>';
    }

    function link_base($tag) {
        if (ctype_digit($tag[0])) {
            $p = strlen((string) $this->_contactId);
            if (substr($tag, 0, $p) != $this->_contactId || $tag[$p] !== "~") {
                return false;
            }
            $tag = substr($tag, $p);
        }
        return Tagger::base($tag);
    }

    function link($tag) {
        if (ctype_digit($tag[0])) {
            $p = strlen((string) $this->_contactId);
            if (substr($tag, 0, $p) != $this->_contactId || $tag[$p] !== "~") {
                return false;
            }
            $tag = substr($tag, $p);
        }
        $base = Tagger::base($tag);
        $dt = $this->conf->tags();
        if ($dt->has_votish
            && ($dt->is_votish($base)
                || ($base[0] === "~" && $dt->is_vote(substr($base, 1))))) {
            $q = "#$base showsort:-#$base";
        } else if ($base === $tag) {
            $q = "#$base";
        } else {
            $q = "order:#$base";
        }
        return $this->conf->hoturl("search", ["q" => $q]);
    }

    function unparse_link($viewable) {
        $tags = $this->unparse($viewable);
        if ($tags === "") {
            return "";
        }

        // decorate with URL matches
        $dt = $this->conf->tags();
        $tt = "";
        foreach (preg_split('/\s+/', $tags) as $tag) {
            if (!($base = Tagger::base($tag))) {
                continue;
            }
            $lbase = strtolower($base);
            if (($link = $this->link($tag))) {
                $tx = '<a class="nn pw" href="' . $link . '"><u class="x">#'
                    . $base . '</u>' . substr($tag, strlen($base)) . '</a>';
            } else {
                $tx = "#" . $tag;
            }
            if (($cc = $dt->styles($base))) {
                $tx = '<span class="' . join(" ", $cc) . ' taghh">' . $tx . '</span>';
            }
            $tt .= $tx . " ";
        }
        return rtrim($tt);
    }
}
