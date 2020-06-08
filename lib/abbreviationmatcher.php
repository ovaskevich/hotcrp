<?php
// abbreviationmatcher.php -- HotCRP abbreviation matcher helper class
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

// Match priority (higher = more priority):
// 5. Exact match
// 4. Exact match with [-_.–—] replaced by spaces
// 3. Case-insensitive match with [-_.–—] replaced by spaces
// 2. Case-insensitive word match with [-_.–—] replaced by spaces
// 1. Case-insensitive CamelCase match with [-_.–—] replaced by spaces
// If a word match is performed, prefer matches that match more complete words.
// Words must appear in order, so pattern "hello kitty" does not match "kitty
// hello".
// If the pattern has no Unicode characters, these steps are performed against
// the deaccented subject (so subjects “élan” and “elan” match pattern “elan”
// with the same priority). If the pattern has Unicode characters, then exact
// matches take priority over deaccented matches (so subject “élan” is a higher
// priority match for pattern “élan”).

class AbbreviationMatchTracker {
    private $isu;
    private $pattern;
    private $dpattern;
    private $upattern;
    private $dupattern;
    private $imatchre;
    private $is_camel_word;
    private $has_star;
    private $camelwords;
    private $mclass = 1;
    private $matches = [];

    function __construct($pattern, $isu = null) {
        if ($isu === null) {
            $isu = !is_usascii($pattern);
        }
        $this->isu = $isu;
        if ($isu) {
            $this->pattern = UnicodeHelper::normalize($pattern);
            $this->dpattern = AbbreviationMatcher::dedash($this->pattern);
            $this->upattern = UnicodeHelper::deaccent($this->pattern);
            $this->dupattern = AbbreviationMatcher::dedash($this->upattern);
        } else {
            $this->pattern = $this->upattern = $pattern;
            $this->dpattern = $this->dupattern = AbbreviationMatcher::dedash($pattern);
        }
        $this->is_camel_word = AbbreviationMatcher::is_camel_word($pattern);
        $starpos = strpos($pattern, "*");
        if ($starpos === false) {
            $this->has_star = 0;
        } else if ($starpos === 0) {
            $this->has_star = 2;
        } else {
            $this->has_star = 1;
        }
    }
    private function wmatch_score($pattern, $subject, $flags) {
        // assert($pattern whitespace is simplified)
        $pwords = explode(" ", $pattern);
        $swords = preg_split('/\s+/', $subject);
        $pword = "";
        $pword_pos = -1;
        $pword_star = false;
        $ppos = $spos = $demerits = $skipped = 0;
        while (isset($pwords[$ppos]) && isset($swords[$spos])) {
            if ($pword_pos !== $ppos) {
                $pword = '{\A' . preg_quote($pwords[$ppos]) . '([^-\s,.:;\'"\[\]{}()!?&]*).*\z}' . $flags;
                $pword_pos = $ppos;
                if ($this->has_star !== 0
                    && strpos($pwords[$ppos], "*") !== false) {
                    $pword = str_replace('\\*', '.*', $pword);
                    $pword_star = true;
                } else {
                    $pword_star = false;
                }
            }
            if (preg_match($pword, $swords[$spos], $m)) {
                ++$ppos;
                $demerits += $m[1] !== "" || $pword_star;
            } else if ($this->has_star !== 2) {
                $skipped = 1;
            }
            ++$spos;
        }
        // missed words cost 1/64 point, partial words cost 1/64 point
        if (!isset($pwords[$ppos])) {
            if ($skipped || ($this->has_star === 0 && $spos < count($swords))) {
                $demerits += 4;
            }
            //error_log("- $subject $this->pattern $demerits $ppos $spos");
            return 1 - 0.015625 * min($demerits + 1, 63);
        } else {
            return 0;
        }
    }
    private function camel_wmatch_score($subject) {
        assert($this->is_camel_word);
        if (!$this->camelwords) {
            $this->camelwords = [];
            $x = $this->pattern;
            while (preg_match('{\A[-_.]*([a-z]+|[A-Z][a-z]*|[0-9]+)(.*)\z}', $x, $m)) {
                $this->camelwords[] = $m[1];
                $this->camelwords[] = $m[2] !== "" && ctype_alnum(substr($m[2], 0, 1));
                $x = $m[2];
            }
        }
        $swords = preg_split('{\s+}', $subject);
        $ppos = $spos = $demerits = $skipped = 0;
        while (isset($this->camelwords[$ppos]) && isset($swords[$spos])) {
            $pword = $this->camelwords[$ppos];
            $sword = $swords[$spos];
            $ppos1 = $ppos;
            $sidx = 0;
            while ($sidx + strlen($pword) <= strlen($sword)
                   && strcasecmp($pword, substr($sword, $sidx, strlen($pword))) === 0) {
                $sidx += strlen($pword);
                $ppos += 2;
                if (!$this->camelwords[$ppos - 1]) {
                    break;
                }
                $pword = $this->camelwords[$ppos];
            }
            if ($sidx !== 0) {
                $demerits += $sidx < strlen($sword);
            } else {
                ++$skipped;
            }
            ++$spos;
        }
        if (!isset($this->camelwords[$ppos])) {
            if ($skipped || ($this->has_star === 0 && $spos < count($swords))) {
                $demerits += 4;
            }
            //error_log("+ $subject $this->pattern $demerits $ppos $spos");
            return 1 - 0.015625 * min($demerits + 1, 63);
        } else {
            return 0;
        }
    }
    /** @param string $subject
     * @param ?bool $sisu
     * @return int|float */
    private function mclass($subject, $sisu = null) {
        if ($sisu === null) {
            $sisu = !is_usascii($subject);
        }

        if ($this->isu && $sisu) {
            if ($this->pattern === $subject) {
                return 9;
            } else if ($this->mclass >= 9) {
                return 0;
            }

            $dsubject = AbbreviationMatcher::dedash($subject);
            if ($this->dpattern === $dsubject) {
                return 8;
            } else if ($this->mclass >= 7) {
                return 0;
            }

            if (!$this->imatchre) {
                $this->imatchre = '{\A' . preg_quote($this->dpattern) . '\z}iu';
            }
            if (preg_match($this->imatchre, $dsubject)) {
                return 7;
            } else if (($s = $this->wmatch_score($this->dpattern, $dsubject, "iu"))) {
                return 6 + $s;
            }
        }

        if ($this->mclass >= 6) {
            return 0;
        }

        $usubject = $sisu ? UnicodeHelper::deaccent($subject) : $subject;
        if ($this->upattern === $usubject) {
            return 5;
        } else if ($this->mclass >= 5) {
            return 0;
        }

        $dusubject = AbbreviationMatcher::dedash($usubject);
        if ($this->dupattern === $dusubject) {
            return 4;
        } else if ($this->mclass >= 4) {
            return 0;
        }

        if (strcasecmp($this->dupattern, $dusubject) === 0) {
            return 3;
        } else if ($this->mclass >= 3) {
            return 0;
        }

        $s1 = $this->wmatch_score($this->dupattern, $dusubject, "i");
        $s2 = $this->is_camel_word ? $this->camel_wmatch_score($dusubject) : 0;
        if ($s1 || $s2) {
            return 1 + max($s1, $s2);
        } else {
            return 0;
        }
    }

    function check($subject, $data, $sisu = null) {
        $mclass = $this->mclass($subject, $sisu);
        //if ($mclass > 0) error_log("$subject : {$this->pattern} : $mclass");
        if ($mclass > $this->mclass) {
            $this->mclass = $mclass;
            $this->matches = [$data];
        } else if ($mclass == $this->mclass
                   && $this->matches[count($this->matches) - 1] !== $data) {
            $this->matches[] = $data;
        }
    }

    function matches() {
        return $this->matches;
    }
}

class AbbreviationClass {
    const TYPE_CAMELCASE = 0;
    const TYPE_LOWERDASH = 1;
    const TYPE_ASIS = 2;
    public $type;
    public $nwords;
    public $drop_parens = true;
    public $stopwords = "";
    public $tflags = 0;
    public $index = 0;
    public $force = false;

    function __construct($type = self::TYPE_CAMELCASE, $nwords = 3) {
        $this->type = $type;
        $this->nwords = $nwords;
    }
    function step() {
        if ($this->nwords < 3) {
            $this->nwords = 3;
            return true;
        }
        ++$this->index;
        if ($this->index >= 1) {
            $this->drop_parens = false;
        }
        if ($this->index >= 2) {
            $this->stopwords = false;
        }
        if ($this->index > $this->nwords) {
            $this->nwords = $this->index;
        }
        if ($this->type === self::TYPE_ASIS) {
            if ($this->index === 6) {
                $this->nwords = 0;
            }
            return $this->index <= 6;
        } else {
            return $this->index <= 5;
        }
    }
}

/** @template T */
class AbbreviationMatcher {
    /** @var list<array{string,?string,T,int,?string,?list}> */
    private $data = [];
    /** @var int */
    private $nanal = 0;
    /** @var array<string,list<int>> */
    private $matches = [];
    private $abbreviators = [];
    private $prio = [];

    /** @param T $template */
    function __construct($template = null) {
    }

    /** @param string $name
     * @param T $data */
    function add($name, $data, int $tflags = 0) {
        $this->data[] = [$name, null, $data, $tflags];
        $this->matches = [];
    }
    /** @param string $name
     * @param callable(...):T $callback
     * @param list $args */
    function add_lazy($name, $callback, $args, int $tflags = 0) {
        $this->data[] = [$name, null, $this, $tflags, $callback, $args];
        $this->matches = [];
    }
    function set_abbreviator(int $tflags, Abbreviator $abbreviator) {
        $this->abbreviators[$tflags] = $abbreviator;
    }
    function set_priority(int $tflags, float $prio) {
        $this->prio[$tflags] = $prio;
    }

    static function dedash($text) {
        return preg_replace('{(?:[-_.\s]|–|—)+}', " ", $text);
    }
    static function is_camel_word($text) {
        return preg_match('{\A[-_.A-Za-z0-9]*(?:[A-Za-z](?=[-_.A-Z0-9])|[0-9](?=[-_.A-Za-z]))[-_.A-Za-z0-9]*\*?\z}', $text);
    }

    private function _analyze() {
        while ($this->nanal < count($this->data)) {
            $name = $uname = simplify_whitespace($this->data[$this->nanal][0]);
            if (!is_usascii($name)) {
                $name = UnicodeHelper::normalize($name);
                $uname = UnicodeHelper::deaccent($name);
            }
            $this->data[$this->nanal][0] = $name;
            $this->data[$this->nanal][1] = self::dedash($uname);
            ++$this->nanal;
        }
    }

    /** @param int $i
     * @return T */
    private function _resolve($i) {
        $d =& $this->data[$i];
        if ($d[2] === $this) {
            assert($d[4] !== null);
            $d[2] = call_user_func_array($d[4], $d[5]);
        }
        return $d[2];
    }

    private function _find_all($pattern) {
        if (empty($this->matches)) {
            $this->_analyze();
        }
        // A call to Abbreviator::abbreviation_for() might call back in
        // to AbbreviationMatcher::find_all(). Short-circuit that call.
        $this->matches[$pattern] = [];

        $spat = $upat = simplify_whitespace($pattern);
        if (($sisu = !is_usascii($spat))) {
            $spat = UnicodeHelper::normalize($spat);
            $upat = UnicodeHelper::deaccent($spat);
        }
        $dupat = self::dedash($upat);
        if (self::is_camel_word($upat)) {
            $re = preg_replace('{([A-Za-z](?=[A-Z0-9 ])|[0-9](?=[A-Za-z ]))}', '$1(?:|.*\b)', $dupat);
            $re = '{\b' . str_replace(" ", "", $re) . '}i';
        } else {
            $re = join('.*\b', preg_split('{[^A-Za-z0-9*]+}', $dupat));
            $re = '{\b' . str_replace("*", ".*", $re) . '}i';
        }

        $mclass = 0;
        $matches = [];
        foreach ($this->data as $i => $d) {
            if (strcasecmp($dupat, $d[1]) === 0) {
                if ($mclass === 0) {
                    $matches = [];
                }
                $mclass = 1;
                $matches[] = $i;
            } else if ($mclass === 0 && preg_match($re, $d[1])) {
                $matches[] = $i;
            }
        }

        if (count($matches) > 1) {
            $amt = new AbbreviationMatchTracker($spat, $sisu);
            foreach ($matches as $i) {
                $d = $this->data[$i];
                $amt->check($d[0], $i, strlen($d[0]) !== strlen($d[1]));
            }
            $matches = $amt->matches();
        }

        if (empty($matches)) {
            $last_abbreviator = $last_value = null;
            $amt = new AbbreviationMatchTracker($spat, $sisu);
            foreach ($this->data as $i => $d) {
                if ($d[2] === $this) {
                    $d[2] = $this->_resolve($i);
                }
                if ($d[2] instanceof Abbreviator) {
                    $abbreviator = $d[2];
                } else if (isset($this->abbreviators[$d[3]])) {
                    $abbreviator = $this->abbreviators[$d[3]];
                } else {
                    continue;
                }
                if ($last_abbreviator === $abbreviator
                    && $last_value === $d[2]) {
                    continue;
                }
                $last_abbreviator = $abbreviator;
                $last_value = $d[2];
                if (($abbrs = $abbreviator->abbreviations_for($d[0], $d[2]))) {
                    foreach (is_string($abbrs) ? [$abbrs] : $abbrs as $abbr) {
                        $amt->check($abbr, $i);
                    }
                }
            }
            $matches = $amt->matches();
        }

        $this->matches[$pattern] = $matches;
    }

    /** @param string $pattern
     * @return list<T> */
    function find_all($pattern, $tflags = 0) {
        if (!array_key_exists($pattern, $this->matches)) {
            $this->_find_all($pattern);
        }
        $results = [];
        $last = false;
        $prio = $tflags ? ($this->prio[$tflags] ?? false) : false;
        foreach ($this->matches[$pattern] as $i) {
            $d = $this->data[$i];
            $dprio = $this->prio[$d[3]] ?? 0.0;
            if ($prio === false || $dprio > $prio) {
                $results = [];
                $prio = $dprio;
            }
            if ((!$tflags || ($d[3] & $tflags) !== 0) && $prio == $dprio) {
                if ($d[2] === $this) {
                    $d[2] = $this->_resolve($i);
                }
                if (empty($results) || $d[2] !== $last) {
                    $results[] = $last = $d[2];
                }
            }
        }
        return $results;
    }

    /** @param string $pattern
     * @param int $tflags
     * @return ?T */
    function find1($pattern, $tflags = 0) {
        $a = $this->find_all($pattern, $tflags);
        return count($a) === 1 ? $a[0] : null;
    }


    function unique_abbreviation($name, $data, AbbreviationClass $aclass1) {
        $last = null;
        $aclass = $aclass1;
        do {
            $x = self::make_abbreviation($name, $aclass);
            if ($last !== $x) {
                $last = $x;
                $a = $this->find_all($x);
                if (count($a) === 1 && $a[0] === $data) {
                    return $x;
                }
            }
            if ($aclass === $aclass1) {
                $aclass = clone $aclass1;
            }
        } while ($aclass->step());

        if ($aclass1->force) {
            $pfx = self::make_abbreviation($name, $aclass1) . ".";
            $sfx = 1;
            foreach ($this->data as $i => $d) {
                if (!$aclass1->tflags || ($d[3] & $aclass1->tflags) !== 0) {
                    if ($d[2] === $this) {
                        $d[2] = $this->_resolve($i);
                    }
                    if ($d[2] === $data) {
                        return $pfx . $sfx;
                    }
                    if ($d[2] instanceof Abbreviator) {
                        $abbreviator = $d[2];
                    } else if (isset($this->abbreviators[$d[3]])) {
                        $abbreviator = $this->abbreviators[$d[3]];
                    } else {
                        $abbreviator = null;
                    }
                    if ($abbreviator) {
                        $tries = $abbreviator->abbreviations_for($d[0], $d[2]);
                    } else {
                        $tries = self::make_abbreviation($d[0], $aclass1);
                    }
                    foreach (is_string($tries) ? [$tries] : $tries as $s) {
                        if ($s === $pfx . $sfx) {
                            ++$sfx;
                        }
                    }
                }
            }
        }

        return null;
    }

    static function make_abbreviation($name, AbbreviationClass $aclass) {
        $name = str_replace("'", "", $name);
        // try to filter out noninteresting words
        if ($aclass->stopwords !== false) {
            $stopwords = (string) $aclass->stopwords;
            if ($stopwords !== "") {
                $stopwords .= "|";
            }
            $xname = preg_replace('/\b(?:' . $stopwords . 'a|an|and|be|did|do|for|in|of|or|the|their|they|this|to|with|you)\b/i', '', $name);
            $name = $xname ? : $name;
        }
        // drop parenthetical remarks
        if ($aclass->drop_parens) {
            $name = preg_replace('/\(.*?\)|\[.*?\]/', ' ', $name);
        }
        // drop unlikely punctuation
        $xname = preg_replace('/[-:\s+,.?!()\[\]\{\}_\/\"]+/', " ", " $name ");
        // drop extraneous words
        if ($aclass->nwords > 0) {
            $xname = preg_replace('/\A(' . str_repeat(' \S+', $aclass->nwords) . ' ).*\z/', '$1', $xname);
        }
        if ($aclass->type === AbbreviationClass::TYPE_CAMELCASE) {
            $xname = str_replace(" ", "", ucwords($xname));
            if (strlen($xname) < 6 && preg_match('/\A[A-Z][a-z]+\z/', $xname)) {
                return $xname;
            } else {
                return preg_replace('/([A-Z][a-z][a-z])[a-z]*/', '$1', $xname);
            }
        } else if ($aclass->type === AbbreviationClass::TYPE_LOWERDASH) {
            return strtolower(str_replace(" ", "-", trim($xname)));
        } else {
            return $xname;
        }
    }
}
