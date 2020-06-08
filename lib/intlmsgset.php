<?php
// intlmsg.php -- HotCRP helper functions for message i18n
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class IntlMsg {
    public $context;
    public $otext;
    public $require;
    public $priority = 0.0;
    public $format;
    public $no_conversions;
    public $template;
    public $next;

    private function resolve_arg(IntlMsgSet $ms, $args, $argname, &$val) {
        $component = false;
        if (strpos($argname, "[") !== false
            && preg_match('/\A(.*?)\[([^\]]*)\]\z/', $argname, $m)) {
            $argname = $m[1];
            $component = $m[2];
        }
        if ($argname[0] === "\$") {
            $which = substr($argname, 1);
            if (ctype_digit($which)) {
                $val = $args[+$which] ?? null;
            } else {
                return false;
            }
        } else if (($ans = $ms->resolve_requirement_argument($argname))) {
            $val = is_array($ans) ? $ans[0] : $ans;
        } else {
            return false;
        }
        if ($component !== false) {
            if (is_array($val)) {
                $val = $val[$component] ?? null;
            } else if (is_object($val)) {
                $val = $val->$component ?? null;
            } else {
                return false;
            }
        }
        return true;
    }
    function check_require(IntlMsgSet $ms, $args) {
        if (!$this->require) {
            return 0;
        }
        $nreq = 0;
        foreach ($this->require as $req) {
            if (preg_match('/\A\s*(!*)\s*(\S+?)\s*(\z|[=!<>]=?|≠|≤|≥|!?\^=)\s*(\S*)\s*\z/', $req, $m)
                && ($m[1] === "" || ($m[3] === "" && $m[4] === ""))
                && ($m[3] === "") === ($m[4] === "")) {
                if (!$this->resolve_arg($ms, $args, $m[2], $val)) {
                    return false;
                }
                $compar = $m[3];
                $compval = $m[4];
                if ($compar === "") {
                    $bval = (bool) $val && $val !== "0";
                    $weight = $bval === (strlen($m[1]) % 2 === 0) ? 1 : 0;
                } else if (!is_scalar($val)) {
                    $weight = 0;
                } else if ($compar === "^=") {
                    $weight = str_starts_with($val, $compval) ? 0.9 : 0;
                } else if ($compar === "!^=") {
                    $weight = !str_starts_with($val, $compval) ? 0.9 : 0;
                } else if (is_numeric($compval)) {
                    $weight = CountMatcher::compare((float) $val, $compar, (float) $compval) ? 1 : 0;
                } else if ($compar === "=" || $compar === "==") {
                    $weight = (string) $val === (string) $compval ? 1 : 0;
                } else if ($compar === "!=" || $compar === "≠") {
                    $weight = (string) $val === (string) $compval ? 0 : 1;
                } else {
                    $weight = 0;
                }
                if ($weight === 0) {
                    return false;
                }
                $nreq += $weight;
            } else if (($weight = $ms->resolve_requirement($req)) !== null) {
                if ($weight <= 0) {
                    return false;
                }
                $nreq += $weight;
            }
        }
        return $nreq;
    }
}

class IntlMsgSet {
    private $ims = [];
    private $require_resolvers = [];
    private $_ctx;
    private $_default_priority;

    const PRIO_OVERRIDE = 1000.0;

    function set_default_priority($p) {
        $this->_default_priority = (float) $p;
    }
    function clear_default_priority() {
        $this->_default_priority = null;
    }

    function add($m, $ctx = null) {
        if (is_string($m)) {
            $x = $this->addj(func_get_args());
        } else if (!$ctx) {
            $x = $this->addj($m);
        } else {
            $octx = $this->_ctx;
            $this->_ctx = $ctx;
            $x = $this->addj($m);
            $this->_ctx = $octx;
        }
        return $x;
    }

    /** @param object $m
     * @return bool */
    private function _addj_object($m) {
        if (isset($m->members) && is_array($m->members)) {
            $octx = $this->_ctx;
            if (isset($m->context) && is_string($m->context)) {
                $this->_ctx = ((string) $this->_ctx === "" ? "" : $this->_ctx . "/") . $m->context;
            }
            $ret = true;
            foreach ($m->members as $mm) {
                $ret = $this->addj($mm) && $ret;
            }
            $this->_ctx = $octx;
            return $ret;
        } else {
            $im = new IntlMsg;
            if (isset($m->context) && is_string($m->context)) {
                $im->context = $m->context;
            }
            if (isset($m->id) && is_string($m->id)) {
                $itext = $m->id;
            } else if (isset($m->itext) && is_string($m->itext)) {
                $itext = $m->itext;
            } else {
                return false;
            }
            if (isset($m->otext) && is_string($m->otext)) {
                $im->otext = $m->otext;
            } else if (isset($m->itext) && is_string($m->itext)) {
                $im->otext = $m->itext;
            } else {
                return false;
            }
            if (isset($m->priority) && (is_float($m->priority) || is_int($m->priority))) {
                $im->priority = (float) $m->priority;
            }
            if (isset($m->require) && is_array($m->require)) {
                $im->require = $m->require;
            }
            if (isset($m->format) && (is_int($m->format) || is_string($m->format))) {
                $im->format = $m->format;
            }
            if (isset($m->no_conversions) && is_bool($m->no_conversions)) {
                $im->no_conversions = $m->no_conversions;
            }
            if (isset($m->template) && is_bool($m->template)) {
                $im->template = $m->template;
            }
            $this->_addj_finish($itext, $im);
            return true;
        }
    }

    /** @param array{string,string} $m */
    private function _addj_list($m) {
        $im = new IntlMsg;
        $n = count($m);
        $p = false;
        while ($n > 0 && !is_string($m[$n - 1])) {
            if ((is_int($m[$n - 1]) || is_float($m[$n - 1])) && $p === false) {
                $p = $im->priority = (float) $m[$n - 1];
            } else if (is_array($m[$n - 1]) && $im->require === null) {
                $im->require = $m[$n - 1];
            } else {
                return false;
            }
            --$n;
        }
        if ($n < 2 || $n > 3 || !is_string($m[0]) || !is_string($m[1])
            || ($n === 3 && !is_string($m[2]))) {
            return false;
        }
        if ($n === 3) {
            $im->context = $m[0];
            $itext = $m[1];
            $im->otext = $m[2];
        } else {
            $itext = $m[0];
            $im->otext = $m[1];
        }
        $this->_addj_finish($itext, $im);
        return true;
    }

    /** @param string $itext
     * @param IntlMsg $im */
    private function _addj_finish($itext, $im) {
        if ($this->_ctx) {
            $im->context = $this->_ctx . ($im->context ? "/" . $im->context : "");
        }
        if ($im->priority === null && $this->_default_priority !== null) {
            $im->priority = $this->_default_priority;
        }
        $im->next = $this->ims[$itext] ?? null;
        $this->ims[$itext] = $im;
    }

    /** @param array{string,string}|array{string,string,int}|object|array<string,mixed> $m */
    function addj($m) {
        if (is_associative_array($m)) {
            return $this->_addj_object((object) $m);
        } else if (is_array($m)) {
            return $this->_addj_list($m);
        } else if (is_object($m)) {
            return $this->_addj_object($m);
        } else  {
            return false;
        }
    }

    /** @param string $id
     * @param string $otext */
    function add_override($id, $otext) {
        $im = $this->ims[$id] ?? null;
        return $this->addj(["id" => $id, "otext" => $otext, "priority" => self::PRIO_OVERRIDE, "no_conversions" => true, "template" => $im && $im->template]);
    }

    function add_requirement_resolver($function) {
        $this->require_resolvers[] = $function;
    }
    function resolve_requirement($requirement) {
        foreach ($this->require_resolvers as $fn) {
            if (($x = call_user_func($fn, $requirement, true)) !== null) {
                return $x;
            }
        }
        return null;
    }
    function resolve_requirement_argument($argname) {
        foreach ($this->require_resolvers as $fn) {
            if (($x = call_user_func($fn, $argname, false)) !== null) {
                return $x;
            }
        }
        return null;
    }

    private function find($context, $itext, $args, $priobound) {
        $match = null;
        $matchnreq = $matchctxlen = 0;
        if ($context === "") {
            $context = null;
        }
        for ($im = $this->ims[$itext] ?? null; $im; $im = $im->next) {
            $ctxlen = $nreq = 0;
            if ($context !== null && $im->context !== null) {
                if ($context === $im->context) {
                    $ctxlen = 10000;
                } else {
                    $ctxlen = strlen($im->context);
                    if ($ctxlen > strlen($context)
                        || strncmp($context, $im->context, $ctxlen) !== 0
                        || $context[$ctxlen] !== "/") {
                        continue;
                    }
                }
            } else if ($context === null && $im->context !== null) {
                continue;
            }
            if ($im->require
                && ($nreq = $im->check_require($this, $args)) === false) {
                continue;
            }
            if ($priobound !== null
                && $im->priority >= $priobound) {
                continue;
            }
            if (!$match
                || $im->priority > $match->priority
                || ($im->priority == $match->priority
                    && ($ctxlen > $matchctxlen
                        || ($ctxlen == $matchctxlen
                            && $nreq > $matchnreq)))) {
                $match = $im;
                $matchnreq = $nreq;
                $matchctxlen = $ctxlen;
            }
        }
        return $match;
    }

    private function expand($s, $args, $context, $im) {
        if ($s === null || $s === false || $s === "")
            return $s;
        $pos = strpos($s, "%");
        $argnum = 0;
        while ($pos !== false) {
            ++$pos;
            if (preg_match('/(?!\d+)\w+(?=%)/A', $s, $m, 0, $pos)
                && ($imt = $this->find($context, strtolower($m[0]), [], null))
                && $imt->template) {
                $t = substr($s, 0, $pos - 1) . $this->expand($imt->otext, $args, null, null);
                $s = $t . substr($s, $pos + strlen($m[0]) + 1);
                $pos = strlen($t);
            } else if (($im && $im->no_conversions) || count($args) === 1) {
                /* do nothing */
            } else if ($pos < strlen($s) && $s[$pos] === "%") {
                $s = substr($s, 0, $pos) . substr($s, $pos + 1);
            } else if (preg_match('/(?:(\d+)(\[[^\[\]\$]*\]|)\$)?(\d*(?:\.\d+)?)([deEifgosxXHU])/A', $s, $m, 0, $pos)) {
                $argi = $m[1] ? +$m[1] : ++$argnum;
                if (isset($args[$argi])) {
                    $val = $args[$argi];
                    if ($m[2]) {
                        assert(is_array($val));
                        $val = $val[substr($m[2], 1, -1)] ?? null;
                    }
                    $conv = $m[3] . ($m[4] === "H" || $m[4] === "U" ? "s" : $m[4]);
                    $x = sprintf("%$conv", $val);
                    if ($m[4] === "H") {
                        $x = htmlspecialchars($x);
                    } else if ($m[4] === "U") {
                        $x = urlencode($x);
                    }
                    $s = substr($s, 0, $pos - 1) . $x . substr($s, $pos + strlen($m[0]));
                    $pos = $pos - 1 + strlen($x);
                }
            }
            $pos = strpos($s, "%", $pos);
        }
        return $s;
    }

    function x($itext) {
        $args = func_get_args();
        if (($im = $this->find(null, $itext, $args, null))) {
            $args[0] = $im->otext;
        }
        return $this->expand($args[0], $args, null, $im);
    }

    function xc($context, $itext) {
        $args = array_slice(func_get_args(), 1);
        if (($im = $this->find($context, $itext, $args, null))) {
            $args[0] = $im->otext;
        }
        return $this->expand($args[0], $args, $context, $im);
    }

    function xi($id, $itext = null) {
        $args = array_slice(func_get_args(), 1);
        if (empty($args)) {
            $args[] = "";
        }
        if (($im = $this->find(null, $id, $args, null))
            && ($itext === null || $itext === false || $im->priority > 0.0)) {
            $args[0] = $im->otext;
        }
        return $this->expand($args[0], $args, $id, $im);
    }

    function xci($context, $id, $itext = null) {
        $args = array_slice(func_get_args(), 2);
        if (empty($args)) {
            $args[] = "";
        }
        if (($im = $this->find($context, $id, $args, null))
            && ($itext === null || $itext === false || $im->priority > 0.0)) {
            $args[0] = $im->otext;
        }
        $cid = (string) $context === "" ? $id : "$context/$id";
        return $this->expand($args[0], $args, $cid, $im);
    }

    function render_xci($fr, $context, $id, $itext = null) {
        $args = array_slice(func_get_args(), 3);
        if (empty($args)) {
            $args[] = "";
        }
        if (($im = $this->find($context, $id, $args, null))
            && ($itext === null || $itext === false || $im->priority > 0.0)) {
            $args[0] = $im->otext;
            if ($im->format !== null) {
                $fr->value_format = $im->format;
            }
        }
        $cid = (string) $context === "" ? $id : "$context/$id";
        $fr->value = $this->expand($args[0], $args, $cid, $im);
    }

    function default_itext($id, $itext) {
        $args = array_slice(func_get_args(), 1);
        if (($im = $this->find(null, $id, $args, self::PRIO_OVERRIDE))) {
            $args[0] = $im->otext;
        }
        return $args[0];
    }
}
