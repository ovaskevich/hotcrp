<?php
// formulagraph.php -- HotCRP class for drawing graphs
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class FormulaGraph extends MessageSet {
    // bitmasks
    const SCATTER = 1;
    const CDF = 2;
    const BARCHART = 4;
    const BOXPLOT = 8;

    const FBARCHART = 132; // 128 | BARCHART
    const RAWCDF = 130;    // 128 | CDF

    const REVIEWER_COLOR = 1;

    /** @var Conf */
    public $conf;
    /** @var Contact */
    public $user;
    public $type = 0;
    /** @var Formula */
    public $fx;
    /** @var list<Formula> */
    private $fxs;
    private $fx_expression;
    /** @var Formula */
    public $fy;
    private $fx_type = 0;
    private $queries = [];
    /** @var list<string> */
    private $_qstyles = [];
    /** @var list<bool> */
    private $_qstyles_bytag = [];
    private $_qstyle_index = 0;
    private $searches = [];
    private $papermap = [];
    private $reviewers = [];
    private $reviewer_color = false;
    private $remapped_rounds = [];
    private $tags = [];
    /** @var ?Formula */
    private $fxorder;
    /** @var array<string,list<array{int|float|bool,int|float|bool,int|string}>> */
    private $_scatter_data;
    /** @var list<array{int|float|bool,int|float|bool,list<int|string>,?string,?string}> */
    private $_bar_data;
    /** @var list<object> */
    private $_cdf_data;
    /** @var list<array{int|float|bool,int|float|bool}> */
    private $_xorder_data;
    private $_xorder_map;
    private $_axis_remapped = 0;
    private $_x_tagvalue_bool;
    private $_y_tagvalue_bool;

    function __construct(Contact $user, $gtype, $fx, $fy) {
        $this->conf = $user->conf;
        $this->user = $user;

        $gtype = simplify_whitespace($gtype);
        $fx = simplify_whitespace($fx);
        $fy = simplify_whitespace($fy);

        // graph type
        $fy_guess = false;
        $fy_gtype = $fy;
        if ($gtype === "") {
            $gtype = preg_replace('/\s+.*/', "", $fy);
            $fy_guess = true;
            $fy_gtype = ltrim(substr($fy, strlen($gtype)));
        }

        // Y axis expression
        if (strcasecmp($gtype, "cdf") === 0) {
            $this->type = self::CDF;
            $fy = "0";
        } else if (preg_match('/\A(?:raw-?cdf|cdf-?count|count-?cdf|cum-?count|cumulative-?count)\z/i', $gtype)) {
            $this->type = self::RAWCDF;
            $fy = "0";
        } else if (preg_match('/\A(?:count|bar|bars|barchart)\z/i', $gtype)) {
            $this->type = self::BARCHART;
            $fy = $fy_gtype ? : "sum(1)";
        } else if (preg_match('/\A(?:full-?area|full-?stack|stack|frac|fraction)\z/i', $gtype)) {
            $this->type = self::FBARCHART;
            $fy = "sum(1)";
        } else if (preg_match('/\A(?:box|boxplot|candlestick)\z/i', $gtype)) {
            $this->type = self::BOXPLOT;
            $fy = $fy_gtype;
        } else if (strcasecmp($gtype, "scatter") === 0) {
            $this->type = self::SCATTER;
            $fy = $fy_gtype;
        } else {
            $this->type = self::SCATTER;
        }

        $this->fy = new Formula($fy, Formula::ALLOW_INDEXED);
        $this->fy->check($this->user);
        $this->_y_tagvalue_bool = $this->fy->result_format() === Fexpr::FTAGVALUE;

        // X axis expression(s)
        $this->fx_expression = $fx;
        $this->fxs = [];
        if (preg_match('/\A(sort|order|rorder)\s+(\S.*)\z/i', $fx, $m)) {
            if (strcasecmp($m[1], "rorder") === 0) {
                $m[2] = "-($m[2])";
            }
            $this->set_xorder($m[2]);
            $this->fxs[] = new Formula("pid", Formula::ALLOW_INDEXED);
        } else if (strcasecmp($fx, "query") === 0 || strcasecmp($fx, "search") === 0) {
            $this->fxs[] = new Formula("0", Formula::ALLOW_INDEXED);
            $this->fx_type = Fexpr::FSEARCH;
        } else if (strcasecmp($fx, "tag") === 0) {
            $this->fxs[] = new Formula("0", Formula::ALLOW_INDEXED);
            $this->fx_type = Fexpr::FTAG;
        } else if (!($this->type & self::CDF)) {
            $this->fxs[] = new Formula($fx, Formula::ALLOW_INDEXED);
        } else {
            while (true) {
                $fx = preg_replace('/\A\s*;*\s*/', '', $fx);
                if ($fx === "") {
                    break;
                }
                $pos = Formula::span_maximal_formula($fx);
                $this->fxs[] = new Formula(substr($fx, 0, $pos), Formula::ALLOW_INDEXED);
                $fx = substr($fx, $pos);
            }
        }
        foreach ($this->fxs as $i => $f) {
            if (!$f->check($this->user)) {
                $this->error_at("fx", "X axis formula error: " . $f->error_html());
            } else if ($i === 0) {
                $this->fx_type = $this->fx_type ? : $f->result_format();
                $this->_x_tagvalue_bool = $this->fx_type === Fexpr::FTAGVALUE;
            } else if ($f->result_format() !== $this->fx_type) {
                $this->error_at("fx", "X axis error: Different formulas use different units");
                $this->fx_type = 0;
            }
        }
        $this->fx = count($this->fxs) === 1 ? $this->fxs[0] : null;

        if ($this->fy->error_html()) {
            $this->error_at("fy", "Y axis formula error: " . $this->fy->error_html());
        } else if (($this->type & self::BARCHART) && !$this->fy->support_combiner()) {
            $this->error_at("fy", "Y axis formula “" . htmlspecialchars($fy) . "” is unsuitable for bar charts, use an aggregate function like “sum(" . htmlspecialchars($fy) . ")”.");
            $this->fy = new Formula("sum(0)", Formula::ALLOW_INDEXED);
            $this->fy->check($this->user);
        } else if (($this->type & self::CDF) && $this->fx_type === Fexpr::FTAG) {
            $this->error_at("fy", "CDFs by tag don’t make sense.");
        }
    }

    static function parse_queries(Qrequest $qreq) {
        $queries = $styles = [];
        for ($i = 1; isset($qreq["q$i"]); ++$i) {
            $q = trim($qreq["q$i"]);
            $queries[] = $q === "" || $q === "(All)" ? "all" : $q;
            $styles[] = trim((string) $qreq["s$i"]);
        }
        if (empty($queries) && isset($qreq->q)) {
            $q = trim($qreq->q);
            $queries[] = $q === "" || $q === "(All)" ? "all" : $q;
            $styles[] = trim((string) $qreq->s);
        } else if (empty($queries)) {
            $queries[] = $styles[] = "";
        }
        while (count($queries) > 1
               && $queries[count($queries) - 1] === $queries[count($queries) - 2]) {
            array_pop($queries);
            array_pop($styles);
        }
        if (count($queries) === 1 && $queries[0] === "all") {
            $queries[0] = "";
        }
        return [$queries, $styles];
    }

    /** @param string $style */
    function add_query($q, $style, $fieldname = false) {
        $qn = count($this->queries);
        $this->queries[] = $q;
        if ($style === "by-tag" || $style === "default" || $style === "") {
            $style = "";
            $this->_qstyles_bytag[] = true;
        } else if ($style === "plain") {
            $style = "";
            $this->_qstyles_bytag[] = false;
        } else {
            $this->_qstyles_bytag[] = false;
        }
        if ($style === "") {
            if (($n = $this->_qstyle_index % 4)) {
                $style = "color" . $n;
            }
            ++$this->_qstyle_index;
        }
        $this->_qstyles[] = $style;
        $psearch = new PaperSearch($this->user, array("q" => $q));
        foreach ($psearch->paper_ids() as $pid) {
            $this->papermap[$pid][] = $qn;
        }
        if (!empty($psearch->warnings)) {
            $this->error_at($fieldname, $psearch->warnings);
        }
        $this->searches[] = $q !== "" ? $psearch : null;
    }

    function set_xorder($xorder) {
        $this->fxorder = null;
        $xorder = simplify_whitespace($xorder);
        if ($xorder !== "") {
            $fxorder = new Formula($xorder, Formula::ALLOW_INDEXED);
            $fxorder->check($this->user);
            if ($fxorder->error_html()) {
                $this->error_at("xorder", "X order formula error: " . $fxorder->error_html());
            } else {
                $this->fxorder = $fxorder;
            }
        }
    }

    function fx_expression() {
        return $this->fx_expression;
    }

    function fx_format() {
        return $this->fx_type;
    }

    function fx_combinable() {
        return !$this->fx_type;
    }

    private function _filter_queries($prow, $rrow) {
        $queries = [];
        foreach ($this->papermap[$prow->paperId] as $q) {
            if (!$rrow
                || !$this->searches[$q]
                || $this->searches[$q]->test_review($prow, $rrow))
                $queries[] = $q;
        }
        return $queries;
    }

    /** @param Formula $fx
     * @return list<object> */
    private function _cdf_data_one_fx($fx, $qcolors, $dashp, PaperInfoSet $rowset) {
        $data = [];

        $fxf = $fx->compile_json_function();
        $reviewf = null;
        if ($fx->indexed()) {
            $reviewf = Formula::compile_indexes_function($this->user, $fx->index_type());
        }

        foreach ($rowset as $prow) {
            $revs = $reviewf ? $reviewf($prow, $this->user) : [null];
            $queries = $this->papermap[$prow->paperId];
            foreach ($revs as $rcid) {
                if (($x = $fxf($prow, $rcid, $this->user)) !== null) {
                    $this->_x_tagvalue_bool = $this->_x_tagvalue_bool && is_bool($x);
                    if ($rcid) {
                        $queries = $this->_filter_queries($prow, $prow->review_of_user($rcid));
                    }
                    if ($this->fx_type === Fexpr::FSEARCH) {
                        foreach ($queries as $q) {
                            $data[0][] = $q;
                        }
                    } else {
                        foreach ($queries as $q) {
                            $data[$q][] = $x;
                        }
                    }
                }
            }
        }

        $fxlabel = count($this->fxs) > 1 ? $fx->expression : "";
        foreach ($data as $q => &$d) {
            $d = (object) ["d" => $d];
            if (($s = $qcolors[$q])) {
                $d->className = $s;
            }
            $dlabel = "";
            if (($this->queries[$q] ?? null) && count($this->queries) > 1) {
                $dlabel = $this->queries[$q];
            }
            if ($dlabel || $fxlabel) {
                $d->label = rtrim("$fxlabel $dlabel");
            }
            if ($dashp) {
                $d->dashpattern = $dashp;
            }
        }
        unset($d);
        return $data;
    }
    private function _cdf_data(PaperInfoSet $rowset) {
        // calculate query styles
        $qcolors = $this->_qstyles;
        $need_anal = array_fill(0, count($qcolors), false);
        $nneed_anal = 0;
        foreach ($qcolors as $qi => $q) {
            if ($this->_qstyles_bytag[$qi]) {
                $qcolors[$qi] = [];
                $need_anal[$qi] = true;
                ++$nneed_anal;
            }
        }
        foreach ($rowset as $prow) {
            if ($nneed_anal === 0) {
                break;
            }
            foreach ($this->papermap[$prow->paperId] as $qi) {
                if ($need_anal[$qi]) {
                    $c = [];
                    if ($prow->paperTags) {
                        $c = $this->conf->tags()->styles($prow->viewable_tags($this->user), TagMap::STYLE_BG);
                    }
                    if ($qcolors[$qi] !== null && !empty($c)) {
                        $c = array_values(array_intersect($qcolors[$qi], $c));
                    }
                    if (empty($c)) {
                        $qcolors[$qi] = $this->_qstyles[$qi];
                        $need_anal[$qi] = false;
                        --$nneed_anal;
                    } else {
                        $qcolors[$qi] = $c;
                    }
                }
            }
        }
        if ($nneed_anal !== 0) {
            foreach ($need_anal as $qi => $na) {
                if ($na) {
                    $qcolors[$qi] = join(" ", $qcolors[$qi]);
                }
            }
        }

        // compute data
        $this->_cdf_data = [];
        $dashps = [null, [10,5], [5,5], [1,1]];
        foreach ($this->fxs as $i => $fx) {
            $dashp = $dashps[$i % count($dashps)];
            $this->_cdf_data = array_merge($this->_cdf_data,
                $this->_cdf_data_one_fx($fx, $qcolors, $dashp, $rowset));
        }
    }

    private function _prepare_reviewer_color(Contact $user) {
        $this->reviewer_color = array();
        foreach ($this->conf->pc_members() as $p) {
            $this->reviewer_color[$p->contactId] = $this->conf->tags()->color_classes($p->viewable_tags($user), true);
        }
    }

    /** @return 1|string */
    private function _paper_style(PaperInfo $prow) {
        $qnum = $this->papermap[$prow->paperId][0];
        if ($this->_qstyles_bytag[$qnum]) {
            if ($this->reviewer_color && $this->user->can_view_user_tags()) {
                return self::REVIEWER_COLOR;
            } else if ($prow->paperTags
                       && ($c = $prow->viewable_tags($this->user))
                       && ($c = $prow->conf->tags()->styles($c, TagMap::STYLE_BG))) {
                return join(" ", $c);
            }
        }
        return $this->_qstyles[$qnum];
    }

    private function _add_tag_data(&$data, $d, PaperInfo $prow) {
        assert($this->fx_type === Fexpr::FTAG);
        $tags = Tagger::split_unpack($prow->viewable_tags($this->user));
        foreach ($tags as $ti) {
            if (!isset($this->tags[$ti[0]])) {
                $this->tags[$ti[0]] = count($this->tags);
            }
            $d[0] = $this->tags[$ti[0]];
            $data[] = $d;
        }
    }

    private function _account_tags(PaperInfo $prow) {
        assert($this->fx_type === Fexpr::FTAG);
        $tags = Tagger::split_unpack($prow->viewable_tags($this->user));
        $r = [];
        foreach ($tags as $ti) {
            if (!isset($this->tags[$ti[0]])) {
                $this->tags[$ti[0]] = count($this->tags);
            }
            $r[] = $this->tags[$ti[0]];
        }
        return $r;
    }

    private function _scatter_data(PaperInfoSet $rowset) {
        if ($this->fx->result_format() === Fexpr::FREVIEWER
            && ($this->type & self::BOXPLOT)) {
            $this->_prepare_reviewer_color($this->user);
        }

        $fxf = $this->fx->compile_json_function();
        $fyf = $this->fy->compile_json_function();
        $reviewf = null;
        if ($this->fx->indexed()
            || $this->fy->indexed()
            || ($this->fxorder && $this->fxorder->indexed())) {
            $reviewf = Formula::compile_indexes_function($this->user, $this->fx->index_type() | $this->fy->index_type() | ($this->fxorder ? $this->fxorder->index_type() : 0));
        }
        $orderf = $ordercf = $order_data = null;
        if ($this->fxorder) {
            $order_data = [];
            if ($reviewf) {
                $orderf = $this->fxorder->compile_extractor_function();
                $ordercf = $this->fxorder->compile_combiner_function();
            } else {
                $orderf = $this->fxorder->compile_json_function();
                $ordercf = function ($x) { return $x[0]; };
            }
        }

        $data = [];
        '@phan-var array<string,list<array{int|float|bool,int|float|bool,int|string}>> $data';
        foreach ($rowset as $prow) {
            $ps = $this->_paper_style($prow);
            $revs = $reviewf ? $reviewf($prow, $this->user) : [null];
            foreach ($revs as $rcid) {
                $rrow = $rcid ? $prow->review_of_user($rcid) : null;
                $x = $fxf($prow, $rcid, $this->user);
                $y = $fyf($prow, $rcid, $this->user);
                if ($x === null || $y === null) {
                    continue;
                }
                $this->_x_tagvalue_bool = $this->_x_tagvalue_bool && is_bool($x);
                $this->_y_tagvalue_bool = $this->_y_tagvalue_bool && is_bool($y);
                $id = $prow->paperId;
                if ($rrow && $rrow->reviewOrdinal) {
                    $id .= unparseReviewOrdinal($rrow->reviewOrdinal);
                }
                if ($ps === self::REVIEWER_COLOR) {
                    $s = $this->reviewer_color[$x] ?? "";
                } else {
                    $s = $ps;
                }
                if ($this->fx_type === Fexpr::FSEARCH) {
                    foreach ($this->_filter_queries($prow, $rrow) as $q) {
                        $data[$s][] = [$q, $y, $id];
                    }
                } else if ($this->fx_type === Fexpr::FTAG) {
                    foreach ($this->_account_tags($prow) as $ta) {
                        $data[$s][] = [$ta, $y, $id];
                    }
                } else {
                    $data[$s][] = [$x, $y, $id];
                }
                if ($orderf) {
                    $order_data[$x][] = $orderf($prow, $rcid, $this->user);
                }
            }
        }
        $this->_scatter_data = $data;

        if ($ordercf) {
            $this->_xorder_data = [];
            foreach ($order_data as $x => $vs) {
                $this->_xorder_data[] = [$x, $ordercf($vs)];
            }
        }
    }

    // combine data: [x, y, pids, style, [query...]]

    static function barchart_compare($a, $b) {
        if (($a[4] ?? 0) != ($b[4] ?? 0)) {
            return ($a[4] ?? 0) - ($b[4] ?? 0);
        } else if ($a[0] != $b[0]) {
            return $a[0] < $b[0] ? -1 : 1;
        } else {
            return strcmp($a[3], $b[3]);
        }
    }

    private function _combine_data(PaperInfoSet $rowset) {
        if ($this->fx->result_format() === Fexpr::FREVIEWER) {
            $this->_prepare_reviewer_color($this->user);
        }

        $fxf = $this->fx->compile_json_function();
        $fytrack = $this->fy->compile_extractor_function();
        $fycombine = $this->fy->compile_combiner_function();
        $reviewf = Formula::compile_indexes_function($this->user, $this->fx->index_type() | $this->fy->index_type() | ($this->fxorder ? $this->fxorder->index_type() : 0));
        $orderf = $ordercf = $order_data = null;
        if ($this->fxorder) {
            $order_data = [];
            $orderf = $this->fxorder->compile_extractor_function();
            $ordercf = $this->fxorder->compile_combiner_function();
        }

        $data = [];
        '@phan-var list<array{int|float|bool,int|float|bool,int|string,string,?string}> $data';
        foreach ($rowset as $prow) {
            $queries = $this->papermap[$prow->paperId];
            $ps = $this->_paper_style($prow);
            $revs = $reviewf ? $reviewf($prow, $this->user) : [null];
            foreach ($revs as $rcid) {
                $x = $fxf($prow, $rcid, $this->user);
                if ($x === null) {
                    continue;
                }
                $rrow = $rcid ? $prow->review_of_user($rcid) : null;
                if ($rrow) {
                    $queries = $this->_filter_queries($prow, $rrow);
                }
                if ($ps === self::REVIEWER_COLOR) {
                    $s = $this->reviewer_color[$x] ?? "";
                } else {
                    $s = $ps;
                }
                $y = $fytrack($prow, $rcid, $this->user);
                $id = $prow->paperId;
                if ($rrow && $rrow->reviewOrdinal && $this->fx->indexed()) {
                    $id .= unparseReviewOrdinal($rrow->reviewOrdinal);
                }
                foreach ($queries as $q) {
                    if ($this->fx_type === Fexpr::FTAG) {
                        foreach ($this->_account_tags($prow) as $ta) {
                            $data[] = [$ta, $y, $id, $s, $q];
                        }
                    } else {
                        $data[] = [$x, $y, $id, $s, $q];
                    }
                }
                if ($orderf) {
                    $order_data[$x][] = $orderf($prow, $rcid, $this->user);
                }
            }
        }

        $is_sum = $this->fy->is_sum();
        usort($data, "FormulaGraph::barchart_compare");
        $newdata = [];
        '@phan-var list<array{int|float|bool,int|float|bool,list<int|string>,?string,?string}> $newdata';
        $ndata = count($data);
        for ($i = 0; $i !== $ndata; ) {
            $d0 = $data[$i];
            $x = $d0[0];
            $ys = [$d0[1]];
            $ids = [$d0[2]];
            $s = $d0[3];
            $q = $d0[4];
            ++$i;
            while ($i !== $ndata
                   && $data[$i][0] == $x
                   && $data[$i][4] == $q
                   && (!$is_sum || $data[$i][3] == $s)) {
                $ys[] = $data[$i][1];
                $ids[] = $data[$i][2];
                if ($s && $data[$i][3] != $s) {
                    $s = "";
                }
                ++$i;
            }
            $y = $fycombine($ys);
            if ($reviewf && !$this->fx->indexed()) {
                $ids = array_values(array_unique($ids));
            }
            if ($q) {
                $newdata[] = [$x, $y, $ids, $s, $q];
            } else if ($s) {
                $newdata[] = [$x, $y, $ids, $s];
            } else {
                $newdata[] = [$x, $y, $ids];
            }
        }
        $this->_bar_data = $newdata;

        if ($ordercf) {
            $this->_xorder_data = [];
            foreach ($order_data as $x => $vs) {
                $this->_xorder_data[] = [$x, $ordercf($vs)];
            }
        }
    }

    private function _valuemap_axes($format) {
        $axes = 0;
        if ((!$this->fx_type && !$format)
            || ($this->fx_type === Fexpr::FTAG && $format === Fexpr::FTAG)) {
            $axes |= 1;
        }
        if (!($this->type & self::CDF) && $this->fy->result_format() === $format) {
            $axes |= 2;
        }
        return $axes;
    }

    private function _valuemap_collect($axes) {
        assert(!!$axes);
        $vs = [];
        if ($this->type & self::CDF) {
            foreach ($this->_cdf_data as $dx) {
                foreach ($dx->d as $d) {
                    $vs[$d] = true;
                }
            }
        } else if ($this->type & self::BARCHART) {
            foreach ($this->_bar_data as $d) {
                ($axes & 1) && $d[0] !== null && ($vs[$d[0]] = true);
                ($axes & 2) && $d[1] !== null && ($vs[$d[1]] = true);
            }
        } else {
            foreach ($this->_scatter_data as $dx) {
                foreach ($dx as $d) {
                    ($axes & 1) && $d[0] !== null && ($vs[$d[0]] = true);
                    ($axes & 2) && $d[1] !== null && ($vs[$d[1]] = true);
                }
            }
        }
        return $vs;
    }

    private function _valuemap_rewrite($axes, $m) {
        assert(!!$axes);
        if ($this->type & self::CDF) {
            foreach ($this->_cdf_data as $dx) {
                foreach ($dx->d as &$d) {
                    array_key_exists($d, $m) && ($d = $m[$d]);
                }
                unset($d);
            }
        } else if ($this->type & self::BARCHART) {
            foreach ($this->_bar_data as &$d) {
                ($axes & 1) && array_key_exists($d[0], $m) && ($d[0] = $m[$d[0]]);
                ($axes & 2) && array_key_exists($d[1], $m) && ($d[1] = $m[$d[1]]);
            }
        } else {
            foreach ($this->_scatter_data as &$dx) {
                foreach ($dx as &$d) {
                    ($axes & 1) && array_key_exists($d[0], $m) && ($d[0] = $m[$d[0]]);
                    ($axes & 2) && array_key_exists($d[1], $m) && ($d[1] = $m[$d[1]]);
                }
                unset($d);
            }
        }
        if (($axes & 1) && $this->_xorder_data) {
            foreach ($this->_xorder_data as &$d) {
                array_key_exists($d[0], $m) && ($d[0] = $m[$d[0]]);
            }
            unset($d);
        }
        $this->_axis_remapped |= $axes;
    }

    private function _reviewer_reformat() {
        if (!($axes = $this->_valuemap_axes(Fexpr::FREVIEWER))
            || !($cids = $this->_valuemap_collect($axes))) {
            return;
        }
        $cids = array_filter(array_keys($cids), "is_numeric");
        $result = $this->conf->qe("select contactId, firstName, lastName, email, roles, contactTags from ContactInfo where contactId ?a", $cids);
        $this->reviewers = [];
        while (($c = Contact::fetch($result, $this->conf))) {
            $this->reviewers[$c->contactId] = $c;
        }
        Dbl::free($result);
        uasort($this->reviewers, $this->conf->user_comparator());
        $i = 0;
        $m = [];
        foreach ($this->reviewers as $c) {
            $c->sort_position = ++$i;
            $m[$c->contactId] = $i;
        }
        $this->_valuemap_rewrite($axes, $m);
    }

    private function _revround_reformat() {
        if (!($axes = $this->_valuemap_axes(Fexpr::FROUND))
            || !($rs = $this->_valuemap_collect($axes)))
            return;
        $i = 0;
        $m = [];
        foreach ($this->conf->defined_round_list() as $n => $rname)
            if ($rs[$n] ?? null) {
                $this->remapped_rounds[++$i] = $rname;
                $m[$n] = $i;
            }
        $this->_valuemap_rewrite($axes, $m);
    }

    private function _tag_reformat() {
        if (!($axes = $this->_valuemap_axes(Fexpr::FTAG))
            || !($rs = $this->_valuemap_collect($axes))) {
            return;
        }
        uksort($this->tags, [$this->conf->collator(), "compare"]);
        $i = -1;
        $m = [];
        foreach ($this->tags as $tag => $ri) {
            $m[$ri] = ++$i;
        }
        $this->_valuemap_rewrite($axes, $m);
    }

    private function _xorder_rewrite() {
        if (!$this->_xorder_data) {
            return;
        }
        usort($this->_xorder_data, function ($x, $y) {
            if ($x[1] != $y[1]) {
                return $x[1] < $y[1] ? -1 : 1;
            } else if ($x[0] != $y[0]) {
                return $x[0] < $y[0] ? -1 : 1;
            } else {
                return 0;
            }
        });
        $xo = [];
        foreach ($this->_xorder_data as $i => $d) {
            $xo[$d[0]] = $i + 1;
        }
        $this->_xorder_map = $xo;
        if ($this->type & self::CDF) {
            foreach ($this->_cdf_data as $dx) {
                foreach ($dx->d as &$d) {
                    $d = $xo[$d];
                }
                unset($d);
            }
        } else if ($this->type & self::BARCHART) {
            foreach ($this->_bar_data as &$d) {
                $d[0] = $xo[$d[0]];
            }
        } else {
            foreach ($this->_scatter_data as &$dx) {
                foreach ($dx as &$d) {
                    $d[0] = $xo[$d[0]];
                }
                unset($d);
            }
        }
    }

    function data() {
        if ($this->_cdf_data === null
            && $this->_bar_data === null
            && $this->_scatter_data === null) {
            // load data
            $paperIds = array_keys($this->papermap);
            $queryOptions = ["paperId" => $paperIds, "tags" => true];
            foreach ($this->fxs as $f) {
                $f->add_query_options($queryOptions);
            }
            $this->fy->add_query_options($queryOptions);
            if (($this->fx && $this->fx->indexed()) || $this->fy->indexed()) {
                $queryOptions["reviewSignatures"] = true;
            }

            $result = $this->conf->paper_result($queryOptions, $this->user);
            $rowset = new PaperInfoSet;
            while (($prow = PaperInfo::fetch($result, $this->user))) {
                if ($this->user->can_view_paper($prow)) {
                    $rowset->add($prow);
                }
            }
            Dbl::free($result);

            if ($this->type & self::CDF) {
                $this->_cdf_data($rowset);
            } else if ($this->type & self::BARCHART) {
                $this->_combine_data($rowset);
            } else {
                $this->_scatter_data($rowset);
            }
            $this->_reviewer_reformat();
            $this->_revround_reformat();
            $this->_tag_reformat();
            $this->_xorder_rewrite();
        }
        if ($this->type & self::CDF) {
            return $this->_cdf_data;
        } else if ($this->type & self::BARCHART) {
            return $this->_bar_data;
        } else {
            return $this->_scatter_data;
        }
    }

    /** @param 'x'|'y' $axis */
    function axis_json($axis) {
        $isx = $axis === "x";
        $j = [];

        $counttype = $this->fx && $this->fx->indexed() ? "reviews" : "papers";
        if ($isx) {
            $j["label"] = $this->fx_expression;
        } else if ($this->type === self::FBARCHART) {
            $j["label"] = "fraction of $counttype";
            $j["fraction"] = true;
        } else if ($this->type === self::BARCHART
                   && $this->fy->expression === "sum(1)") {
            $j["label"] = "# $counttype";
        } else if ($this->type === self::RAWCDF) {
            $j["label"] = "Cumulative count of $counttype";
            $j["raw"] = true;
        } else if ($this->type & self::CDF) {
            $j["label"] = "CDF of $counttype";
        } else if (!$this->fx_type) {
            $j["label"] = $this->fy->expression;
        }

        $format = $isx ? $this->fx_type : $this->fy->result_format();
        $ticks = $named_ticks = null;
        if ($isx && $this->fx_type === Fexpr::FSEARCH) {
            $named_ticks = $this->queries;
        } else if ($isx && $this->fx_type === Fexpr::FTAG) {
            $tagger = new Tagger($this->user);
            $named_ticks = array_map(function ($t) use ($tagger) {
                return $tagger->unparse($t);
            }, array_keys($this->tags));
        } else if ($format instanceof ReviewField) {
            $n = count($format->options);
            $ol = $format->option_letter ? chr($format->option_letter - $n) : null;
            $ticks = ["score", $n, $ol, $format->option_class_prefix];
            if ($format->option_letter && $isx) {
                $j["flip"] = true;
            }
        } else {
            if ($format === Fexpr::FTAGVALUE
                && ($isx ? $this->_x_tagvalue_bool : $this->_y_tagvalue_bool)) {
                $format = Fexpr::FBOOL;
            }
            if ($format === Fexpr::FREVIEWER) {
                $x = [];
                foreach ($this->reviewers as $r) {
                    $rd = ["text" => $this->user->name_text_for($r),
                           "search" => "re:" . $r->email];
                    if ($this->user->can_view_user_tags()
                        && ($colors = $r->viewable_color_classes($this->user))) {
                        $rd["color_classes"] = $colors;
                    }
                    $rd["id"] = $r->contactId;
                    $x[$r->sort_position] = $rd;
                }
                $named_ticks = $x;
            } else if ($format === Fexpr::FDECISION) {
                $named_ticks = $this->conf->decision_map();
            } else if ($format === Fexpr::FBOOL) {
                $named_ticks = ["no", "yes"];
            } else if ($format instanceof SelectorPaperOption) {
                $named_ticks = $format->selector_options();
            } else if ($format === Fexpr::FROUND) {
                $named_ticks = $this->remapped_rounds;
            } else if ($format === Fexpr::FREVTYPE) {
                $named_ticks = ReviewForm::$revtype_names;
            } else if (is_int($format) && $format >= Fexpr::FDATE && $format <= Fexpr::FTIMEDELTA) {
                $ticks = ["time"];
            } else if ($isx && $this->_xorder_map) {
                if (isset($j["label"])) {
                    $j["label"] .= " order";
                } else {
                    $j["label"] = "order";
                }
            }
            if (!$isx && ($ticks !== null || $named_ticks !== null)) {
                $j["rotate_ticks"] = -90;
            }
        }

        if ($isx && $this->_xorder_map && $named_ticks !== null) {
            $newticks = [];
            foreach ($named_ticks as $n => $x) {
                if (isset($this->_xorder_map[$n]))
                    $named_ticks[$this->_xorder_map[$n]] = $x;
            }
            $named_ticks = $newticks;
        }

        if ($ticks !== null) {
            $j["ticks"] = $ticks;
        } else if ($named_ticks !== null) {
            $j["ticks"] = ["named", $named_ticks];
        }

        if ($this->_axis_remapped & ($isx ? 1 : 2)) {
            $j["reordered"] = true;
        }
        return $j;
    }

    function type_json() {
        $tj = [
            self::SCATTER => "scatter", self::CDF => "cdf",
            self::RAWCDF => "cumulative-count", self::BARCHART => "bar",
            self::FBARCHART => "full-stack", self::BOXPLOT => "box"
        ];
        return $tj[$this->type] ?? null;
    }

    function graph_json() {
        $j = [
            "type" => $this->type_json(),
            "data" => $this->data(),
            "x" => $this->axis_json("x"),
            "y" => $this->axis_json("y")
        ];
        if ($this->type & self::CDF) {
            $j["cdf_tooltip_position"] = true;
        }
        return $j;
    }
}
