<?php
// paperlist.php -- HotCRP helper class for producing paper lists
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class PaperListTableRender {
    public $table_start;
    public $thead;
    public $tbody_class;
    public $rows;
    public $tfoot;
    public $table_end;
    public $error;

    public $ncol;
    public $titlecol;
    public $split_ncol = 0;

    public $colorindex = 0;
    public $hascolors = false;
    public $skipcallout;
    public $last_trclass = "";
    public $groupstart = [0];

    function __construct($ncol, $titlecol, $skipcallout) {
        $this->ncol = $ncol;
        $this->titlecol = $titlecol;
        $this->skipcallout = $skipcallout;
    }
    static function make_error($error) {
        $tr = new PaperListTableRender(0, 0, 0);
        $tr->error = $error;
        return $tr;
    }
    function tbody_start() {
        return "  <tbody class=\"{$this->tbody_class}\">\n";
    }
    function heading_row($heading, $attr = []) {
        if (!$heading) {
            return "  <tr class=\"plheading\"><td class=\"plheading-blank\" colspan=\"{$this->ncol}\"></td></tr>\n";
        } else {
            $x = "  <tr class=\"plheading\"";
            foreach ($attr as $k => $v) {
                if ($k !== "no_titlecol" && $k !== "tdclass")
                    $x .= " $k=\"" . htmlspecialchars($v) . "\"";
            }
            $x .= ">";
            $titlecol = get($attr, "no_titlecol") ? 0 : $this->titlecol;
            if ($titlecol) {
                $x .= "<td class=\"plheading-spacer\" colspan=\"{$titlecol}\"></td>";
            }
            $tdclass = get($attr, "tdclass");
            $x .= "<td class=\"plheading" . ($tdclass ? " $tdclass" : "") . "\" colspan=\"" . ($this->ncol - $titlecol) . "\">";
            return $x . $heading . "</td></tr>\n";
        }
    }
    function heading_separator_row() {
        return "  <tr class=\"plheading\"><td class=\"plheading-separator\" colspan=\"{$this->ncol}\"></td></tr>\n";
    }
    function body_rows() {
        return join("", $this->rows);
    }
    function tbody_end() {
        return "  </tbody>\n";
    }
}

class PaperListReviewAnalysis {
    private $prow;
    public $rrow = null;
    public $round = "";
    function __construct($rrow, PaperInfo $prow) {
        $this->prow = $prow;
        if ($rrow->reviewId) {
            $this->rrow = $rrow;
            if ($rrow->reviewRound) {
                $this->round = htmlspecialchars($prow->conf->round_name($rrow->reviewRound));
            }
        }
    }
    function icon_html($includeLink) {
        $t = $this->rrow->type_icon();
        if ($includeLink) {
            $t = $this->wrap_link($t);
        }
        if ($this->round) {
            $t .= '<span class="revround" title="Review round">&nbsp;' . $this->round . "</span>";
        }
        return $t;
    }
    function icon_text() {
        $x = "";
        if ($this->rrow->reviewType) {
            $x = get_s(ReviewForm::$revtype_names, $this->rrow->reviewType);
        }
        if ($x !== "" && $this->round) {
            $x .= ":" . $this->round;
        }
        return $x;
    }
    function wrap_link($html, $klass = null) {
        if (!$this->rrow) {
            return $html;
        }
        if (!$this->rrow->reviewSubmitted) {
            $href = $this->prow->reviewurl(["r" => $this->rrow->unparse_ordinal()]);
        } else {
            $href = $this->prow->hoturl(["anchor" => "r" . $this->rrow->unparse_ordinal()]);
        }
        $t = $klass ? "<a class=\"$klass\"" : "<a";
        return $t . ' href="' . $href . '">' . $html . '</a>';
    }
}

class PaperList {
    /** @var Conf */
    public $conf;
    /** @var Contact */
    public $user;
    /** @var PaperSearch */
    public $search;
    private $qreq;
    /** @var Contact */
    private $_reviewer_user;
    /** @var ?PaperInfoSet */
    private $_rowset;
    /** @var list<TagAnno> */
    private $_groups;

    private $sortable;
    private $foldable;
    private $_paper_link_page;
    private $_paper_link_mode;
    private $_view_columns = false;
    private $_view_compact_columns = false;
    private $_view_force = false;
    private $_viewing = [];
    private $_view_origin = [];
    private $_view_field_options = [];
    private $_atab;

    private $_table_id;
    private $_table_class;
    private $_report_id;
    private $_row_id_pattern;
    /** @var ?SearchSelection */
    private $_selection;

    private $_row_filter;
    /** @var array<string,list<PaperColumn>> */
    private $_columns_by_name;
    private $_column_errors_by_name = [];
    private $_current_find_column;
    /** @var list<ListSorter> */
    private $_sorters = [];
    /** @var bool */
    private $_has_sorters = false;

    // columns access
    public $qopts; // set by PaperColumn::prepare
    public $tagger;
    public $need_tag_attr;
    public $table_attr;
    public $row_attr;
    public $row_overridable;
    public $row_tags;
    public $row_tags_overridable;
    public $need_render;
    public $has_editable_tags = false;
    public $check_format;

    // collected during render and exported to caller
    public $count; // also exported to columns access: 1 more than row index
    private $_has;
    public $error_html = array();

    static public $include_stash = true;

    static private $stats = [ScoreInfo::SUM, ScoreInfo::MEAN, ScoreInfo::MEDIAN, ScoreInfo::STDDEV_P, ScoreInfo::COUNT];

    function __construct(string $report, PaperSearch $search, $args = [], $qreq = null) {
        $this->conf = $search->conf;
        $this->user = $search->user;
        if (!$qreq || !($qreq instanceof Qrequest)) {
            $qreq = new Qrequest("GET", $qreq);
        }
        $this->qreq = $qreq;
        $this->search = $search;
        $this->_reviewer_user = $search->reviewer_user();
        $this->_rowset = $args["rowset"] ?? null;

        $this->sortable = isset($args["sort"]) && $args["sort"];
        $this->foldable = $this->sortable || ($args["foldable"] ?? false)
            || $this->user->is_manager() /* “Override conflicts” fold */;

        $this->_paper_link_page = "";
        if ($qreq->linkto === "paper" || $qreq->linkto === "assign") {
            $this->_paper_link_page = $qreq->linkto;
        } else if ($qreq->linkto === "paperedit") {
            $this->_paper_link_page = "paper";
            $this->_paper_link_mode = "edit";
        }
        $this->_atab = $qreq->atab;

        $this->tagger = new Tagger($this->user);

        $this->qopts = $this->search->simple_search_options();
        if ($this->qopts === false) {
            $this->qopts = ["paperId" => $this->search->paper_ids()];
        }
        $this->qopts["scores"] = [];

        $this->_report_id = $report;
        if ($report === "pl" || $report === "pf") {
            $s = $this->conf->setting_data("{$report}display_default", null);
            if ($s === null && $report === "pl") {
                $s = $this->conf->review_form()->default_display();
            }
            $this->set_view_display($s, 2);

            if (!($args["no_session_display"] ?? false)) {
                $s = $this->user->session("{$report}display", null);
                $this->set_view_display($s, 1);
            }
        }

        $display = $args["display"] ?? null;
        if ($display !== null) {
            // reset any `set_view_display` changes
            $this->_viewing = $this->_view_origin = $this->_sorters = [];
        }
        $view_list = $this->search->view_list();
        for ($i = 0; $i !== count($view_list); ++$i) {
            list($field, $action) = $view_list[$i];
            $options = [];
            while ($action === "show"
                   && $i + 1 !== count($view_list)
                   && $view_list[$i + 1][1] === "as") {
                $options[] = $view_list[$i + 1][0];
                ++$i;
            }
            $this->set_view($field, $action, 0, $options);
        }
        if ($display !== null) {
            $this->set_view_display($args["display"], 0);
        }
        if ($qreq->forceShow !== null) {
            $this->set_view("force", !!$qreq->forceShow, 0);
        }
        $xsorts = [];
        if ($this->sortable) {
            if (is_string($args["sort"])) {
                $xsorts[] = PaperSearch::parse_sorter($args["sort"]);
            } else if ($qreq->sort) {
                $xsorts[] = PaperSearch::parse_sorter($qreq->sort);
            }
        }
        if (($xsorts = array_merge($xsorts, $this->search->sorter_list()))) {
            $this->_sorters = array_merge(ListSorter::compress($xsorts), $this->_sorters);
        }

        $this->_columns_by_name = ["anonau" => [], "aufull" => [], "rownum" => [], "statistics" => []];
    }

    function __get($name) {
        // XXX remove this
        error_log("PaperList::$name " . json_encode(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS)));
        return $name === "contact" ? $this->user : null;
    }

    function table_id() {
        return $this->_table_id;
    }
    function set_table_id_class($table_id, $table_class, $row_id_pattern = null) {
        $this->_table_id = $table_id;
        $this->_table_class = $table_class;
        $this->_row_id_pattern = $row_id_pattern;
    }

    function report_id() {
        return $this->_report_id;
    }

    function set_row_filter($filter) {
        $this->_row_filter = $filter;
    }

    function add_column($name, PaperColumn $col) {
        $this->_columns_by_name[$name][] = $col;
    }

    static private $view_synonym = [
        "author" => "au",
        "authors" => "au",
        "cc" => "ccol",
        "col" => "columns",
        "column" => "columns",
        "compact" => "ccol",
        "compactcolumn" => "ccol",
        "compactcolumns" => "ccol",
        "rownumbers" => "rownum",
        "stat" => "statistics",
        "stats" => "statistics",
        "totals" => "statistics"
    ];
    static private $view_fake = [
        "anonau" => 150, "aufull" => 150,
        "ccol" => -2, "columns" => -2, "force" => -3, "rownum" => -1, "statistics" => -1
    ];

    /** @param string $k
     * @param 'show'|'hide'|'edit'|bool $v */
    function set_view($k, $v, $origin = 0, $opts = null) {
        if ($k !== "" && $k[0] === "\"" && $k[strlen($k) - 1] === "\"") {
            $k = substr($k, 1, -1);
        }
        if (isset(self::$view_synonym[$k])) {
            $k = self::$view_synonym[$k];
        }
        if (isset($this->_view_origin[$k])
            && $this->_view_origin[$k] < $origin) {
            return;
        }

        if ($v === "show" || $v === "hide") {
            $v = $v === "show";
        }
        if ($v) {
            if (($k === "aufull" || $k === "anonau")
                && !isset($this->_viewing["au"])) {
                $this->_viewing["au"] = $v;
                $this->_view_origin["au"] = 3;
            }
        }
        $this->_viewing[$k] = $v;
        $this->_view_origin[$k] = $origin;
        $this->_view_field_options[$k] = empty($opts) ? null : $opts;

        if ($k === "force") {
            $this->_view_force = $v;
        } else if ($k === "ccol") {
            $this->_view_columns = $this->_view_compact_columns = $v;
        } else if ($k === "columns") {
            $this->_view_columns = $v;
        }
    }
    private function set_view_display($str, $origin) {
        assert(!$this->_has_sorters);
        if ((string) $str === "") {
            return;
        }
        $splitter = new SearchSplitter($str);
        $sorters = [];
        while (($w = $splitter->shift()) !== "") {
            if (($colon = strpos($w, ":")) !== false) {
                $action = substr($w, 0, $colon);
                $w = substr($w, $colon + 1);
            } else {
                $action = "show";
            }
            if ($action === "sort") {
                if ($w !== "sort:id" || $sorters || $this->_sorters) {
                    $sorters[] = PaperSearch::parse_sorter($w);
                }
            } else {
                $action = $action === "edit" ? $action : $action !== "hide";
                $this->set_view($w, $action, $origin);
            }
        }
        if ($sorters) {
            $this->_sorters = array_merge(ListSorter::compress($sorters), $this->_sorters);
        }
    }


    function rowset() {
        if ($this->_rowset === null) {
            $this->qopts["scores"] = array_keys($this->qopts["scores"]);
            if (empty($this->qopts["scores"])) {
                unset($this->qopts["scores"]);
            }
            $result = $this->conf->paper_result($this->qopts, $this->user);
            $this->_rowset = new PaperInfoSet;
            while (($row = PaperInfo::fetch($result, $this->user))) {
                assert(!$this->_rowset->get($row->paperId));
                $this->_rowset->add($row);
            }
            Dbl::free($result);
        }
        if ($this->_groups === null) {
            $this->_sort();
        }
        return $this->_rowset;
    }

    function _sort_compare($a, $b) {
        foreach ($this->_sorters as $s) {
            if (($x = $s->field->compare($a, $b, $s))) {
                return ($x < 0) === $s->reverse ? 1 : -1;
            }
        }
        if ($a->paperId != $b->paperId) {
            return $a->paperId < $b->paperId ? -1 : 1;
        } else {
            return 0;
        }
    }
    function _then_sort_compare($a, $b) {
        if (($x = $a->_then_sort_info - $b->_then_sort_info)) {
            return $x < 0 ? -1 : 1;
        }
        foreach ($this->_sorters as $s) {
            if (($s->thenval === -1 || $s->thenval === $a->_then_sort_info)
                && ($x = $s->field->compare($a, $b, $s))) {
                return ($x < 0) === $s->reverse ? 1 : -1;
            }
        }
        if ($a->paperId != $b->paperId) {
            return $a->paperId < $b->paperId ? -1 : 1;
        } else {
            return 0;
        }
    }

    /** @return non-empty-list<ListSorter> */
    function sorters() {
        if (!$this->_has_sorters) {
            $this->_has_sorters = true;
            $old_context = $this->conf->xt_swap_context($this);
            $sorters = [];
            foreach ($this->_sorters as $sorter) {
                if ($sorter->field) {
                    // already prepared (e.g., NumericOrderPaperColumn)
                    $sorters[] = $sorter;
                } else if ($sorter->type
                           && ($field = $this->find_column($sorter->type))) {
                    if ($field->prepare($this, PaperColumn::PREP_SORT)
                        && $field->sort) {
                        $sorter->field = $field;
                        $sorter->type = $field->name;
                        $sorters[] = $sorter;
                    }
                } else if ($sorter->type) {
                    if ($this->user->can_view_tags(null)
                        && ($tagger = new Tagger($this->user))
                        && ($tag = $tagger->check($sorter->type))
                        && $this->conf->fetch_ivalue("select exists (select * from PaperTag where tag=?)", $tag)) {
                        $this->search->warn("Unrecognized sort “" . htmlspecialchars($sorter->type) . "”. Did you mean “sort:#" . htmlspecialchars($sorter->type) . "”?");
                    } else {
                        $this->search->warn("Unrecognized sort “" . htmlspecialchars($sorter->type) . "”.");
                    }
                }
            }
            if (empty($sorters)) {
                $sorters[] = PaperSearch::parse_sorter("id");
                $sorters[0]->field = $this->find_column("id");
            }
            foreach ($sorters as $s) {
                $s->assign_uid();
                $s->pl = $this;
                if ($s->reverse === null) {
                    $s->reverse = false;
                }
                if ($s->score === null) {
                    $s->score = ListSorter::default_score_sort($this->user);
                }
            }
            $this->conf->xt_swap_context($this);
            $this->_sorters = $sorters;
        }
        return $this->_sorters;
    }

    private function _sort() {
        $this->_groups = [];

        // actually sort
        $overrides = $this->user->add_overrides($this->_view_force ? Contact::OVERRIDE_CONFLICT : 0);
        if (($thenmap = $this->search->thenmap)) {
            foreach ($this->_rowset as $row) {
                $row->_then_sort_info = $thenmap[$row->paperId];
            }
        }
        foreach ($this->sorters() as $s) {
            $s->pl = $this;
            $s->field->analyze_sort($this, $this->_rowset, $s);
        }
        $this->_rowset->sort_by([$this, $thenmap ? "_then_sort_compare" : "_sort_compare"]);
        $this->user->set_overrides($overrides);

        // clean up, assign groups
        foreach ($this->sorters() as $s) {
            $s->pl = null; // break circular ref
        }
        if (!empty($this->search->groupmap)) {
            $this->_collect_groups($this->_rowset->as_array());
        }
    }

    private function _collect_groups(array $srows) {
        $groupmap = $this->search->groupmap ? : [];
        $thenmap = $this->search->thenmap ? : [];
        $rowpos = 0;
        for ($grouppos = 0;
             $rowpos < count($srows) || $grouppos < count($groupmap);
             ++$grouppos) {
            $first_rowpos = $rowpos;
            while ($rowpos < count($srows)
                   && ($thenmap[$srows[$rowpos]->paperId] ?? 0) === $grouppos) {
                ++$rowpos;
            }
            $ginfo = $groupmap[$grouppos] ?? null;
            if (($ginfo === null || $ginfo->is_empty())
                && $first_rowpos === 0) {
                continue;
            }
            $ginfo = $ginfo ? clone $ginfo : TagAnno::make_empty();
            $ginfo->pos = $first_rowpos;
            $ginfo->count = $rowpos - $first_rowpos;
            // leave off an empty “Untagged” section unless editing
            if ($ginfo->count === 0
                && $ginfo->tag && !$ginfo->annoId
                && !$this->has_editable_tags) {
                continue;
            }
            $this->_groups[] = $ginfo;
        }
    }

    /** @return string */
    function sortdef($always = false) {
        $sorters = $this->sorters();
        if ($sorters[0]->type
            && $sorters[0]->thenval === -1
            && ($always || (string) $this->qreq->sort != "")
            && ($sorters[0]->type != "id" || $sorters[0]->reverse)) {
            if (($fdef = $this->find_column($sorters[0]->type))) {
                $x = $fdef->sort_name($this, $sorters[0]);
            } else {
                $x = $sorters[0]->type;
            }
            if ($sorters[0]->reverse) {
                $x .= " reverse";
            }
            return $x;
        } else {
            return "";
        }
    }


    function set_selection(SearchSelection $ssel) {
        $this->_selection = $ssel;
    }

    /** @return bool */
    function is_selected($paperId, $default = false) {
        return $this->_selection ? $this->_selection->is_selected($paperId) : $default;
    }

    /** @param string $key
     * @param bool $value */
    function mark_has($key, $value = true) {
        if ($value) {
            $this->_has[$key] = true;
        } else if (!isset($this->_has[$key])) {
            $this->_has[$key] = false;
        }
    }

    /** @param string $key
     * @return bool */
    function has($key) {
        if (!isset($this->_has[$key])) {
            $this->_has[$key] = $this->_compute_has($key);
        }
        return $this->_has[$key];
    }

    private function _compute_has($key) {
        if ($key === "paper" || $key === "final") {
            $opt = $this->conf->paper_opts->find($key);
            return $this->user->can_view_some_option($opt)
                && $this->rowset()->any(function ($row) use ($opt) {
                    return ($opt->id == DTYPE_SUBMISSION ? $row->paperStorageId : $row->finalPaperStorageId) > 1
                        && $this->user->can_view_option($row, $opt);
                });
        } else if (str_starts_with($key, "opt")
                   && ($opt = $this->conf->paper_opts->find($key))) {
            return $this->user->can_view_some_option($opt)
                && $this->rowset()->any(function ($row) use ($opt) {
                    return ($ov = $row->option($opt))
                        && (!$opt->has_document() || $ov->value > 1)
                        && $this->user->can_view_option($row, $opt);
                });
        } else if ($key === "abstract") {
            return $this->conf->opt("noAbstract") !== 1
                && $this->rowset()->any(function ($row) {
                    return $row->abstract_text() !== "";
                });
        } else if ($key === "openau") {
            return $this->has("authors")
                && (!$this->user->is_manager()
                    || $this->rowset()->any(function ($row) {
                           return $this->user->can_view_authors($row);
                       }));
        } else if ($key === "anonau") {
            return $this->has("authors")
                && $this->user->is_manager()
                && $this->rowset()->any(function ($row) {
                        return $this->user->allow_view_authors($row)
                           && !$this->user->can_view_authors($row);
                    });
        } else if ($key === "lead") {
            return $this->conf->has_any_lead_or_shepherd()
                && $this->rowset()->any(function ($row) {
                        return $row->leadContactId > 0
                            && $this->user->can_view_lead($row);
                    });
        } else if ($key === "shepherd") {
            return $this->conf->has_any_lead_or_shepherd()
                && $this->rowset()->any(function ($row) {
                        return $row->shepherdContactId > 0
                            && $this->user->can_view_shepherd($row);
                    });
        } else if ($key === "collab") {
            return $this->rowset()->any(function ($row) {
                return $row->has_nonempty_collaborators()
                    && $this->user->can_view_authors($row);
            });
        } else if ($key === "need_submit") {
            return $this->rowset()->any(function ($row) {
                return $row->timeSubmitted <= 0 && $row->timeWithdrawn <= 0;
            });
        } else if ($key === "accepted") {
            return $this->rowset()->any(function ($row) {
                return $row->outcome > 0 && $this->user->can_view_decision($row);
            });
        } else if ($key === "need_final") {
            return $this->has("accepted")
                && $this->rowset()->any(function ($row) {
                       return $row->outcome > 0
                           && $this->user->can_view_decision($row)
                           && $row->timeFinalSubmitted <= 0;
                   });
        } else {
            if (!in_array($key, ["sel", "need_review", "authors", "tags"], true)) {
                error_log("unexpected PaperList::_compute_has({$key})");
            }
            return false;
        }
    }


    function column_error($text) {
        if ($this->_current_find_column) {
            $this->_column_errors_by_name[$this->_current_find_column][] = $text;
        }
    }

    /** @param string $name
     * @return list<PaperColumn> */
    private function find_columns($name, $opt = null) {
        if (!array_key_exists($name, $this->_columns_by_name)) {
            $this->_current_find_column = $name;
            $fs = $this->conf->paper_columns($name, $this->user, $opt);
            if (!$fs && !isset($this->_column_errors_by_name[$name])) {
                if ($this->conf->paper_columns($name, $this->conf->root_user())) {
                    $this->_column_errors_by_name[$name][] = "Permission error.";
                } else {
                    $this->_column_errors_by_name[$name][] = "No such column.";
                }
            }
            $nfs = [];
            foreach ($fs as $fdef) {
                if ($fdef->name === $name) {
                    $nfs[] = PaperColumn::make($this->conf, $fdef);
                } else {
                    if (!array_key_exists($fdef->name, $this->_columns_by_name)) {
                        $this->_columns_by_name[$fdef->name][] = PaperColumn::make($this->conf, $fdef);
                    }
                    $nfs = array_merge($nfs, $this->_columns_by_name[$fdef->name]);
                }
            }
            $this->_columns_by_name[$name] = $nfs;
        }
        return $this->_columns_by_name[$name];
    }

    /** @param string $name
     * @return ?PaperColumn */
    private function find_column($name) {
        return ($this->find_columns($name))[0] ?? null;
    }

    private function _expand_view_column($k, $report) {
        if (isset(self::$view_fake[$k])) {
            return [];
        }
        $fs = $this->find_columns($k, $this->_view_field_options[$k] ?? null);
        if (!$fs && $report && isset($this->_column_errors_by_name[$k])) {
            foreach ($this->_column_errors_by_name[$k] as $i => $err) {
                $this->error_html[] = ($i ? "" : "Can’t show “" . htmlspecialchars($k) . "”: ") . $err;
            }
        }
        return $fs;
    }

    /** @return list<PaperColumn> */
    private function _view_columns($field_list) {
        // add explicitly requested columns
        $viewmap_add = [];
        foreach ($this->_viewing as $k => $v) {
            $f = $this->_expand_view_column($k, !!$v);
            foreach ($f as $fx) {
                $viewmap_add[$fx->name] = $v;
                foreach ($field_list as $ff) {
                    if ($fx && $fx->name == $ff->name)
                        $fx = null;
                }
                if ($fx) {
                    $field_list[] = $fx;
                }
            }
        }
        foreach ($viewmap_add as $k => $v) {
            $this->_viewing[$k] = $v;
        }
        foreach ($field_list as $fi => $f) {
            if (($this->_viewing[$f->name] ?? null) === "edit") {
                $f->mark_editable();
            }
        }

        // sort by position
        usort($field_list, "Conf::xt_position_compare");
        return $field_list;
    }

    /** @param string|list<string> $fields
     * @return list<PaperColumn> */
    private function _canonicalize_columns($fields) {
        if (is_string($fields)) {
            $fields = explode(" ", $fields);
        }
        $field_list = array();
        foreach ($fields as $fid) {
            foreach ($this->find_columns($fid) as $fdef) {
                $field_list[] = $fdef;
                $view = self::$view_synonym[$fdef->name] ?? $fdef->name;
                if (!isset($this->_viewing[$view])) {
                    $this->_viewing[$view] = !$fdef->fold
                        && ($fdef->minimal || !$this->_view_compact_columns);
                    $this->_view_origin[$view] = 3;
                }
            }
        }
        if ($this->qreq->selectall > 0 && $field_list[0]->name == "sel") {
            $field_list[0] = $this->find_column("selon");
        }
        return $field_list;
    }

    /** @param string|list<string> $field_list
     * @param bool $expand
     * @param bool $all
     * @return list<PaperColumn> */
    private function _columns($field_list, $expand, $all) {
        $old_context = $this->conf->xt_swap_context($this);
        // look up columns
        $field_list = $this->_canonicalize_columns($field_list);
        if ($expand) {
            $field_list = $this->_view_columns($field_list);
        }
        // look up sorters
        $this->conf->xt_swap_context($old_context);

        // prepare columns
        $result = [];
        $this->need_tag_attr = false;
        $this->table_attr = [];
        assert(empty($this->row_attr));
        foreach ($field_list as $fdef) {
            if ($fdef) {
                $fdef->is_visible = $all || get($this->_viewing, $fdef->name);
                $fdef->has_content = false;
                if ($fdef->prepare($this, $fdef->is_visible ? 1 : 0)) {
                    $result[] = $fdef;
                }
            }
        }

        // analyze rows and return
        foreach ($result as $fdef) {
            $fdef->analyze($this, $result);
        }
        return $result;
    }


    /** @param PaperInfo $row
     * @return string */
    function _contentDownload($row) {
        if ($row->size !== 0
            && $this->user->can_view_pdf($row)
            && ($doc = $row->primary_document())) {
            return "&nbsp;" . $doc->link_html("", DocumentInfo::L_SMALL | DocumentInfo::L_NOSIZE | DocumentInfo::L_FINALTITLE);
        } else {
            return "";
        }
    }

    /** @return string */
    function _paperLink(PaperInfo $row) {
        $pt = $this->_paper_link_page ? : "paper";
        if ($pt === "finishreview") {
            $ci = $row->contact_info($this->user);
            $pt = $ci->review_status <= PaperContactInfo::RS_UNSUBMITTED ? "review" : "paper";
        }
        $pl = "p=" . $row->paperId;
        if ($pt === "paper" && $this->_paper_link_mode) {
            $pl .= "&amp;m=" . $this->_paper_link_mode;
        }
        return $row->conf->hoturl($pt, $pl);
    }

    // content downloaders
    /** @return Contact */
    function reviewer_user() {
        return $this->_reviewer_user;
    }
    function set_reviewer_user(Contact $user) {
        $this->_reviewer_user = $user;
    }

    /** @param int $contactId
     * @return string */
    function _content_pc($contactId) {
        $pc = $this->conf->pc_member_by_id($contactId);
        return $pc ? $this->user->reviewer_html_for($pc) : "";
    }

    /** @param int $contactId
     * @return string */
    function _text_pc($contactId) {
        $pc = $this->conf->pc_member_by_id($contactId);
        return $pc ? $this->user->reviewer_text_for($pc) : "";
    }

    /** @param int $contactId1
     * @param int $contactId2 */
    function _compare_pc($contactId1, $contactId2, ListSorter $sorter) {
        assert(!!$sorter->ianno);
        $pc1 = $this->conf->pc_member_by_id($contactId1);
        $pc2 = $this->conf->pc_member_by_id($contactId2);
        if ($pc1 === $pc2) {
            return $contactId1 - $contactId2;
        } else if (!$pc1 || !$pc2) {
            return $pc1 ? -1 : 1;
        } else {
            $as = Contact::get_sorter($pc1, $sorter->ianno);
            $bs = Contact::get_sorter($pc2, $sorter->ianno);
            return $this->conf->collator()->compare($as, $bs);
        }
    }

    /** @return PaperListReviewAnalysis */
    function make_review_analysis($xrow, PaperInfo $row) {
        return new PaperListReviewAnalysis($xrow, $row);
    }


    private function _default_linkto($page) {
        if (!$this->_paper_link_page) {
            $this->_paper_link_page = $page;
        }
    }

    private function _list_columns() {
        switch ($this->_report_id) {
        case "empty":
            return "";
        case "authorHome":
            return "id title status";
        case "reviewerHome":
            $this->_default_linkto("finishreview");
            return "id title revtype status";
        case "pl":
            return "sel id title revtype revstat status authors tags";
        case "reqrevs":
            return "id title revdelegation revstat status authors tags";
        case "reviewAssignment":
            $this->_default_linkto("assign");
            return "id title mypref topicscore desirability assignment authors potentialconflict tags";
        case "conflictassign":
            $this->_default_linkto("assign");
            return "id title authors potentialconflict revtype editconf tags";
        case "pf":
            $this->_default_linkto("paper");
            return "sel id title topicscore revtype editmypref authors tags";
        case "reviewers":
            $this->_default_linkto("assign");
            return "selon id title status";
        case "reviewersSel":
            $this->_default_linkto("assign");
            return "sel id title status reviewers";
        default:
            error_log($this->conf->dbname . ": No such report {$this->_report_id}");
            return "";
        }
    }


    function showing($fname) {
        $fname = self::$view_synonym[$fname] ?? $fname;
        if (isset($this->qreq["show$fname"])) {
            return true;
        } else {
            return $this->_viewing[$fname] ?? false;
        }
    }

    private function _wrap_conflict($main_content, $override_content, PaperColumn $fdef) {
        if ($main_content === $override_content) {
            return $main_content;
        }
        $tag = $fdef->viewable_row() ? "div" : "span";
        if ((string) $main_content !== "") {
            $main_content = "<$tag class=\"fn5\">$main_content</$tag>";
        }
        if ((string) $override_content !== "") {
            $override_content = "<$tag class=\"fx5\">$override_content</$tag>";
        }
        return $main_content . $override_content;
    }

    /** @return array{bool,string} */
    private function _row_field_content(PaperColumn $fdef, PaperInfo $row) {
        $content = "";
        $override = $fdef->override;
        if ($override & PaperColumn::OVERRIDE_NONCONFLICTED) {
            $override &= ~PaperColumn::OVERRIDE_NONCONFLICTED;
        } else if (!$this->row_overridable) {
            $override = 0;
        }
        if ($override <= 0) {
            $empty = $fdef->content_empty($this, $row);
            if (!$empty && $fdef->is_visible) {
                $content = $fdef->content($this, $row);
            }
        } else if ($override === PaperColumn::OVERRIDE_BOTH) {
            $content1 = $content2 = "";
            $empty1 = $fdef->content_empty($this, $row);
            if (!$empty1 && $fdef->is_visible) {
                $content1 = $fdef->content($this, $row);
            }
            $overrides = $this->user->add_overrides(Contact::OVERRIDE_CONFLICT);
            $empty2 = $fdef->content_empty($this, $row);
            if (!$empty2 && $fdef->is_visible) {
                $content2 = $fdef->content($this, $row);
            }
            $this->user->set_overrides($overrides);
            $empty = $empty1 && $empty2;
            $content = $this->_wrap_conflict($content1, $content2, $fdef);
        } else if ($override === PaperColumn::OVERRIDE_FORCE) {
            $overrides = $this->user->add_overrides(Contact::OVERRIDE_CONFLICT);
            $empty = $fdef->content_empty($this, $row);
            if (!$empty && $fdef->is_visible) {
                $content = $fdef->content($this, $row);
            }
            $this->user->set_overrides($overrides);
        } else { // $override > 0
            $empty = $fdef->content_empty($this, $row);
            if ($empty) {
                $overrides = $this->user->add_overrides(Contact::OVERRIDE_CONFLICT);
                $empty = $fdef->content_empty($this, $row);
                if (!$empty && $fdef->is_visible) {
                    if ($override === PaperColumn::OVERRIDE_IFEMPTY_LINK) {
                        $content = '<em>Hidden for conflict</em> · <a class="ui js-override-conflict" href="">Override</a>';
                    }
                    $content = $this->_wrap_conflict($content, $fdef->content($this, $row), $fdef);
                }
                $this->user->set_overrides($overrides);
            } else if ($fdef->is_visible) {
                $content = $fdef->content($this, $row);
            }
        }
        return [$empty, $content];
    }

    private function _row_setup(PaperInfo $row) {
        ++$this->count;
        $this->row_attr = [];
        $this->row_overridable = $this->user->has_overridable_conflict($row);

        $this->row_tags = $this->row_tags_overridable = null;
        if (isset($row->paperTags) && $row->paperTags !== "") {
            if ($this->row_overridable) {
                $overrides = $this->user->add_overrides(Contact::OVERRIDE_CONFLICT);
                $this->row_tags_overridable = $row->sorted_viewable_tags($this->user);
                $this->user->remove_overrides(Contact::OVERRIDE_CONFLICT);
                $this->row_tags = $row->sorted_viewable_tags($this->user);
                $this->user->set_overrides($overrides);
            } else {
                $this->row_tags = $row->sorted_viewable_tags($this->user);
            }
        }
    }

    static private function _prepend_row_header($content, $ch) {
        $ch = '<em class="plx">' . $ch . ':</em> ';
        if (str_starts_with($content, '<div class="fn5"')) {
            return preg_replace_callback('/(<div class="f[nx]5">)/', function ($m) use ($ch) {
                return $m[1] . $ch;
            }, $content);
        } else if (preg_match('/\A((?:<(?:div|p|ul|ol|li).*?>)*)([\s\S]*)\z/', $content, $m)) {
            return $m[1] . $ch . $m[2];
        } else {
            return $ch . $content;
        }
    }

    private function _row_content($rstate, PaperInfo $row, $fieldDef) {
        // filter
        if ($this->_row_filter
            && !call_user_func($this->_row_filter, $this, $row)) {
            --$this->count;
            return "";
        }

        // main columns
        $tm = "";
        foreach ($fieldDef as $fdef) {
            if (!$fdef->viewable_column()
                || (!$fdef->is_visible && $fdef->has_content)) {
                continue;
            }
            list($empty, $content) = $this->_row_field_content($fdef, $row);
            if ($fdef->is_visible) {
                if ($content !== "") {
                    $tm .= "<td class=\"pl " . $fdef->className;
                    if ($fdef->fold) {
                        $tm .= " fx{$fdef->fold}";
                    }
                    $tm .= "\">" . $content . "</td>";
                } else {
                    $tm .= "<td";
                    if ($fdef->fold) {
                        $tm .= " class=\"fx{$fdef->fold}\"";
                    }
                    $tm .= "></td>";
                }
            }
            if ($fdef->is_visible ? $content !== "" : !$empty) {
                $fdef->has_content = true;
            }
        }

        // extension columns
        $tt = "";
        foreach ($fieldDef as $fdef) {
            if (!$fdef->viewable_row()
                || (!$fdef->is_visible && $fdef->has_content)) {
                continue;
            }
            list($empty, $content) = $this->_row_field_content($fdef, $row);
            if ($fdef->is_visible) {
                if ($content !== ""
                    && ($ch = $fdef->header($this, false))) {
                    if ($content[0] === "<") {
                        $content = self::_prepend_row_header($content, $ch);
                    } else {
                        $content = '<em class="plx">' . $ch . ':</em> ' . $content;
                    }
                }
                $tt .= "<div class=\"" . $fdef->className;
                if ($fdef->fold) {
                    $tt .= " fx" . $fdef->fold;
                }
                $tt .= "\">" . $content . "</div>";
            }
            if ($fdef->is_visible ? $content !== "" : !$empty) {
                $fdef->has_content = true;
            }
        }

        // tags
        if ($this->need_tag_attr) {
            if ($this->row_tags_overridable
                && $this->row_tags_overridable !== $this->row_tags) {
                $this->row_attr["data-tags"] = trim($this->row_tags_overridable);
                $this->row_attr["data-tags-conflicted"] = trim($this->row_tags);
            } else {
                $this->row_attr["data-tags"] = trim($this->row_tags);
            }
        }

        // row classes
        $trclass = [];
        $cc = "";
        if ($row->paperTags ?? null) {
            if ($this->row_tags_overridable
                && ($cco = $row->conf->tags()->color_classes($this->row_tags_overridable))) {
                $ccx = $row->conf->tags()->color_classes($this->row_tags);
                if ($cco !== $ccx) {
                    $this->row_attr["data-color-classes"] = $cco;
                    $this->row_attr["data-color-classes-conflicted"] = $ccx;
                    $trclass[] = "colorconflict";
                }
                $cc = $this->_view_force ? $cco : $ccx;
                $rstate->hascolors = $rstate->hascolors || str_ends_with($cco, " tagbg");
            } else if ($this->row_tags) {
                $cc = $row->conf->tags()->color_classes($this->row_tags);
            }
        }
        if ($cc) {
            $trclass[] = $cc;
            $rstate->hascolors = $rstate->hascolors || str_ends_with($cc, " tagbg");
        }
        if (!$cc || !$rstate->hascolors) {
            $trclass[] = "k" . $rstate->colorindex;
        }
        if (($highlightclass = $this->search->highlightmap[$row->paperId] ?? null)) {
            $trclass[] = $highlightclass[0] . "highlightmark";
        }
        $want_plx = $tt !== "" || $this->table_id();
        if (!$want_plx) {
            $trclass[] = "plnx";
        }
        $trclass = join(" ", $trclass);
        $rstate->colorindex = 1 - $rstate->colorindex;
        $rstate->last_trclass = $trclass;

        $t = "  <tr";
        if ($this->_row_id_pattern) {
            $t .= " id=\"" . str_replace("#", (string) $row->paperId, $this->_row_id_pattern) . "\"";
        }
        $t .= " class=\"pl $trclass\" data-pid=\"$row->paperId";
        foreach ($this->row_attr as $k => $v) {
            $t .= "\" $k=\"" . htmlspecialchars($v);
        }
        $t .= "\">" . $tm . "</tr>\n";

        if ($want_plx) {
            $t .= "  <tr class=\"plx $trclass\" data-pid=\"$row->paperId\">";
            if ($rstate->skipcallout > 0) {
                $t .= "<td colspan=\"$rstate->skipcallout\"></td>";
            }
            $t .= "<td class=\"plx\" colspan=\"" . ($rstate->ncol - $rstate->skipcallout) . "\">$tt</td></tr>\n";
        }

        return $t;
    }

    private function _groups_for($grouppos, $rstate, &$body, $last) {
        for ($did_groupstart = false;
             $grouppos < count($this->_groups)
             && ($last || $this->count > $this->_groups[$grouppos]->pos);
             ++$grouppos) {
            if ($this->count !== 1 && $did_groupstart === false) {
                $rstate->groupstart[] = $did_groupstart = count($body);
            }
            $ginfo = $this->_groups[$grouppos];
            if ($ginfo->is_empty()) {
                $body[] = $rstate->heading_row(null);
            } else {
                $attr = [];
                if ($ginfo->tag) {
                    $attr["data-anno-tag"] = $ginfo->tag;
                }
                if ($ginfo->annoId) {
                    $attr["data-anno-id"] = $ginfo->annoId;
                    $attr["data-tags"] = "{$ginfo->tag}#{$ginfo->tagIndex}";
                    if (isset($this->table_attr["data-drag-tag"])) {
                        $attr["tdclass"] = "need-draghandle";
                    }
                }
                $x = "<span class=\"plheading-group";
                if ($ginfo->heading !== ""
                    && ($format = $this->conf->check_format($ginfo->annoFormat, $ginfo->heading))) {
                    $x .= " need-format\" data-format=\"$format";
                    $this->need_render = true;
                }
                $x .= "\" data-title=\"" . htmlspecialchars($ginfo->heading)
                    . "\">" . htmlspecialchars($ginfo->heading)
                    . ($ginfo->heading !== "" ? " " : "")
                    . "</span><span class=\"plheading-count\">"
                    . plural($ginfo->count, "paper") . "</span>";
                $body[] = $rstate->heading_row($x, $attr);
                $rstate->colorindex = 0;
            }
        }
        return $grouppos;
    }

    /** @param PaperColumn $fdef
     * @return string */
    private function _field_title($fdef) {
        $t = $fdef->header($this, false);
        if (!$fdef->viewable_column()
            || !$fdef->sort
            || !$this->sortable
            || !($sort_url = $this->search->url_site_relative_raw())) {
            return $t;
        }

        $sort_name = $fdef->sort_name($this, null);
        $sort_url = htmlspecialchars(Navigation::siteurl() . $sort_url)
            . (strpos($sort_url, "?") ? "&amp;" : "?") . "sort=" . urlencode($sort_name);
        $s0 = ($this->sorters())[0];

        $sort_class = "pl_sort";
        if ($s0
            && $s0->thenval === -1
            && $sort_name === $s0->field->sort_name($this, $s0)) {
            $sort_class = "pl_sort pl_sorting" . ($s0->reverse ? "_rev" : "_fwd");
            $sort_url .= $s0->reverse ? "" : urlencode(" reverse");
        }

        if ($this->user->overrides() & Contact::OVERRIDE_CONFLICT) {
            $sort_url .= "&amp;forceShow=1";
        }
        return '<a class="' . $sort_class . '" rel="nofollow" href="' . $sort_url . '">' . $t . '</a>';
    }

    /** @param PaperListTableRender $rstate
     * @param list<PaperColumn> $fieldDef */
    private function _analyze_folds($rstate, $fieldDef) {
        $classes = &$this->table_attr["class"];
        $jscol = [];
        $has_sel = false;
        $has_statistics = $has_loadable_statistics = false;
        foreach ($fieldDef as $fdef) {
            $j = $fdef->field_json($this);
            if (isset($j["has_statistics"]) && $j["has_statistics"]) {
                if ($fdef->has_content) {
                    $has_loadable_statistics = true;
                }
                if ($fdef->has_content && $fdef->is_visible) {
                    $has_statistics = true;
                }
            }
            $jscol[] = $j;
            if ($fdef->fold) {
                $classes[] = "fold" . $fdef->fold . ($fdef->is_visible ? "o" : "c");
            }
            if ($fdef instanceof Selector_PaperColumn) {
                $has_sel = true;
            }
        }
        // authorship requires special handling
        if ($this->has("anonau")) {
            $classes[] = "fold2" . ($this->showing("anonau") ? "o" : "c");
        }
        // row number folding
        if ($has_sel) {
            $classes[] = "fold6" . ($this->showing("rownum") ? "o" : "c");
        }
        if ($this->user->is_track_manager()) {
            $classes[] = "fold5" . ($this->showing("force") ? "o" : "c");
        }
        $classes[] = "fold7" . ($this->showing("statistics") ? "o" : "c");
        $classes[] = "fold8" . ($has_statistics ? "o" : "c");
        $this->table_attr["data-columns"] = $jscol;
    }

    /** @param PaperListTableRender $rstate */
    private function _column_split($rstate, $colhead, &$body) {
        if (count($rstate->groupstart) <= 1) {
            return false;
        }
        $rstate->groupstart[] = count($body);
        $rstate->split_ncol = count($rstate->groupstart) - 1;

        $rownum_marker = "<span class=\"pl_rownum fx6\">";
        $rownum_len = strlen($rownum_marker);
        $nbody = array("<tr>");
        $tbody_class = "pltable" . ($rstate->hascolors ? " pltable-colored" : "");
        for ($i = 1; $i < count($rstate->groupstart); ++$i) {
            $nbody[] = '<td class="plsplit_col top" width="' . (100 / $rstate->split_ncol) . '%"><div class="plsplit_col"><table width="100%">';
            $nbody[] = $colhead . "  <tbody class=\"$tbody_class\">\n";
            $number = 1;
            for ($j = $rstate->groupstart[$i - 1]; $j < $rstate->groupstart[$i]; ++$j) {
                $x = $body[$j];
                if (($pos = strpos($x, $rownum_marker)) !== false) {
                    $pos += strlen($rownum_marker);
                    $x = substr($x, 0, $pos) . preg_replace('/\A\d+/', (string) $number, substr($x, $pos));
                    ++$number;
                } else if (strpos($x, "<td class=\"plheading-blank") !== false) {
                    $x = "";
                }
                $nbody[] = $x;
            }
            $nbody[] = "  </tbody>\n</table></div></td>\n";
        }
        $nbody[] = "</tr>";

        $body = $nbody;
        $rstate->last_trclass = "plsplit_col";
        return true;
    }

    private function _prepare() {
        $this->_has = [];
        $this->count = 0;
        $this->need_render = false;
    }

    /** @param PaperListTableRender $rstate
     * @param list<PaperColumn> $fieldDef
     * @return string */
    private function _statistics_rows($rstate, $fieldDef) {
        if (!$this->foldable) {
            $any = false;
            foreach ($fieldDef as $fdef) {
                $any = $any || ($fdef->viewable_column() && $fdef->has_statistics());
            }
            if (!$any) {
                return "";
            }
        }
        $t = '  <tr class="pl_statheadrow fx8">';
        if ($rstate->titlecol) {
            $t .= "<td colspan=\"{$rstate->titlecol}\" class=\"plstat\"></td>";
        }
        $t .= "<td colspan=\"" . ($rstate->ncol - $rstate->titlecol) . "\" class=\"plstat\">" . foldupbutton(7, "Statistics") . "</td></tr>\n";
        foreach (self::$stats as $stat) {
            $t .= '  <tr';
            if ($this->_row_id_pattern) {
                $t .= " id=\"" . str_replace("#", "stat_" . ScoreInfo::$stat_keys[$stat], $this->_row_id_pattern) . "\"";
            }
            $t .= ' class="pl_statrow fx7 fx8" data-statistic="' . ScoreInfo::$stat_keys[$stat] . '">';
            $col = 0;
            foreach ($fieldDef as $fdef) {
                if (!$fdef->viewable_column() || !$fdef->is_visible) {
                    continue;
                }
                $class = "plstat " . $fdef->className;
                if ($fdef->has_statistics()) {
                    $content = $fdef->statistic($this, $stat);
                } else if ($col == $rstate->titlecol) {
                    $content = ScoreInfo::$stat_names[$stat];
                    $class = "plstat pl_statheader";
                } else {
                    $content = "";
                }
                $t .= '<td class="' . $class;
                if ($fdef->fold) {
                    $t .= ' fx' . $fdef->fold;
                }
                $t .= '">' . $content . '</td>';
                ++$col;
            }
            $t .= "</tr>\n";
        }
        return $t;
    }

    function displayable_list_actions($prefix) {
        $la = [];
        foreach ($this->conf->list_action_map() as $name => $fjs) {
            if (str_starts_with($name, $prefix)) {
                $uf = null;
                foreach ($fjs as $fj) {
                    if (Conf::xt_priority_compare($fj, $uf) <= 0
                        && $this->conf->xt_allowed($fj, $this->user)
                        && $this->action_xt_displayed($fj)) {
                        $uf = $fj;
                    }
                }
                if ($uf) {
                    $la[$name] = $uf;
                }
            }
        }
        return $la;
    }

    function action_xt_displayed($fj) {
        if (isset($fj->display_if_report)
            && (str_starts_with($fj->display_if_report, "!")
                ? $this->_report_id === substr($fj->display_if_report, 1)
                : $this->_report_id !== $fj->display_if_report)) {
            return false;
        }
        if (isset($fj->display_if)
            && !$this->conf->xt_check($fj->display_if, $fj, $this->user)) {
            return false;
        }
        if (isset($fj->display_if_list_has)) {
            $ifl = $fj->display_if_list_has;
            foreach (is_array($ifl) ? $ifl : [$ifl] as $h) {
                if (!is_bool($h)) {
                    if (str_starts_with($h, "!")) {
                        $h = !$this->has(substr($h, 1));
                    } else {
                        $h = $this->has($h);
                    }
                }
                if (!$h) {
                    return false;
                }
            }
        }
        if (isset($fj->disabled) && $fj->disabled) {
            return false;
        }
        return true;
    }

    static function render_footer_row($arrow_ncol, $ncol, $header,
                            $lllgroups, $activegroup = -1, $extra = null) {
        $foot = "<tr class=\"pl_footrow\">\n   ";
        if ($arrow_ncol) {
            $foot .= '<td class="plf pl_footselector" colspan="' . $arrow_ncol . '">'
                . Icons::ui_upperleft() . "</td>\n   ";
        }
        $foot .= '<td id="plact" class="plf pl-footer linelinks" colspan="' . $ncol . '">';

        if ($header) {
            $foot .= "<table class=\"pl-footer-part\"><tbody><tr>\n"
                . '    <td class="pl-footer-desc">' . $header . "</td>\n"
                . '   </tr></tbody></table>';
        }

        foreach ($lllgroups as $i => $lllg) {
            $attr = ["class" => "linelink pl-footer-part"];
            if ($i === $activegroup) {
                $attr["class"] .= " active";
            }
            for ($j = 2; $j < count($lllg); ++$j) {
                if (is_array($lllg[$j])) {
                    foreach ($lllg[$j] as $k => $v) {
                        if (str_starts_with($k, "linelink-")) {
                            $k = substr($k, 9);
                            if ($k === "class") {
                                $attr["class"] .= " " . $v;
                            } else {
                                $attr[$k] = $v;
                            }
                        }
                    }
                }
            }
            $foot .= "<table";
            foreach ($attr as $k => $v) {
                $foot .= " $k=\"" . htmlspecialchars($v) . "\"";
            }
            $foot .= "><tbody><tr>\n"
                . "    <td class=\"pl-footer-desc lll\"><a class=\"ui lla\" href=\""
                . $lllg[0] . "\">" . $lllg[1] . "</a></td>\n";
            for ($j = 2; $j < count($lllg); ++$j) {
                $cell = is_array($lllg[$j]) ? $lllg[$j] : ["content" => $lllg[$j]];
                '@phan-var array{content:string} $cell';
                $attr = [];
                foreach ($cell as $k => $v) {
                    if ($k !== "content" && !str_starts_with($k, "linelink-")) {
                        $attr[$k] = $v;
                    }
                }
                if ($attr || isset($cell["content"])) {
                    $attr["class"] = rtrim("lld " . get($attr, "class", ""));
                    $foot .= "    <td";
                    foreach ($attr as $k => $v) {
                        $foot .= " $k=\"" . htmlspecialchars($v) . "\"";
                    }
                    $foot .= ">";
                    if ($j === 2
                        && isset($cell["content"])
                        && !str_starts_with($cell["content"], "<b>")) {
                        $foot .= "<b>:&nbsp;</b> ";
                    }
                    if (isset($cell["content"])) {
                        $foot .= $cell["content"];
                    }
                    $foot .= "</td>\n";
                }
            }
            if ($i < count($lllgroups) - 1) {
                $foot .= "    <td>&nbsp;<span class=\"barsep\">·</span>&nbsp;</td>\n";
            }
            $foot .= "   </tr></tbody></table>";
        }
        return $foot . (string) $extra . "<hr class=\"c\" /></td>\n </tr>";
    }

    private function _footer($ncol, $extra, Qrequest $qreq) {
        if ($this->count == 0) {
            return "";
        }

        $renderers = [];
        foreach ($this->conf->list_action_renderers() as $name => $fjs) {
            $rf = null;
            foreach ($fjs as $fj) {
                if (Conf::xt_priority_compare($fj, $rf) <= 0
                    && $this->conf->xt_allowed($fj, $this->user)
                    && $this->action_xt_displayed($fj)) {
                    $rf = $fj;
                }
            }
            if ($rf) {
                Conf::xt_resolve_require($rf);
                $renderers[] = $rf;
            }
        }
        usort($renderers, "Conf::xt_position_compare");

        $lllgroups = [];
        $whichlll = -1;
        foreach ($renderers as $rf) {
            if (($lllg = call_user_func($rf->render_callback, $this, $qreq, $rf))) {
                if (is_string($lllg)) {
                    $lllg = [$lllg];
                }
                array_unshift($lllg, $rf->name, $rf->title);
                $lllg[0] = $this->conf->selfurl($qreq, ["atab" => $lllg[0], "anchor" => "plact"]);
                $lllgroups[] = $lllg;
                if ($qreq->fn == $rf->name || $this->_atab == $rf->name) {
                    $whichlll = count($lllgroups) - 1;
                }
            }
        }

        $footsel_ncol = $this->_view_columns ? 0 : 1;
        return self::render_footer_row($footsel_ncol, $ncol - $footsel_ncol,
            "<b>Select papers</b> (or <a class=\"ui js-select-all\" href=\""
            . $this->conf->selfurl($qreq, ["selectall" => 1, "anchor" => "plact"])
            . '">select all ' . $this->count . "</a>), then&nbsp;",
            $lllgroups, $whichlll, $extra);
    }


    /** @return array{list<int>,list<TagAnno>} */
    function ids_and_groups() {
        $rows = $this->rowset();
        return [$rows->paper_ids(), $this->_groups];
    }

    /** @return list<int> */
    function paper_ids() {
        return $this->rowset()->paper_ids();
    }

    private function _listDescription() {
        switch ($this->_report_id) {
        case "reviewAssignment":
            return "Review assignments";
        case "editpref":
            return "Review preferences";
        case "reviewers":
        case "reviewersSel":
            return "Proposed assignments";
        default:
            return null;
        }
    }

    /** @return SessionList */
    function session_list_object() {
        assert($this->_groups !== null);
        return $this->search->create_session_list_object($this->paper_ids(), $this->_listDescription(), $this->sortdef());
    }

    private function _table_render($options) {
        $this->_prepare();
        // need tags for row coloring
        if ($this->user->can_view_tags(null)) {
            $this->qopts["tags"] = true;
        }

        // get column list
        $field_list = $this->_columns($this->_list_columns(), true, false);
        if (empty($field_list)) {
            return null;
        }

        $rows = $this->rowset();
        if ($rows->is_empty()) {
            if (($altq = $this->search->alternate_query())) {
                $altqh = htmlspecialchars($altq);
                $url = $this->search->url_site_relative_raw($altq);
                if (substr($url, 0, 5) == "search") {
                    $altqh = "<a href=\"" . htmlspecialchars(Navigation::siteurl() . $url) . "\">" . $altqh . "</a>";
                }
                return PaperListTableRender::make_error("No matching papers. Did you mean “{$altqh}”?");
            } else {
                return PaperListTableRender::make_error("No matching papers");
            }
        }

        // get field array
        $fieldDef = array();
        $ncol = $titlecol = 0;
        // folds: au:1, anonau:2, fullrow:3, aufull:4, force:5, rownum:6, statistics:7,
        // statistics-exist:8, [fields]
        $next_fold = 9;
        foreach ($field_list as $fdef) {
            if ($fdef->viewable()) {
                $fieldDef[$fdef->name] = $fdef;
                if ($fdef->fold === true) {
                    $fdef->fold = $next_fold;
                    ++$next_fold;
                }
            }
            if ($fdef->name == "title") {
                $titlecol = $ncol;
            }
            if ($fdef->viewable_column() && $fdef->is_visible) {
                ++$ncol;
            }
        }

        // count non-callout columns
        $skipcallout = 0;
        foreach ($fieldDef as $fdef) {
            if ($fdef->viewable_column()) {
                if ($fdef->position === null || $fdef->position >= 100)
                    break;
                else
                    ++$skipcallout;
            }
        }

        // create render state
        $rstate = new PaperListTableRender($ncol, $titlecol, $skipcallout);

        // prepare table attributes
        $this->table_attr["class"] = ["pltable"];
        if ($this->_table_class) {
            $this->table_attr["class"][] = $this->_table_class;
        }
        if ($options["list"] ?? false) {
            $this->table_attr["class"][] = "has-hotlist has-fold";
        }
        if ($this->_table_id) {
            $this->table_attr["id"] = $this->_table_id;
        }
        if (!empty($options["attributes"])) {
            foreach ($options["attributes"] as $n => $v) {
                $this->table_attr[$n] = $v;
            }
        }
        if ($options["fold_session_prefix"] ?? false) {
            $this->table_attr["data-fold-session-prefix"] = $options["fold_session_prefix"];
            $this->table_attr["data-fold-session"] = json_encode_browser([
                "2" => "anonau", "5" => "force", "6" => "rownum", "7" => "statistics"
            ]);
        }
        if ($this->search->is_order_anno) {
            $this->table_attr["data-order-tag"] = $this->search->is_order_anno;
        }
        if ($this->_groups) {
            $this->table_attr["data-groups"] = json_encode_browser($this->_groups);
        }
        if ($options["list"] ?? false) {
            $this->table_attr["data-hotlist"] = $this->session_list_object()->info_string();
        }
        if ($this->sortable && ($url = $this->search->url_site_relative_raw())) {
            $url = Navigation::siteurl() . $url . (strpos($url, "?") ? "&" : "?") . "sort={sort}";
            $this->table_attr["data-sort-url-template"] = $url;
        }

        // collect row data
        $body = array();
        $grouppos = empty($this->_groups) ? -1 : 0;
        $need_render = false;
        foreach ($rows as $row) {
            $this->_row_setup($row);
            if ($grouppos >= 0) {
                $grouppos = $this->_groups_for($grouppos, $rstate, $body, false);
            }
            $body[] = $this->_row_content($rstate, $row, $fieldDef);
            if ($this->need_render && !$need_render) {
                Ht::stash_script('$(plinfo.render_needed)', 'plist_render_needed');
                $need_render = true;
            }
            if ($this->need_render && $this->count % 16 == 15) {
                $body[count($body) - 1] .= "  " . Ht::script('plinfo.render_needed()') . "\n";
                $this->need_render = false;
            }
        }
        if ($grouppos >= 0 && $grouppos < count($this->_groups)) {
            $this->_groups_for($grouppos, $rstate, $body, true);
        }
        if ($this->count === 0) {
            return PaperListTableRender::make_error("No matching papers");
        }

        // analyze `has`, including authors
        foreach ($fieldDef as $fdef) {
            $this->mark_has($fdef->name, $fdef->has_content);
        }

        // statistics rows
        $tfoot = "";
        if (!$this->_view_columns) {
            $tfoot = $this->_statistics_rows($rstate, $fieldDef);
        }

        // analyze folds
        $this->_analyze_folds($rstate, $fieldDef);

        // header cells
        $colhead = "";
        if (!($options["noheader"] ?? false)) {
            $colhead .= " <thead class=\"pltable\">\n  <tr class=\"pl_headrow\">";

            foreach ($fieldDef as $fdef) {
                if (!$fdef->viewable_column() || !$fdef->is_visible) {
                    continue;
                }
                if ($fdef->has_content) {
                    $colhead .= "<th class=\"pl plh " . $fdef->className;
                    if ($fdef->fold) {
                        $colhead .= " fx" . $fdef->fold;
                    }
                    $colhead .= "\">";
                    if ($fdef->has_content) {
                        $colhead .= $this->_field_title($fdef);
                    }
                    $colhead .= "</th>";
                } else {
                    $colhead .= "<th";
                    if ($fdef->fold) {
                        $colhead .= " class=\"fx{$fdef->fold}\"";
                    }
                    $colhead .= "></th>";
                }
            }

            $colhead .= "</tr>\n";

            if ($this->search->is_order_anno
                && isset($this->table_attr["data-drag-tag"])) {
                $drag_tag = $this->tagger->check($this->table_attr["data-drag-tag"]);
                if (strcasecmp($drag_tag, $this->search->is_order_anno) === 0
                    && $this->user->can_change_tag_anno($drag_tag)) {
                    $colhead .= "  <tr class=\"pl_headrow pl_annorow\" data-anno-tag=\"{$this->search->is_order_anno}\">";
                    if ($rstate->titlecol)
                        $colhead .= "<td class=\"plh\" colspan=\"$rstate->titlecol\"></td>";
                    $colhead .= "<td class=\"plh\" colspan=\"" . ($rstate->ncol - $rstate->titlecol) . "\"><a class=\"ui js-annotate-order\" data-anno-tag=\"{$this->search->is_order_anno}\" href=\"\">Annotate order</a></td></tr>\n";
                }
            }

            $colhead .= " </thead>\n";
        }

        // table skeleton including fold classes
        $enter = "<table";
        foreach ($this->table_attr as $k => $v) {
            if (is_array($v) || is_object($v)) {
                $v = $k === "class" ? join(" ", $v) : json_encode_browser($v);
            }
            if ($k === "data-columns" || $k === "data-groups") {
                $enter .= " $k='" . str_replace("'", "&#039;", htmlspecialchars($v, ENT_NOQUOTES)) . "'";
            } else {
                $enter .= " $k=\"" . htmlspecialchars($v) . "\"";
            }
        }
        $rstate->table_start = $enter . ">\n";
        $rstate->table_end = "</table>";

        // maybe make columns, maybe not
        if ($this->_view_columns
            && !$this->rowset()->is_empty()
            && $this->_column_split($rstate, $colhead, $body)) {
            $rstate->table_start = '<div class="plsplit_col_ctr_ctr"><div class="plsplit_col_ctr">' . $rstate->table_start;
            $rstate->table_end .= "</div></div>";
            $ncol = $rstate->split_ncol;
            $rstate->tbody_class = "pltable-split";
        } else {
            $rstate->thead = $colhead;
            $rstate->tbody_class = "pltable" . ($rstate->hascolors ? " pltable-colored" : "");
        }
        if ($this->has_editable_tags) {
            $rstate->tbody_class .= " need-editable-tags";
        }

        // footer
        reset($fieldDef);
        if (current($fieldDef) instanceof Selector_PaperColumn
            && !($options["nofooter"] ?? false)) {
            $tfoot .= $this->_footer($ncol, get_s($options, "footer_extra"), $this->qreq);
        }
        if ($tfoot) {
            $rstate->tfoot = ' <tfoot class="pltable' . ($rstate->hascolors ? " pltable-colored" : "") . '">' . $tfoot . "</tfoot>\n";
        }

        $rstate->rows = $body;
        return $rstate;
    }

    /** @return PaperListTableRender */
    function table_render($options = []) {
        $overrides = $this->user->remove_overrides(Contact::OVERRIDE_CONFLICT);
        $rstate = $this->_table_render($options);
        $this->user->set_overrides($overrides);
        return $rstate;
    }

    /** @return string */
    function table_html($options = []) {
        $render = $this->table_render($options);
        if ($render->error) {
            return $render->error;
        } else {
            return $render->table_start
                . (self::$include_stash ? Ht::unstash() : "")
                . ($render->thead ? : "")
                . $render->tbody_start()
                . $render->body_rows()
                . $render->tbody_end()
                . ($render->tfoot ? : "")
                . "</table>";
        }
    }

    /** @return ?array{fields:array<string,object>,data:array<int,array{id:int}>,attr?:array,stat?:array} */
    function column_json($fields) {
        // get column list, check sort
        $this->_prepare();
        $field_list = $this->_columns($fields, false, true);
        if (empty($field_list)) {
            return null;
        }

        // turn off forceShow
        $overrides = $this->user->remove_overrides(Contact::OVERRIDE_CONFLICT);

        // output field data
        $data = $attr = [];
        foreach ($this->rowset() as $row) {
            $this->_row_setup($row);
            $p = ["id" => $row->paperId];
            foreach ($field_list as $fdef) {
                list($empty, $content) = $this->_row_field_content($fdef, $row);
                if ($content !== "") {
                    $p[$fdef->name] = $content;
                }
            }
            $data[$row->paperId] = $p;
            foreach ($this->row_attr as $k => $v) {
                if (!isset($attr[$row->paperId])) {
                    $attr[$row->paperId] = [];
                }
                $attr[$row->paperId][$k] = $v;
            }
        }

        // analyze `has`, including authors
        foreach ($field_list as $fdef) {
            $this->mark_has($fdef->name, $fdef->has_content);
        }

        // output fields and statistics
        $fields = $stats = [];
        foreach ($field_list as $fdef) {
            $fields[$fdef->name] = $fdef->field_json($this);
            if ($fdef->has_statistics()) {
                $stat = [];
                foreach (self::$stats as $s) {
                    $stat[ScoreInfo::$stat_keys[$s]] = $fdef->statistic($this, $s);
                }
                $stats[$fdef->name] = $stat;
            }
        }

        // restore forceShow
        $this->user->set_overrides($overrides);

        // output
        $result = ["fields" => $fields, "data" => $data];
        if (!empty($attr)) {
            $result["attr"] = $attr;
        }
        if (!empty($stats)) {
            $result["stat"] = $stats;
        }
        return $result;
    }

    /** @return array<int,object> */
    function text_json($fields) {
        // get column list, check sort
        $this->_prepare();
        $field_list = $this->_columns($fields, false, true);
        $data = [];
        if (!empty($field_list)) {
            foreach ($this->rowset() as $row) {
                $this->_row_setup($row);
                $p = ["id" => $row->paperId];
                foreach ($field_list as $fdef) {
                    if ($fdef->viewable()
                        && !$fdef->content_empty($this, $row)
                        && ($text = $fdef->text($this, $row)) !== "") {
                        $p[$fdef->name] = $text;
                    }
                }
                $data[$row->paperId] = (object) $p;
            }
        }
        return $data;
    }

    /** @return array<string,string> */
    private function _row_text_csv_data(PaperInfo $row, $fieldDef) {
        $csv = [];
        foreach ($fieldDef as $fdef) {
            $empty = $fdef->content_empty($this, $row);
            $c = $empty ? "" : $fdef->text($this, $row);
            if ($c !== "") {
                $fdef->has_content = true;
            }
            $csv[$fdef->name] = $c;
        }
        return $csv;
    }

    private function _groups_for_csv($grouppos, &$csv) {
        for (; $grouppos < count($this->_groups)
               && $this->_groups[$grouppos]->pos < $this->count;
               ++$grouppos) {
            $ginfo = $this->_groups[$grouppos];
            $csv["__precomment__"] = $ginfo->is_empty() ? "none" : $ginfo->heading;
        }
        return $grouppos;
    }

    /** @return array{array<string,string>,list<array<string,string>>} */
    function text_csv($options = []) {
        // get column list, check sort
        $this->_prepare();
        $field_list = $this->_columns($this->_list_columns(), true, false); /* XXX */

        // get field array
        $fieldDef = [];
        foreach ($field_list as $fdef) {
            if ($fdef->viewable()
                && $fdef->is_visible
                && $fdef->header($this, true) != "") {
                $fieldDef[] = $fdef;
            }
        }

        // collect row data
        $body = [];
        $grouppos = empty($this->_groups) ? -1 : 0;
        foreach ($this->rowset() as $row) {
            $this->_row_setup($row);
            $csv = $this->_row_text_csv_data($row, $fieldDef);
            if ($grouppos >= 0) {
                $grouppos = $this->_groups_for_csv($grouppos, $csv);
            }
            $body[] = $csv;
        }

        // header cells
        $header = [];
        foreach ($fieldDef as $fdef) {
            if ($fdef->has_content) {
                $header[$fdef->name] = $fdef->header($this, true);
            }
        }

        return [$header, $body];
    }


    function viewer_list() {
        $this->_prepare();
        $field_list = $this->_columns($this->_list_columns(), false, false);
        $res = [];
        foreach ($this->_viewing as $k => $v) {
            if (!$v) {
                // skip
            } else if (isset(self::$view_fake[$k])) {
                $key = self::$view_fake[$k] . " " . $k;
                $res[$key] = "show:$k";
            } else {
                foreach ($this->_expand_view_column($k, false) as $col) {
                    $key = ($col->position ? : 0) . " " . $col->name;
                    $res[$key] = ($v === true ? "show" : $v) . ":" . PaperSearch::escape_word($col->name);
                }
            }
        }
        if (((get($this->_viewing, "anonau") && $this->conf->submission_blindness() == Conf::BLIND_OPTIONAL)
             || get($this->_viewing, "aufull"))
            && !get($this->_viewing, "au")) {
            $res["150 authors"] = "hide:authors";
        }
        ksort($res, SORT_NATURAL);
        $res = array_values($res);

        foreach ($this->sorters() as $s) {
            $sn = $s->field->sort_name($this, $s);
            $res[] = "sort:" . PaperSearch::escape_word($sn . ($s->reverse ? ",reverse" : ""));
            if ($sn === "id") {
                break;
            }
        }
        while (!empty($res) && $res[count($res) - 1] === "sort:id") {
            array_pop($res);
        }
        return $res;
    }

    static function viewer_diff($v1, $v2) {
        $res = [];
        foreach ($v1 as $x) {
            if (!str_starts_with($x, "show:") || !in_array($x, $v2))
                $res[] = $x;
        }
        foreach ($v2 as $x) {
            if (str_starts_with($x, "show:") && !in_array($x, $v1))
                $res[] = "hide:" . substr($x, 5);
        }
        return $res;
    }
}
