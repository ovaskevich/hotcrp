<?php
// papertable.php -- HotCRP helper class for producing paper tables
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class PaperTable {
    /** @var Conf */
    public $conf;
    /** @var PaperInfo */
    public $prow;
    /** @var Contact */
    public $user;
    /** @var list<ReviewInfo> */
    private $all_rrows = [];
    /** @var list<ReviewInfo> */
    private $viewable_rrows = [];
    /** @var array<int,CommentInfo> */
    private $crows;
    /** @var array<int,CommentInfo> */
    private $mycrows;
    /** @var bool */
    private $can_view_reviews;
    /** @var ?ReviewInfo */
    public $rrow;
    /** @var ?ReviewInfo */
    public $editrrow;
    /** @var string */
    public $mode;
    /** @var string */
    private $first_mode;
    private $prefer_approvable = false;
    private $allreviewslink;
    /** @var ?PaperStatus */
    private $edit_status;

    public $editable;
    /** @var list<PaperOption> */
    public $edit_fields;
    /** @var int */
    public $edit_fields_position;

    private $qreq;
    private $useRequest;
    /** @var ?ReviewValues */
    private $review_values;
    private $npapstrip = 0;
    private $allFolded;
    private $matchPreg;
    private $entryMatches;
    private $canUploadFinal;
    private $foldmap;
    private $foldnumber;

    /** @var bool */
    private $allow_admin;
    /** @var bool */
    private $admin;

    /** @var ?CheckFormat */
    private $cf;
    private $quit = false;

    function __construct(PaperInfo $prow = null, Qrequest $qreq, $mode = null) {
        global $Conf, $Me;

        $this->conf = $Conf;
        $this->user = $user = $Me;
        $this->prow = $prow ? : PaperInfo::make_new($user);
        $this->allow_admin = $user->allow_administer($prow);
        $this->admin = $user->can_administer($prow);
        $this->qreq = $qreq;

        $this->canUploadFinal = $this->user->allow_edit_final_paper($this->prow);

        if (!$prow || !$this->prow->paperId) {
            $this->can_view_reviews = false;
            $this->mode = $this->first_mode = "edit";
            return;
        }

        $this->can_view_reviews = $user->can_view_review($prow, null)
            || $prow->review_submitted($user);

        // enumerate allowed modes
        if ($prow->has_author($user)
            && !$user->can_view_review($prow, null)
            && $this->conf->timeFinalizePaper($prow)) {
            $this->first_mode = "edit";
        } else if ($user->can_review($prow, null)
                   && $qreq->page() === "review") {
            $this->first_mode = "re";
        } else {
            $this->first_mode = "p";
        }

        $ms = ["p" => true];
        if ($user->can_review($prow, null)) {
            $ms["re"] = true;
        }
        if ($prow->has_author($user) || $this->allow_admin) {
            $ms["edit"] = true;
        }
        if ($prow->review_type($user) >= REVIEW_SECONDARY || $this->allow_admin) {
            $ms["assign"] = true;
        }
        if (!$mode) {
            $mode = $this->qreq->m ? : $this->qreq->mode;
        }
        if ($mode === "pe") {
            $mode = "edit";
        } else if ($mode === "view" || $mode === "r" || $mode === "main") {
            $mode = "p";
        } else if ($mode === "rea") {
            $mode = "re";
            $this->prefer_approvable = true;
        }
        if ($mode && isset($ms[$mode])) {
            $this->mode = $mode;
        } else {
            $this->mode = $this->first_mode;
        }
        if (isset($ms["re"]) && isset($this->qreq->reviewId)) {
            $this->mode = "re";
        }
    }

    static function do_header($paperTable, $id, $action_mode, $qreq) {
        global $Conf, $Me;
        $prow = $paperTable ? $paperTable->prow : null;
        $format = 0;

        $t = '<header id="header-page" class="header-page-submission"><h1 class="paptitle';

        if (!$paperTable) {
            if (($pid = $qreq->paperId) && ctype_digit($pid)) {
                $title = "#$pid";
            } else {
                $title = $Conf->_c("paper_title", "Submission");
            }
            $t .= '">' . $title;
        } else if (!$prow->paperId) {
            $title = $Conf->_c("paper_title", "New submission");
            $t .= '">' . $title;
        } else {
            $paperTable->initialize_list();
            $title = "#" . $prow->paperId;
            $viewable_tags = $prow->viewable_tags($Me);
            if ($viewable_tags || $Me->can_view_tags($prow)) {
                $t .= ' has-tag-classes';
                if (($color = $prow->conf->tags()->color_classes($viewable_tags)))
                    $t .= ' ' . $color;
            }
            $t .= '"><a class="q" href="' . $prow->hoturl()
                . '"><span class="taghl"><span class="pnum">' . $title . '</span>'
                . ' &nbsp; ';

            $highlight_text = null;
            $title_matches = 0;
            if ($paperTable->matchPreg
                && ($highlight = $paperTable->matchPreg["title"] ?? null)) {
                $highlight_text = Text::highlight($prow->title, $highlight, $title_matches);
            }

            if (!$title_matches && ($format = $prow->title_format())) {
                $t .= '<span class="ptitle need-format" data-format="' . $format . '">';
            } else {
                $t .= '<span class="ptitle">';
            }
            if ($highlight_text) {
                $t .= $highlight_text;
            } else if ($prow->title === "") {
                $t .= "[No title]";
            } else {
                $t .= htmlspecialchars($prow->title);
            }

            $t .= '</span></span></a>';
            if ($viewable_tags && $Conf->tags()->has_decoration) {
                $tagger = new Tagger($Me);
                $t .= $tagger->unparse_decoration_html($viewable_tags);
            }
        }

        $t .= '</h1></header>';
        if ($paperTable && $prow->paperId) {
            $t .= $paperTable->_paptabBeginKnown();
        }

        $Conf->header($title, $id, [
            "action_bar" => actionBar($action_mode, $qreq),
            "title_div" => $t, "body_class" => "paper", "paperId" => $qreq->paperId
        ]);
        if ($format) {
            echo Ht::unstash_script("render_text.on_page()");
        }
    }

    private function initialize_list() {
        assert(!$this->conf->has_active_list());
        $list = $this->find_session_list();
        $this->conf->set_active_list($list);

        $this->matchPreg = [];
        if (($list = $this->conf->active_list())
            && $list->highlight
            && preg_match('_\Ap/([^/]*)/([^/]*)(?:/|\z)_', $list->listid, $m)) {
            $hlquery = is_string($list->highlight) ? $list->highlight : urldecode($m[2]);
            $ps = new PaperSearch($this->user, ["t" => $m[1], "q" => $hlquery]);
            foreach ($ps->field_highlighters() as $k => $v) {
                $this->matchPreg[$k] = $v;
            }
        }
        if (empty($this->matchPreg)) {
            $this->matchPreg = null;
        }
    }
    private function find_session_list() {
        $prow = $this->prow;
        if ($prow->paperId <= 0) {
            return null;
        }

        if (($list = SessionList::load_cookie($this->user, "p"))
            && ($list->set_current_id($prow->paperId) || $list->digest)) {
            return $list;
        }

        // look up list description
        $list = null;
        $listdesc = $this->qreq->ls;
        if ($listdesc) {
            if (($opt = PaperSearch::unparse_listid($listdesc))) {
                $list = $this->try_list($opt, $prow);
            }
            if (!$list && preg_match('{\A(all|s):(.*)\z}s', $listdesc, $m)) {
                $list = $this->try_list(["t" => $m[1], "q" => $m[2]], $prow);
            }
            if (!$list && preg_match('{\A[a-z]+\z}', $listdesc)) {
                $list = $this->try_list(["t" => $listdesc], $prow);
            }
            if (!$list) {
                $list = $this->try_list(["q" => $listdesc], $prow);
            }
        }

        // default lists
        if (!$list) {
            $list = $this->try_list([], $prow);
        }
        if (!$list && $this->user->privChair) {
            $list = $this->try_list(["t" => "all"], $prow);
        }

        return $list;
    }
    private function try_list($opt, $prow) {
        $srch = new PaperSearch($this->user, $opt);
        if ($srch->test($prow)) {
            $list = $srch->session_list_object();
            $list->set_current_id($prow->paperId);
            return $list;
        } else {
            return null;
        }
    }

    private static function _combine_match_preg($m1, $m) {
        if (is_object($m)) {
            $m = get_object_vars($m);
        }
        if (!is_array($m)) {
            $m = ["abstract" => $m, "title" => $m,
                  "authorInformation" => $m, "collaborators" => $m];
        }
        foreach ($m as $k => $v) {
            if (!isset($m1[$k]) || !$m1[$k])
                $m1[$k] = $v;
        }
        return $m1;
    }

    function initialize($editable, $useRequest) {
        $this->editable = $editable;
        $this->useRequest = $useRequest;
        $this->allFolded = $this->mode === "re" || $this->mode === "assign"
            || ($this->mode !== "edit"
                && (!empty($this->all_rrows) || !empty($this->crows)));
    }

    function set_edit_status(PaperStatus $status) {
        $this->edit_status = $status;
    }

    function set_review_values(ReviewValues $rvalues = null) {
        $this->review_values = $rvalues;
    }

    /** @return bool */
    function can_view_reviews() {
        return $this->can_view_reviews;
    }

    private function abstract_foldable($abstract) {
        return strlen($abstract) > 190;
    }

    private function echoDivEnter() {
        // 5: topics, 6: abstract, 7: [JavaScript abstract expansion],
        // 8: blind authors, 9: full authors
        $foldstorage = [5 => "t", 6 => "b", 8 => "a", 9 => "p"];
        $this->foldnumber = ["topics" => 5];

        // other expansions
        $next_foldnum = 10;
        foreach ($this->conf->paper_opts->field_list($this->prow) as $o) {
            if ($o->display_position() !== false
                && $o->display_position() >= 1000
                && $o->display_position() < 5000
                && ($o->id <= 0 || $this->user->allow_view_option($this->prow, $o))
                && $o->display_group !== null) {
                if (strlen($o->display_group) > 1
                    && !isset($this->foldnumber[$o->display_group])) {
                    $this->foldnumber[$o->display_group] = $next_foldnum;
                    $foldstorage[$next_foldnum] = str_replace(" ", "_", $o->display_group);
                    ++$next_foldnum;
                }
                if ($o->display_expand) {
                    $this->foldnumber[$o->formid] = $next_foldnum;
                    $foldstorage[$next_foldnum] = $o->formid;
                    ++$next_foldnum;
                }
            }
        }

        // what is folded?
        // if highlighting, automatically unfold abstract/authors
        $this->foldmap = [];
        foreach ($foldstorage as $num => $k) {
            $this->foldmap[$num] = $this->allFolded || $k === "a";
        }
        if ($this->foldmap[6]) {
            $abstract = $this->entryData("abstract");
            if ($this->entryMatches || !$this->abstract_foldable($abstract)) {
                $this->foldmap[6] = false;
            }
        }
        if ($this->matchPreg && ($this->foldmap[8] || $this->foldmap[9])) {
            $this->entryData("authorInformation"); // check entryMatches
            if ($this->entryMatches) {
                $this->foldmap[8] = $this->foldmap[9] = false;
            }
        }

        // collect folders
        $folders = ["need-fold-storage"];
        foreach ($this->foldmap as $num => $f) {
            if ($num !== 8 || $this->user->view_authors_state($this->prow) === 1) {
                $folders[] = "fold" . $num . ($f ? "c" : "o");
            }
        }

        // echo div
        echo '<div id="foldpaper" class="', join(" ", $folders),
            '" data-fold-storage-prefix="p." data-fold-storage="',
            htmlspecialchars(json_encode_browser($foldstorage)), '">';
        Ht::stash_script("fold_storage()");
    }

    private function problem_status_at($f) {
        if ($this->edit_status) {
            if (str_starts_with($f, "au")) {
                if ($f === "authorInformation") {
                    $f = "authors";
                } else if (preg_match('/\A.*?(\d+)\z/', $f, $m)
                           && ($ps = $this->edit_status->problem_status_at("author$m[1]"))) {
                    return $ps;
                }
            }
            return $this->edit_status->problem_status_at($f);
        } else {
            return 0;
        }
    }
    function has_problem_at($f) {
        return $this->problem_status_at($f) != 0;
    }
    function has_error_class($f) {
        return $this->has_problem_at($f) ? " has-error" : "";
    }
    function control_class($f, $rest = "", $prefix = "has-") {
        return MessageSet::status_class($this->problem_status_at($f), $rest, $prefix);
    }

    private function echo_editable_papt($what, $heading, $extra = [], PaperOption $opt = null) {
        if ($opt && !isset($extra["for"])) {
            $for = $opt->readable_formid();
        } else {
            $for = $extra["for"] ?? false;
        }
        echo '<div class="papeg';
        if ($opt && $opt->exists_condition()) {
            echo ' has-edit-condition';
            if (!$opt->test_exists($this->prow)) {
                echo ' hidden';
            }
            echo '" data-edit-condition="', htmlspecialchars(json_encode($opt->compile_exists_condition($this->prow)));
            Ht::stash_script('$(edit_paper_ui.edit_condition)', 'edit_condition');
        }
        echo '"><h3 class="', $this->control_class($what, "papet");
        if ($for === "checkbox") {
            echo " checki";
        }
        if (($tclass = $extra["tclass"] ?? false)) {
            echo " ", ltrim($tclass);
        }
        if (($id = $extra["id"] ?? false)) {
            echo '" id="' . $id;
        }
        echo '">', Ht::label($heading, $for === "checkbox" ? false : $for, ["class" => "papfn"]), '</h3>';
    }

    /** @param array<string,int|string> $extra */
    private function papt($what, $name, $extra = []) {
        $fold = $extra["fold"] ?? false;
        $editfolder = $extra["editfolder"] ?? false;
        $foldnum = $foldnumclass = false;
        if ($fold || $editfolder) {
            $foldnum = $extra["foldnum"] ?? 0;
            $foldnumclass = $foldnum ? " data-fold-target=\"$foldnum\"" : "";
        }

        if (($extra["type"] ?? null) === "ps") {
            list($divclass, $hdrclass) = ["pst", "psfn"];
        } else {
            list($divclass, $hdrclass) = ["pavt", "pavfn"];
        }

        $c = "<div class=\"" . $this->control_class($what, $divclass);
        if (($fold || $editfolder) && !($extra["float"] ?? false)) {
            $c .= " ui js-foldup\"" . $foldnumclass . ">";
        } else {
            $c .= "\">";
        }
        $c .= "<h3 class=\"$hdrclass";
        if (isset($extra["fnclass"])) {
            $c .= " " . $extra["fnclass"];
        }
        $c .= '">';
        if (!$fold) {
            $n = (is_array($name) ? $name[0] : $name);
            if ($editfolder) {
                $c .= "<a class=\"q fn ui js-foldup\" "
                    . "href=\"" . $this->conf->selfurl($this->qreq, ["atab" => $what])
                    . "\"" . $foldnumclass . ">" . $n
                    . '<span class="t-editor">✎ </span>'
                    . "</a><span class=\"fx\">" . $n . "</span>";
            } else {
                $c .= $n;
            }
        } else {
            '@phan-var-force int $foldnum';
            '@phan-var-force string $foldnumclass';
            $c .= '<a class="q ui js-foldup" href=""' . $foldnumclass;
            if (($title = $extra["foldtitle"] ?? false)) {
                $c .= ' title="' . $title . '"';
            }
            if (isset($this->foldmap[$foldnum])) {
                $c .= ' role="button" aria-expanded="' . ($this->foldmap[$foldnum] ? "false" : "true") . '"';
            }
            $c .= '>' . expander(null, $foldnum);
            if (!is_array($name)) {
                $name = array($name, $name);
            }
            if ($name[0] !== $name[1]) {
                $c .= '<span class="fn' . $foldnum . '">' . $name[1] . '</span><span class="fx' . $foldnum . '">' . $name[0] . '</span>';
            } else {
                $c .= $name[0];
            }
            $c .= '</a>';
        }
        $c .= "</h3>";
        if (isset($extra["float"])) {
            $c .= $extra["float"];
        }
        $c .= "</div>";
        return $c;
    }

    private function entryData($fieldName, $table_type = false) {
        $this->entryMatches = 0;
        $text = $this->prow->$fieldName;
        if ($this->matchPreg
            && isset($this->matchPreg[$fieldName])) {
            $text = Text::highlight($text, $this->matchPreg[$fieldName], $this->entryMatches);
        } else {
            $text = htmlspecialchars($text);
        }
        return $table_type === "col" ? nl2br($text) : $text;
    }

    function messages_at($field, $klass = "f-h") {
        $t = "";
        foreach ($this->edit_status ? $this->edit_status->message_list_at($field) : [] as $mx) {
            $t .= '<p class="' . MessageSet::status_class($mx[2], $klass, "is-") . '">' . $mx[1] . '</p>';
        }
        return $t;
    }

    /** @param PaperOption $opt */
    private function echo_field_hint($opt) {
        echo $this->messages_at($opt->formid, "feedback");
        $fr = new FieldRender(FieldRender::CFHTML);
        $fr->value_format = 5;
        if ($opt->description_format !== null) {
            $fr->value_format = $opt->description_format;
        }
        $this->conf->ims()->render_xci($fr, "field_description/edit",
                                       $opt->formid, $opt->description);
        if (!$fr->is_empty()) {
            echo $fr->value_html("field-d");
        }
    }

    /** @param PaperOption $opt */
    function edit_title_html($opt) {
        $t = $opt->edit_title();
        if (str_ends_with($t, ")")
            && preg_match('{\A([^()]* +)(\([^()]+\))\z}', $t, $m)) {
            return htmlspecialchars($m[1]) . '<span class="n">' . htmlspecialchars($m[2]) . '</span>';
        } else {
            return htmlspecialchars($t);
        }
    }

    static function pdf_stamps_html($data, $options = null) {
        global $Conf;
        $tooltip = !$options || !get($options, "notooltip");
        $t = [];

        $tm = get($data, "timestamp", get($data, "timeSubmitted", 0));
        if ($tm > 0) {
            $t[] = ($tooltip ? '<span class="nb need-tooltip" aria-label="Upload time">' : '<span class="nb">')
                . '<svg width="12" height="12" viewBox="0 0 96 96" class="licon"><path d="M48 6a42 42 0 1 1 0 84 42 42 0 1 1 0-84zm0 10a32 32 0 1 0 0 64 32 32 0 1 0 0-64zM48 19A5 5 0 0 0 43 24V46c0 2.352.37 4.44 1.464 5.536l12 12c4.714 4.908 12-2.36 7-7L53 46V24A5 5 0 0 0 43 24z"/></svg>'
                . " " . $Conf->unparse_time($tm) . "</span>";
        }

        $ha = new HashAnalysis(get($data, "sha1"));
        if ($ha->ok()) {
            $h = $ha->text_data();
            $x = '<span class="nb checksum';
            if ($tooltip) {
                $x .= ' need-tooltip" data-tooltip="';
                if ($ha->algorithm() === "sha256")  {
                    $x .= "SHA-256 checksum";
                } else if ($ha->algorithm() === "sha1") {
                    $x .= "SHA-1 checksum";
                }
            }
            $x .= '"><svg width="12" height="12" viewBox="0 0 48 48" class="licon"><path d="M19 32l-8-8-7 7 14 14 26-26-6-6-19 19zM15 3V10H8v5h7v7h5v-7H27V10h-7V3h-5z"/></svg> '
                . '<span class="checksum-overflow">' . $h . '</span>'
                . '<span class="checksum-abbreviation">' . substr($h, 0, 8) . '</span></span>';
            $t[] = $x;
        }

        if (!empty($t)) {
            return '<span class="hint">' . join(' <span class="barsep">·</span> ', $t) . "</span>";
        } else {
            return "";
        }
    }

    /** @param PaperOption $o */
    function render_submission(FieldRender $fr, $o) {
        assert(!$this->editable);
        $fr->title = false;
        $fr->value = "";
        $fr->value_format = 5;

        // conflicts
        if ($this->user->isPC
            && !$this->prow->has_conflict($this->user)
            && $this->conf->timeUpdatePaper($this->prow)
            && $this->mode !== "assign"
            && $this->mode !== "contact"
            && $this->prow->outcome >= 0) {
            $fr->value .= Ht::msg('The authors still have <a href="' . $this->conf->hoturl("deadlines") . '">time</a> to make changes.', 1);
        }

        // download
        if ($this->user->can_view_pdf($this->prow)) {
            $dprefix = "";
            $dtype = $this->prow->finalPaperStorageId > 1 ? DTYPE_FINAL : DTYPE_SUBMISSION;
            if (($doc = $this->prow->document($dtype))
                && $doc->paperStorageId > 1) {
                if (($stamps = self::pdf_stamps_html($doc))) {
                    $stamps = '<span class="sep"></span>' . $stamps;
                }
                $stamps = $stamps . self::paptabTemplateText('submissionLinkTemplate');
                if ($dtype == DTYPE_FINAL) {
                    $dhtml = $o->title_html();
                } else {
                    $dhtml = $o->title_html($this->prow->timeSubmitted != 0);
                }
                $fr->value .= '<p class="pgsm">' . $dprefix . $doc->link_html('<span class="pavfn">' . $dhtml . '</span>', DocumentInfo::L_REQUIREFORMAT) . $stamps . '</p>';
            }
        }
    }

    /** @param PaperOption $o */
    function render_submission_version(FieldRender $fr, $o) {
        if ($this->user->can_view_pdf($this->prow)
            && $this->prow->finalPaperStorageId > 1
            && $this->prow->paperStorageId > 1) {
            $fr->title = false;
            $dname = $this->conf->_c("field", "Submission version");
            $fr->set_html('<p class="pgsm"><small>' . $this->prow->document(DTYPE_SUBMISSION)->link_html(htmlspecialchars($dname), DocumentInfo::L_SMALL | DocumentInfo::L_NOSIZE) . "</small></p>");
        }
    }

    private function is_ready($checkbox) {
        if ($this->useRequest) {
            return !!$this->qreq->submitpaper
                && ($checkbox
                    || $this->conf->opt("noPapers")
                    || $this->prow->paperStorageId > 1);
        } else {
            return $this->prow->timeSubmitted > 0
                || ($checkbox
                    && !$this->conf->setting("sub_freeze")
                    && (!$this->prow->paperId
                        || (!$this->conf->opt("noPapers") && $this->prow->paperStorageId <= 1)));
        }
    }

    private function echo_editable_complete() {
        if ($this->canUploadFinal) {
            echo Ht::hidden("submitpaper", 1);
            return;
        }

        $checked = $this->is_ready(true);
        echo '<div class="ready-container ',
            ($this->prow->paperStorageId > 1
             || $this->conf->opt("noPapers") ? "foldo" : "foldc"),
            '"><div class="checki fx"><span class="checkc">',
            Ht::checkbox("submitpaper", 1, $checked, ["class" => "uich js-check-submittable"]),
            " </span>";
        if ($this->conf->setting("sub_freeze")) {
            echo Ht::label("<strong>" . $this->conf->_("The submission is complete") . "</strong>"),
                '<p class="settings-ap hint">You must complete your submission before the deadline or it will not be reviewed. Completed submissions are frozen and cannot be changed further.</p>';
        } else {
            echo Ht::label("<strong>" . $this->conf->_("The submission is ready for review") . "</strong>");
        }
        echo "</div></div>\n";
    }

    static function document_upload_input($inputid, $dtype, $accepts) {
        $t = '<input id="' . $inputid . '" type="file" name="' . $inputid . '"';
        if ($accepts !== null && count($accepts) == 1) {
            $t .= ' accept="' . $accepts[0]->mimetype . '"';
        }
        $t .= ' size="30" class="';
        $k = ["uich", "document-uploader"];
        if ($dtype == DTYPE_SUBMISSION || $dtype == DTYPE_FINAL) {
            $k[] = "js-check-submittable primary-document";
        }
        return $t . join(" ", $k) . '">';
    }

    function echo_editable_document(PaperOption $docx, $storageId) {
        $dtype = $docx->id;
        if ($dtype == DTYPE_SUBMISSION || $dtype == DTYPE_FINAL) {
            $noPapers = $this->conf->opt("noPapers");
            if ($noPapers === 1
                || $noPapers === true
                || ($dtype == DTYPE_FINAL) !== $this->canUploadFinal)
                return;
        }
        $inputid = "opt" . $dtype;

        $accepts = $docx->mimetypes();
        $field = $docx->field_key();
        $doc = null;
        if ($storageId > 1 && $this->user->can_view_pdf($this->prow)) {
            $doc = $this->prow->document($dtype, $storageId, true);
        }
        $max_size = $docx->max_size ?? $this->conf->opt("uploadMaxFilesize") ?? ini_get_bytes("upload_max_filesize") / 1.024;

        $heading = $this->edit_title_html($docx);
        $msgs = [];
        if ($accepts) {
            $msgs[] = htmlspecialchars(Mimetype::list_description($accepts));
        }
        if ($max_size > 0) {
            $msgs[] = "max " . unparse_byte_size($max_size);
        }
        if (!empty($msgs)) {
            $heading .= ' <span class="n">(' . join(", ", $msgs) . ')</span>';
        }
        $this->echo_editable_papt($field, $heading, ["for" => $doc ? false : $inputid, "id" => $docx->readable_formid()], $docx);
        $this->echo_field_hint($docx);
        echo Ht::hidden("has_" . $docx->formid, 1),
            '<div class="papev has-document" data-dtype="', $dtype,
            '" data-document-name="', $docx->field_key(), '"';
        if ($doc) {
            echo ' data-docid="', $doc->paperStorageId, '"';
        }
        if ($accepts) {
            echo ' data-document-accept="', htmlspecialchars(join(",", array_map(function ($m) { return $m->mimetype; }, $accepts))), '"';
        }
        if ($max_size > 0) {
            echo ' data-document-max-size="', (int) $max_size, '"';
        }
        echo '>';

        // current version, if any
        $has_cf = false;
        if ($doc) {
            if ($doc->mimetype === "application/pdf") {
                if (!$this->cf)
                    $this->cf = new CheckFormat($this->conf, CheckFormat::RUN_NO);
                $spec = $this->conf->format_spec($dtype);
                $has_cf = $spec && !$spec->is_empty();
                if ($has_cf) {
                    $this->cf->check_document($this->prow, $doc);
                }
            }

            echo '<div class="document-file">',
                $doc->link_html(htmlspecialchars($doc->filename ? : "")),
                '</div><div class="document-stamps">';
            if (($stamps = self::pdf_stamps_html($doc))) {
                echo $stamps;
            }
            echo '</div><div class="document-actions">';
            if ($dtype > 0) {
                echo '<a href="" class="ui js-remove-document document-action">Delete</a>';
            }
            if ($has_cf
                && ($this->cf->failed || $this->cf->need_run || $this->cf->possible_run)) {
                echo '<a href="" class="ui js-check-format document-action">',
                    ($this->cf->failed || $this->cf->need_run ? "Check format" : "Recheck format"),
                    '</a>';
            } else if ($has_cf && !$this->cf->has_problem()) {
                echo '<span class="document-action js-check-format dim">Format OK</span>';
            }
            echo '</div>';
            if ($has_cf) {
                echo '<div class="document-format">';
                if (!$this->cf->failed && $this->cf->has_problem()) {
                    echo $this->cf->document_report($this->prow, $doc);
                }
                echo '</div>';
            }
        }

        echo '<div class="document-replacer">',
            Ht::button($doc ? "Replace" : "Upload", ["class" => "ui js-replace-document", "id" => $inputid]),
            "</div></div></div>\n\n";
    }

    function startsWith($haystack, $needle) {
        return $needle === "" || strrpos($haystack, $needle, -strlen($haystack)) !== false;
    }

    // template text replacement
    // conference option $optionName contains html template which is
    // filled the paper data here. Used for custom summary (ahead of 
    // abstract and for custom link
    private function paptabTemplateText($optionName) {
        global $Opt;
        // get options of this paper
        $options = $this->prow->options();
        // load the template from conference definition
        $summaryTemplate = $this->conf->opt($optionName);
        // if no template, return 
        if (!$summaryTemplate) {
            return false;
        }
        $summary = "";

        // First, process all the conditionals.
        $conditionalStart = 0;
        $conditionalEnd = 0;

        // define constants for template "language" but these constants
        // only need to be defined once for each runtime (however template
        // text can be used multiple times leading to warnings)
        // hence, conditionally define if not yet defined
        if (! defined('BEGIN_IF')) {
          define("BEGIN_IF", "%%%BEGIN_IF{");
          define("BEGIN_IF_LEN", strlen(BEGIN_IF));
          define("BEGIN_IF_END", "}%%%");
          define("BEGIN_IF_END_LEN", strlen(BEGIN_IF_END));
          define("END_IF", "%%%END_IF%%%");
          define("END_IF_LEN", strlen(END_IF));
        }
        
        // iterate through template while conditionals are found 
        //  %%%BEGIN_IF{variable}%%%
        while (($conditionalStart = strpos($summaryTemplate, BEGIN_IF, $conditionalEnd)) !== false) {
            // construct summary string excluding the conditional
            $summary .= substr($summaryTemplate, $conditionalEnd, $conditionalStart - $conditionalEnd);

            // Find the ending "}%%%".
            $varStart = $conditionalStart + BEGIN_IF_LEN;
            $varEnd = strpos($summaryTemplate, BEGIN_IF_END, $conditionalStart);
            // cut out the option name 
            $var = substr($summaryTemplate, $varStart, $varEnd - $varStart);
            $expectedValue = true;
            // Handle negations. Note space before ! is not allowed
            if ($var && strlen($var) > 0 && $var[0] == "!") {
              $expectedValue = false;
              // variable name without the leading !
              $var = substr($var, 1);
            }
            // get reference to the paper option based on variable name
            $varOption = reset(array_filter($options, function ($o) use ($var) {return $o->option->name == $var;}));
            // get positions of where the conditional section ends
            //TODO nested BEGIN_IF not yet supported
            $contentStart = $varEnd + BEGIN_IF_END_LEN;
            $contentEnd = strpos($summaryTemplate, END_IF, $varEnd);
            $conditionalEnd = $contentEnd + END_IF_LEN;
            // if paper option exists and if value is set 
            $shouldShow = $varOption
                        && (($varOption->option->type == "text" && !empty($varOption->data()))
                            || ($varOption->option->type != "text" && ($varOption->data() || $varOption->value)));
            // emit body of conditional
            if ($shouldShow == $expectedValue) {
                $summary .= substr($summaryTemplate, $contentStart, $contentEnd - $contentStart);
            }
        }
        // emit everything after the last (if any) conditional
        $summary .= substr($summaryTemplate, $conditionalEnd);
        
        // Now, replace all the variables.
        $summary = preg_replace_callback('/\$\{.+?\}/', function($matches) use (&$options) {
            $var = $matches[0];
            // cut out option name 
            $var = substr($var, 2, strlen($var) - 3);
            // get reference to the paper option based on variable name
            $varOption = reset(array_filter($options, function ($o) use ($var) {return $o->option->name == $var;}));
            // determine value, return [???] if option not defined (means user did not define conditional in template)
            // for text options, return data(), for others return data() if defined or its numeric value otherwise
            $value = $varOption ? ($varOption->option->type == "text" ? $varOption->data() : ($varOption->data() ? $varOption->data() : $varOption->value)) : "[???]";
            // special handling for non-option value for paperId
            if ($var == 'paperId') {
                $value = $this->prow->paperId;
            }
            // convert checkbox value 
            if ($varOption && $varOption->option->type == "checkbox") {
                $value = $value ? 'Yes' : 'No';
            }
            return $value;
        }, $summary);
        
        return $summary;
    }

    function render_abstract(FieldRender $fr, PaperOption $o) {
        $fr->title = false;
        $fr->value_format = 5;

        // get the summary from template
        $summary = $this->paptabTemplateText('summaryTemplate');
        // emtpy abstract (both by summary and submission)?
        if ($summary == null && trim($text) === "") {
            // return fals if no abstract option is set
            if ($this->conf->opt("noAbstract")) {
                return false;
            } else { 
                // add default text if we don't have a summary
                if ($summary == null)
                    $text = "[No abstract]";
            }
        }        
        $extra = [];
        if ($this->allFolded && $this->abstract_foldable($text)) {
            $extra = ["fold" => "paper", "foldnum" => 6,
                      "foldtitle" => "Toggle full abstract"];
        }
        $fr->value = '<div class="paperinfo-abstract"><div class="pg">'
            . $this->papt("abstract", $o->title_html(), $extra)
            . '<div class="pavb abstract';
        if (!$this->entryMatches
            && ($format = $this->prow->format_of($text))) {
            $fr->value .= ' need-format" data-format="' . $format . '">' . $text;
        } else {
            $fr->value .= ' format0">' . Ht::format0($text);
        }
        $fr->value .= "</div></div></div>";
        if ($extra) {
            $fr->value .= '<div class="fn6 fx7 longtext-fader"></div>'
                . '<div class="fn6 fx7 longtext-expander"><a class="ui x js-foldup" href="" role="button" aria-expanded="false" data-fold-target="6">[more]</a></div>'
                . Ht::unstash_script("render_text.on_page()");
        }
    }

    private function editable_author_component_entry($n, $pfx, $au) {
        $auval = "";
        if ($pfx === "auname") {
            $js = ["size" => "35", "placeholder" => "Name", "autocomplete" => "off", "aria-label" => "Author name"];
            if ($au && $au->firstName && $au->lastName && !preg_match('@^\s*(v[oa]n\s+|d[eu]\s+)?\S+(\s+jr.?|\s+sr.?|\s+i+)?\s*$@i', $au->lastName)) {
                $auval = $au->lastName . ", " . $au->firstName;
            } else if ($au) {
                $auval = $au->name();
            }
        } else if ($pfx === "auemail") {
            $js = ["size" => "30", "placeholder" => "Email", "autocomplete" => "off", "aria-label" => "Author email"];
            $auval = $au ? $au->email : "";
        } else {
            $js = ["size" => "32", "placeholder" => "Affiliation", "autocomplete" => "off", "aria-label" => "Author affiliation"];
            $auval = $au ? $au->affiliation : "";
        }

        $val = $auval;
        if ($this->useRequest) {
            $val = ($pfx === '$' ? "" : (string) $this->qreq["$pfx$n"]);
        }

        $js["class"] = $this->control_class("$pfx$n", "need-autogrow js-autosubmit e$pfx");
        if ($au && !$this->prow->paperId && !$this->useRequest) {
            $js["class"] .= " ignore-diff";
        }
        if ($pfx === "auemail" && $this->user->can_lookup_user()) {
            $js["class"] .= " uii js-email-populate";
        }
        if ($val !== $auval) {
            $js["data-default-value"] = $auval;
        }
        return Ht::entry("$pfx$n", $val, $js);
    }
    private function editable_authors_tr($n, $au, $max_authors) {
        $t = '<tr>';
        if ($max_authors !== 1) {
            $t .= '<td class="rxcaption">' . $n . '.</td>';
        }
        return $t . '<td class="lentry">'
            . $this->editable_author_component_entry($n, "auemail", $au) . ' '
            . $this->editable_author_component_entry($n, "auname", $au) . ' '
            . $this->editable_author_component_entry($n, "auaff", $au)
            . '<span class="nb btnbox aumovebox"><button type="button" class="ui qx need-tooltip row-order-ui moveup" aria-label="Move up" tabindex="-1">'
            . Icons::ui_triangle(0)
            . '</button><button type="button" class="ui qx need-tooltip row-order-ui movedown" aria-label="Move down" tabindex="-1">'
            . Icons::ui_triangle(2)
            . '</button><button type="button" class="ui qx need-tooltip row-order-ui delete" aria-label="Delete" tabindex="-1">✖</button></span>'
            . $this->messages_at("author$n")
            . $this->messages_at("auemail$n")
            . $this->messages_at("auname$n")
            . $this->messages_at("auaff$n")
            . '</td></tr>';
    }

    /** @param PaperOption $option */
    function echo_editable_authors($option) {
        $max_authors = (int) $this->conf->opt("maxAuthors");
        $min_authors = $max_authors > 0 ? min(5, $max_authors) : 5;

        $sb = $this->conf->submission_blindness();
        $title = $this->edit_title_html($option);
        if ($sb === Conf::BLIND_ALWAYS) {
            $title .= ' <span class="n">(blind)</span>';
        } else if ($sb === Conf::BLIND_UNTILREVIEW) {
            $title .= ' <span class="n">(blind until review)</span>';
        }
        $this->echo_editable_papt("authors", $title, ["id" => "authors"]);
        $this->echo_field_hint($option);
        echo Ht::hidden("has_authors", 1),
            '<div class="papev"><table class="js-row-order">',
            '<tbody class="need-row-order-autogrow" data-min-rows="', $min_authors, '" ',
            ($max_authors > 0 ? 'data-max-rows="' . $max_authors . '" ' : ''),
            'data-row-template="', htmlspecialchars($this->editable_authors_tr('$', null, $max_authors)), '">';

        $aulist = $this->prow->author_list();
        if ($this->useRequest) {
            $n = $nonempty_n = 0;
            while (1) {
                $auname = $this->qreq["auname" . ($n + 1)];
                $auemail = $this->qreq["auemail" . ($n + 1)];
                $auaff = $this->qreq["auaff" . ($n + 1)];
                if ($auname === null && $auemail === null && $auaff === null) {
                    break;
                }
                ++$n;
                if ((string) $auname !== "" || (string) $auemail !== "" || (string) $auaff !== "") {
                    $nonempty_n = $n;
                }
            }
            while (count($aulist) < $nonempty_n) {
                $aulist[] = null;
            }
        } else if (empty($aulist) && !$this->admin) {
            $aulist[] = $this->user;
        }

        $tr_maxau = $max_authors <= 0 ? 0 : max(count($aulist), $max_authors);
        for ($n = 1; $n <= count($aulist); ++$n) {
            echo $this->editable_authors_tr($n, $aulist[$n - 1] ?? null, $tr_maxau);
        }
        if ($max_authors <= 0 || $n <= $max_authors) {
            do {
                echo $this->editable_authors_tr($n, null, $tr_maxau);
                ++$n;
            } while ($n <= $min_authors);
        }
        echo "</tbody></table></div></div>\n\n";
    }

    private function authorData($table, $type, $viewAs = null) {
        if ($this->matchPreg && isset($this->matchPreg["authorInformation"])) {
            $highpreg = $this->matchPreg["authorInformation"];
        } else {
            $highpreg = false;
        }
        $this->entryMatches = 0;
        $names = [];

        if (empty($table)) {
            return "[No authors]";
        } else if ($type === "last") {
            foreach ($table as $au) {
                $n = Text::nameo($au, NAME_P|NAME_I);
                $names[] = Text::highlight($n, $highpreg, $nm);
                $this->entryMatches += $nm;
            }
            return join(", ", $names);
        } else {
            foreach ($table as $au) {
                $nm1 = $nm2 = $nm3 = 0;
                $n = $e = $t = "";
                $n = trim(Text::highlight("$au->firstName $au->lastName", $highpreg, $nm1));
                if ($au->email !== "") {
                    $e = Text::highlight($au->email, $highpreg, $nm2);
                    $e = '&lt;<a href="mailto:' . htmlspecialchars($au->email)
                        . '" class="mailto">' . $e . '</a>&gt;';
                }
                $t = ($n === "" ? $e : $n);
                if ($au->affiliation !== "") {
                    $t .= ' <span class="auaff">(' . Text::highlight($au->affiliation, $highpreg, $nm3) . ')</span>';
                }
                if ($n !== "" && $e !== "") {
                    $t .= " " . $e;
                }
                $this->entryMatches += $nm1 + $nm2 + $nm3;
                $t = trim($t);
                if ($au->email !== ""
                    && $au->contactId
                    && $viewAs !== null
                    && $viewAs->email !== $au->email
                    && $viewAs->privChair) {
                    $t .= " <a href=\""
                        . $this->conf->selfurl($this->qreq, ["actas" => $au->email])
                        . "\">" . Ht::img("viewas.png", "[Act as]", array("title" => "Act as " . Text::nameo($au, NAME_P))) . "</a>";
                }
                $names[] = '<p class="odname">' . $t . '</p>';
            }
            return join("\n", $names);
        }
    }

    private function _analyze_authors() {
        // clean author information
        $aulist = $this->prow->author_list();
        if (empty($aulist)) {
            return [[], []];
        }

        // find contact author information, combine with author table
        $result = $this->conf->qe("select contactId, firstName, lastName, '' affiliation, email from ContactInfo where contactId?a", array_keys($this->prow->contacts()));
        $contacts = array();
        while ($result && ($row = $result->fetch_object("Author"))) {
            $match = -1;
            for ($i = 0; $match < 0 && $i < count($aulist); ++$i) {
                if (strcasecmp($aulist[$i]->email, $row->email) == 0)
                    $match = $i;
            }
            if (($row->firstName !== "" || $row->lastName !== "") && $match < 0) {
                $contact_n = $row->firstName . " " . $row->lastName;
                $contact_preg = str_replace("\\.", "\\S*", "{\\b" . preg_quote($row->firstName) . "\\b.*\\b" . preg_quote($row->lastName) . "\\b}i");
                for ($i = 0; $match < 0 && $i < count($aulist); ++$i) {
                    $f = $aulist[$i]->firstName;
                    $l = $aulist[$i]->lastName;
                    if (($f !== "" || $l !== "") && $aulist[$i]->email === "") {
                        $author_n = $f . " " . $l;
                        $author_preg = str_replace("\\.", "\\S*", "{\\b" . preg_quote($f) . "\\b.*\\b" . preg_quote($l) . "\\b}i");
                        if (preg_match($contact_preg, $author_n)
                            || preg_match($author_preg, $contact_n))
                            $match = $i;
                    }
                }
            }
            if ($match >= 0) {
                $au = $aulist[$match];
                if ($au->email === "") {
                    $au->email = $row->email;
                }
            } else {
                $contacts[] = $au = $row;
                $au->nonauthor = true;
            }
            $au->contactId = (int) $row->contactId;
        }
        Dbl::free($result);

        uasort($contacts, $this->conf->user_comparator());
        return array($aulist, $contacts);
    }

    function render_authors(FieldRender $fr, PaperOption $o) {
        $fr->title = false;
        $fr->value_format = 5;

        $vas = $this->user->view_authors_state($this->prow);
        if ($vas === 0) {
            $fr->value = '<div class="pg">'
                . $this->papt("authorInformation", $o->title_html(0))
                . '<div class="pavb"><i>Hidden for blind review</i></div>'
                . "</div>\n\n";
            return;
        }

        // clean author information
        list($aulist, $contacts) = $this->_analyze_authors();

        // "author" or "authors"?
        $auname = $o->title_html(count($aulist));
        if ($vas === 1) {
            $auname .= " (deblinded)";
        } else if ($this->user->act_author_view($this->prow)) {
            $sb = $this->conf->submission_blindness();
            if ($sb === Conf::BLIND_ALWAYS
                || ($sb === Conf::BLIND_OPTIONAL && $this->prow->blind)) {
                $auname .= " (blind)";
            } else if ($sb === Conf::BLIND_UNTILREVIEW) {
                $auname .= " (blind until review)";
            }
        }

        // header with folding
        $fr->value = '<div class="pg">'
            . '<div class="'
            . $this->control_class("authors", "pavt ui js-aufoldup")
            . '"><h3 class="pavfn">';
        if ($vas === 1 || $this->allFolded) {
            $fr->value .= '<a class="q ui js-aufoldup" href="" title="Toggle author display" role="button" aria-expanded="' . ($this->foldmap[8] ? "false" : "true") . '">';
        }
        if ($vas === 1) {
            $fr->value .= '<span class="fn8">' . $o->title_html(0) . '</span><span class="fx8">';
        }
        if ($this->allFolded) {
            $fr->value .= expander(null, 9);
        } else if ($vas === 1) {
            $fr->value .= expander(false);
        }
        $fr->value .= $auname;
        if ($vas === 1) {
            $fr->value .= '</span>';
        }
        if ($vas === 1 || $this->allFolded) {
            $fr->value .= '</a>';
        }
        $fr->value .= '</h3></div>';

        // contents
        $fr->value .= '<div class="pavb">';
        if ($vas === 1) {
            $fr->value .= '<a class="q fn8 ui js-aufoldup" href="" title="Toggle author display">'
                . '+&nbsp;<i>Hidden for blind review</i>'
                . '</a><div class="fx8">';
        }
        if ($this->allFolded) {
            $fr->value .= '<div class="fn9">'
                . $this->authorData($aulist, "last", null)
                . ' <a class="ui js-aufoldup" href="">[details]</a>'
                . '</div><div class="fx9">';
        }
        $fr->value .= $this->authorData($aulist, "col", $this->user);
        if ($this->allFolded) {
            $fr->value .= '</div>';
        }
        if ($vas === 1) {
            $fr->value .= '</div>';
        }
        $fr->value .= "</div></div>\n\n";

        // contacts
        if (!empty($contacts)
            && ($this->editable
                || $this->mode !== "edit"
                || $this->prow->timeSubmitted <= 0)) {
            $contacts_option = $this->conf->option_by_id(PaperOption::CONTACTSID);
            $fr->value .= '<div class="pg fx9' . ($vas > 1 ? "" : " fx8") . '">'
                . $this->papt("authorInformation", $contacts_option->title_html(count($contacts)))
                . '<div class="pavb">'
                . $this->authorData($contacts, "col", $this->user)
                . "</div></div>\n\n";
        }
    }

    /** @param PaperOption $o */
    function render_topics(FieldRender $fr, $o) {
        if (!($tmap = $this->prow->topic_map())) {
            return;
        }
        $interests = $this->user->topic_interest_map();
        $lenclass = count($tmap) < 4 ? "long" : "short";
        $topics = $this->conf->topic_set();
        $ts = [];
        foreach ($tmap as $tid => $tname) {
            $t = '<li class="topicti';
            if ($interests) {
                $t .= ' topic' . ($interests[$tid] ?? 0);
            }
            $x = $topics->unparse_name_html($tid);
            if ($this->user->isPC) {
                $x = Ht::link($x, $this->conf->hoturl("search", ["q" => "topic:" . SearchWord::quote($tname)]), ["class" => "qq"]);
            }
            $ts[] = $t . '">' . $x . '</li>';
            $lenclass = TopicSet::max_topici_lenclass($lenclass, $tname);
        }
        $fr->title = $o->title(count($ts));
        $fr->set_html('<ul class="topict topict-' . $lenclass . '">' . join("", $ts) . '</ul>');
        $fr->value_long = true;
    }

    /** @param PaperOption $o
     * @param int $vos
     * @param FieldRender $fr */
    private function clean_render($o, $vos, $fr) {
        if ($fr->title === false) {
            assert($fr->value_format === 5);
            return;
        }

        if ($fr->title === null) {
            $fr->title = $o->title();
        }

        $fr->value = $fr->value_html();
        $fr->value_format = 5;

        if ($fr->title !== "" && $o->display_group && !$fr->value_long) {
            $title = htmlspecialchars($fr->title);
            if ($fr->value === "") {
                $fr->value = '<h3 class="pavfn">' . $title . '</h3>';
            } else if ($fr->value[0] === "<"
                       && preg_match('{\A((?:<(?:div|p).*?>)*)}', $fr->value, $cm)) {
                $fr->value = $cm[1] . '<h3 class="pavfn pavfnsp">' . $title
                    . ':</h3> ' . substr($fr->value, strlen($cm[1]));
            } else {
                $fr->value = '<h3 class="pavfn pavfnsp">' . $title . ':</h3> ' . $fr->value;
            }
            $fr->value_long = false;
            $fr->title = "";
        }
    }

    /** @param list<PaperTableFieldRender> $renders
     * @param int $first
     * @param int $last
     * @param int $vos */
    private function _group_name_html($renders, $first, $last, $vos) {
        $group_names = [];
        $group_flags = 0;
        for ($i = $first; $i !== $last; ++$i) {
            if ($renders[$i]->view_state >= $vos) {
                $o = $renders[$i]->option;
                $group_names[] = $o->title();
                if ($o->id === -1005) {
                    $group_flags |= 1;
                } else if ($o->has_document()) {
                    $group_flags |= 2;
                } else {
                    $group_flags |= 4;
                }
            }
        }
        $group_types = [];
        if ($group_flags & 1) {
            $group_types[] = "Topics";
        }
        if ($group_flags & 2) {
            $group_types[] = "Attachments";
        }
        if ($group_flags & 4) {
            $group_types[] = "Options";
        }
        return htmlspecialchars($this->conf->_c("field_group", $renders[$first]->option->display_group, commajoin($group_names), commajoin($group_types)));
    }

    private function _echo_normal_body() {
        $status_info = $this->user->paper_status_info($this->prow);
        echo '<p class="pgsm"><span class="pstat ', $status_info[0], '">',
            htmlspecialchars($status_info[1]), "</span></p>";

        $renders = [];
        $fr = new FieldRender(FieldRender::CPAGE);
        $fr->table = $this;
        foreach ($this->conf->paper_opts->field_list($this->prow) as $o) {
            if ($o->display_position() === false
                || $o->display_position() < 1000
                || $o->display_position() >= 5000
                || ($vos = $this->user->view_option_state($this->prow, $o)) === 0) {
                continue;
            }

            $fr->clear();
            $o->render($fr, $this->prow->force_option($o->id));
            if (!$fr->is_empty()) {
                $this->clean_render($o, $vos, $fr);
                $renders[] = new PaperTableFieldRender($o, $vos, $fr);
            }
        }

        $lasto1 = null;
        $in_paperinfo_i = false;
        for ($first = 0; $first !== count($renders); $first = $last) {
            // compute size of group
            $o1 = $renders[$first]->option;
            $last = $first + 1;
            if ($o1->display_group !== null && $this->allFolded) {
                while ($last !== count($renders)
                       && $renders[$last]->option->display_group === $o1->display_group) {
                    ++$last;
                }
            }

            $nvos1 = 0;
            for ($i = $first; $i !== $last; ++$i) {
                if ($renders[$i]->view_state === 1) {
                    ++$nvos1;
                }
            }

            // change column
            if ($o1->display_position() >= 2000) {
                if (!$lasto1 || $lasto1->display_position() < 2000) {
                    echo '<div class="paperinfo"><div class="paperinfo-c">';
                } else if ($o1->display_position() >= 3000
                           && $lasto1->display_position() < 3000) {
                    if ($in_paperinfo_i) {
                        echo '</div>'; // paperinfo-i
                        $in_paperinfo_i = false;
                    }
                    echo '</div><div class="paperinfo-c">';
                }
                if ($o1->display_expand) {
                    if ($in_paperinfo_i) {
                        echo '</div>';
                        $in_paperinfo_i = false;
                    }
                    echo '<div class="paperinfo-i paperinfo-i-expand">';
                } else if (!$in_paperinfo_i) {
                    echo '<div class="paperinfo-i">';
                    $in_paperinfo_i = true;
                }
            }

            // echo start of group
            if ($o1->display_group !== null && $this->allFolded) {
                if ($nvos1 === 0 || $nvos1 === $last - $first) {
                    $group_html = $this->_group_name_html($renders, $first, $last, $nvos1 === 0 ? 2 : 1);
                } else {
                    $group_html = $this->_group_name_html($renders, $first, $last, 2);
                    $gn1 = $this->_group_name_html($renders, $first, $last, 1);
                    if ($group_html !== $gn1) {
                        $group_html = '<span class="fn8">' . $group_html . '</span><span class="fx8">' . $gn1 . '</span>';
                    }
                }

                $class = "pg";
                if ($nvos1 === $last - $first) {
                    $class .= " fx8";
                }
                $foldnum = $this->foldnumber[$o1->display_group] ?? 0;
                if ($foldnum && $renders[$first]->title !== "") {
                    $group_html = '<span class="fn' . $foldnum . '">'
                        . $group_html . '</span><span class="fx' . $foldnum
                        . '">' . $renders[$first]->title . '</span>';
                    $renders[$first]->title = false;
                    $renders[$first]->value = '<div class="'
                        . ($renders[$first]->value_long ? "pg" : "pgsm")
                        . ' pavb">' . $renders[$first]->value . '</div>';
                }
                echo '<div class="', $class, '">';
                if ($foldnum) {
                    echo '<div class="pavt ui js-foldup" data-fold-target="', $foldnum, '">',
                        '<h3 class="pavfn">',
                        '<a class="q ui js-foldup" href="" data-fold-target="', $foldnum, '" title="Toggle visibility" role="button" aria-expanded="',
                        $this->foldmap[$foldnum] ? "false" : "true",
                        '">', expander(null, $foldnum),
                        $group_html,
                        '</a></h3></div><div class="pg fx', $foldnum, '">';
                } else {
                    echo '<div class="pavt"><h3 class="pavfn">',
                        $group_html,
                        '</h3></div><div class="pg">';
                }
            }

            // echo contents
            for ($i = $first; $i !== $last; ++$i) {
                $x = $renders[$i];
                if ($x->value_long === false
                    || (!$x->value_long && $x->title === "")) {
                    $class = "pgsm";
                } else {
                    $class = "pg";
                }
                if ($x->value === ""
                    || ($x->title === "" && preg_match('{\A(?:[^<]|<a|<span)}', $x->value))) {
                    $class .= " outdent";
                }
                if ($x->view_state === 1) {
                    $class .= " fx8";
                }
                if ($x->title === false) {
                    echo $x->value;
                } else if ($x->title === "") {
                    echo '<div class="', $class, '">', $x->value, '</div>';
                } else if ($x->value === "") {
                    echo '<div class="', $class, '"><h3 class="pavfn">', $x->title, '</h3></div>';
                } else {
                    echo '<div class="', $class, '"><div class="pavt"><h3 class="pavfn">', $x->title, '</h3></div><div class="pavb">', $x->value, '</div></div>';
                }
            }

            // echo end of group
            if ($o1->display_group !== null && $this->allFolded) {
                echo '</div></div>';
            }
            if ($o1->display_position() >= 2000
                && $o1->display_expand) {
                echo '</div>';
            }
            $lasto1 = $o1;
        }

        // close out display
        if ($in_paperinfo_i) {
            echo '</div>';
        }
        if ($lasto1 && $lasto1->display_position() >= 2000) {
            echo '</div></div>';
        }
    }


    private function editable_newcontact_row($anum) {
        if ($anum === '$') {
            $checked = true;
            $name = $email = "";
        } else {
            $checked = !$this->useRequest || $this->qreq["contacts:active_$anum"];
            $email = (string) ($this->useRequest ? $this->qreq["contacts:email_$anum"] : "");
            $name = (string) ($this->useRequest ? $this->qreq["contacts:name_$anum"] : "");
        }
        $email = $email === "Email" ? "" : $email;
        $name = $name === "Name" ? "" : $name;

        return '<div class="' . $this->control_class("contacts:$anum", "checki")
            . '"><span class="checkc">'
            . Ht::checkbox("contacts:active_$anum", 1, $checked, ["data-default-checked" => true, "id" => false])
            . ' </span>'
            . Ht::entry("contacts:email_$anum", $email, ["size" => 30, "placeholder" => "Email", "class" => $this->control_class("contacts:email_$anum", "want-focus js-autosubmit uii js-email-populate"), "autocomplete" => "off"])
            . '  '
            . Ht::entry("contacts:name_$anum", $name, ["size" => 35, "placeholder" => "Name", "class" => "js-autosubmit", "autocomplete" => "off"])
            . Ht::hidden("contacts:isnew_$anum", "1")
            . $this->messages_at("contacts:$anum")
            . $this->messages_at("contacts:name_$anum")
            . $this->messages_at("contacts:email_$anum")
            . '</div>';
    }

    function echo_editable_contact_author($option) {
        if ($this->prow) {
            list($aulist, $contacts) = $this->_analyze_authors();
            $contacts = array_merge($aulist, $contacts);
        } else if (!$this->admin) {
            $contacts = [new Author($this->user)];
            $contacts[0]->contactId = $this->user->contactId;
        } else {
            $contacts = [];
        }
        usort($contacts, $this->conf->user_comparator());

        echo '<div class="papeg">',
            '<div class="', $this->control_class("contacts", "papet"),
            '" id="contacts"><label class="', $this->control_class("contacts", "papfn", "is-"), '">',
            $this->edit_title_html($option),
            '</label></div>';

        // Editable version
        $this->echo_field_hint($option);
        echo Ht::hidden("has_contacts", 1),
            '<div class="papev js-row-order"><div>';

        $req_cemail = [];
        if ($this->useRequest) {
            for ($cidx = 1; isset($this->qreq["contacts:email_$cidx"]); ++$cidx) {
                if ($this->qreq["contacts:active_$cidx"])
                    $req_cemail[strtolower($this->qreq["contacts:email_$cidx"])] = $cidx;
            }
        }

        $cidx = 1;
        foreach ($contacts as $au) {
            $reqidx = $req_cemail[strtolower($au->email)] ?? null;
            if ($au->nonauthor
                && (strcasecmp($this->user->email, $au->email) != 0 || $this->allow_admin)) {
                $ctl = Ht::hidden("contacts:email_$cidx", $au->email)
                    . Ht::checkbox("contacts:active_$cidx", 1, !$this->useRequest || $reqidx, ["data-default-checked" => true, "id" => false]);
            } else if ($au->contactId) {
                $ctl = Ht::hidden("contacts:email_$cidx", $au->email)
                    . Ht::hidden("contacts:active_$cidx", 1)
                    . Ht::checkbox(null, null, true, ["disabled" => true, "id" => false]);
            } else if ($au->email && validate_email($au->email)) {
                $ctl = Ht::hidden("contacts:email_$cidx", $au->email)
                    . Ht::checkbox("contacts:active_$cidx", 1, $this->useRequest && $reqidx, ["data-default-checked" => false, "id" => false]);
            } else {
                continue;
            }
            echo '<div class="',
                $reqidx ? $this->control_class("contacts:$reqidx", "checki") : "checki",
                '"><label><span class="checkc">', $ctl, ' </span>',
                Text::nameo_h($au, NAME_E);
            if ($au->nonauthor) {
                echo ' (<em>non-author</em>)';
            }
            if ($this->user->privChair
                && $au->contactId
                && $au->contactId != $this->user->contactId) {
                echo '&nbsp;', actas_link($au);
            }
            echo '</label>', $this->messages_at("contacts:$cidx"), '</div>';
            ++$cidx;
        }
        echo '</div><div data-row-template="',
            htmlspecialchars($this->editable_newcontact_row('$')),
            '">';
        if ($this->useRequest) {
            while ($this->qreq["contacts:isnew_$cidx"]) {
                echo $this->editable_newcontact_row($cidx);
                ++$cidx;
            }
        }
        echo '</div><div class="ug">',
            Ht::button("Add contact", ["class" => "ui row-order-ui addrow"]),
            "</div></div></div>\n\n";
    }

    /** @param PaperOption $option
     * @param PaperValue $ov
     * @param PaperValue $reqov */
    function echo_editable_anonymity($option, $ov, $reqov) {
        if ($this->conf->submission_blindness() == Conf::BLIND_OPTIONAL
            && $this->editable !== "f") {
            $heading = '<span class="checkc">' . Ht::checkbox("blind", 1, !$reqov->value, ["data-default-checked" => !$ov->value]) . "</span>" . $this->edit_title_html($option);
            $this->echo_editable_papt("nonblind", $heading, ["for" => "checkbox"]);
            $this->echo_field_hint($option);
            echo Ht::hidden("has_nonblind", 1), "</div>\n\n";
        }
    }

    private function _papstrip_framework() {
        if (!$this->npapstrip) {
            echo '<article class="pcontainer"><div class="pcard-left',
                '"><div class="pspcard"><div class="ui pspcard-fold">',
                '<div style="float:right;margin-left:1em;cursor:pointer"><span class="psfn">More ', expander(true), '</span></div>';

            if (($viewable = $this->prow->sorted_viewable_tags($this->user))) {
                $tagger = new Tagger($this->user);
                echo '<span class="psfn">Tags:</span> ',
                    $tagger->unparse_link($viewable);
            } else {
                echo '<hr class="c">';
            }

            echo '</div><div class="pspcard-open">';
        }
        ++$this->npapstrip;
    }

    private function _papstripBegin($foldid = null, $folded = null, $extra = null) {
        $this->_papstrip_framework();
        echo '<div';
        if ($foldid) {
            echo " id=\"fold$foldid\"";
        }
        echo ' class="psc';
        if ($foldid) {
            echo " fold", ($folded ? "c" : "o");
        }
        if ($extra) {
            if (isset($extra["class"])) {
                echo " ", $extra["class"];
            }
            foreach ($extra as $k => $v) {
                if ($k !== "class")
                    echo "\" $k=\"", str_replace("\"", "&quot;", $v);
            }
        }
        echo '">';
    }

    private function papstripCollaborators() {
        if (!$this->conf->setting("sub_collab")
            || !$this->prow->collaborators
            || strcasecmp(trim($this->prow->collaborators), "None") == 0) {
            return;
        }
        $fold = $this->user->session("foldpscollab", 1) ? 1 : 0;

        $data = $this->entryData("collaborators", "col");
        if ($this->entryMatches || !$this->allFolded) {
            $fold = 0;
        }

        $option = $this->conf->option_by_id(PaperOption::COLLABORATORSID);
        $this->_papstripBegin("pscollab", $fold, ["data-fold-storage" => "p.collab", "class" => "need-fold-storage"]);
        echo $this->papt("collaborators", $option->title_html(),
                         ["type" => "ps", "fold" => "pscollab", "folded" => $fold]),
            '<div class="psv"><div class="fx">', $data,
            "</div></div></div>\n\n";
    }

    function echo_editable_topics($option, $reqov) {
        if (!$this->conf->has_topics()) {
            return;
        }
        $this->echo_editable_papt("topics", $this->edit_title_html($option), ["id" => "topics"]);
        $this->echo_field_hint($option);
        echo Ht::hidden("has_topics", 1),
            '<div class="papev"><ul class="ctable">';
        $ptopics = $this->prow->topic_map();
        $topics = $this->conf->topic_set();
        foreach ($topics->group_list() as $tg) {
            $arg = ["class" => "uic js-range-click topic-entry", "id" => false,
                    "data-range-type" => "topic"];
            $isgroup = count($tg) > 2;
            if ($isgroup) {
                echo '<li class="ctelt cteltg"><div class="ctelti">';
                if (strcasecmp($tg[0], $topics[$tg[1]]) === 0) {
                    $tid = $tg[1];
                    $arg["data-default-checked"] = isset($ptopics[$tid]);
                    $checked = in_array($tid, $reqov->value_array());
                    echo '<label class="checki cteltx"><span class="checkc">',
                        Ht::checkbox("top$tid", 1, $checked, $arg),
                        '</span>', htmlspecialchars($tg[0]), '</label>';
                } else {
                    echo '<div class="cteltx"><span class="topicg">',
                        htmlspecialchars($tg[0]), '</span></div>';
                }
                echo '<div class="checki">';
            }
            for ($i = 1; $i !== count($tg); ++$i) {
                $tid = $tg[$i];
                if ($isgroup) {
                    $tname = htmlspecialchars($topics->subtopic_name($tid));
                    if ($tname === "")
                        continue;
                } else {
                    $tname = $topics->unparse_name_html($tid);
                }
                $arg["data-default-checked"] = isset($ptopics[$tid]);
                $checked = in_array($tid, $reqov->value_array());
                echo ($isgroup ? '<label class="checki cteltx">' : '<li class="ctelt"><label class="checki ctelti">'),
                    '<span class="checkc">',
                    Ht::checkbox("top$tid", 1, $checked, $arg),
                    '</span>', $tname, '</label>',
                    ($isgroup ? '' : '</li>');
            }
            if ($isgroup) {
                echo '</div></div></li>';
            }
        }
        echo "</ul></div></div>\n\n";
    }

    function echo_editable_option_papt(PaperOption $o, $heading = null, $rest = []) {
        if (!$heading) {
            $heading = $this->edit_title_html($o);
        }
        $this->echo_editable_papt($o->formid, $heading, $rest, $o);
        $this->echo_field_hint($o);
        echo Ht::hidden("has_{$o->formid}", 1);
    }

    /** @param PaperOption $option
     * @param PaperValue $ov
     * @param PaperValue $reqov */
    function echo_editable_pc_conflicts($option, $ov, $reqov) {
        if (!$this->conf->setting("sub_pcconf")) {
            return;
        } else if ($this->editable === "f" && !$this->admin) {
            foreach ($this->prow->pc_conflicts() as $cflt) {
                echo Ht::hidden("pcc" . $cflt->contactId, $cflt->conflictType);
            }
            return;
        }

        $pcm = $this->conf->full_pc_members();
        if (empty($pcm)) {
            return;
        }

        $selectors = $this->conf->setting("sub_pcconfsel");
        $confset = $this->conf->conflict_types();
        $ctypes = [];
        if ($selectors) {
            $ctypes[0] = $confset->unparse_text(0);
            foreach ($confset->basic_conflict_types() as $ct) {
                $ctypes[$ct] = $confset->unparse_text($ct);
            }
            $extra = ["class" => "pcconf-selector"];
            if ($this->admin) {
                $ctypes["xsep"] = null;
                $ct = Conflict::set_pinned(Conflict::GENERAL, true);
                $ctypes[$ct] = $confset->unparse_text($ct);
            }
            $author_ctype = $confset->unparse_html(CONFLICT_AUTHOR);
        }

        $ctmaps = [[], []];
        foreach ([$ov, $reqov] as $num => $value) {
            $vs = $value->value_array();
            $ds = $value->data_array();
            for ($i = 0; $i !== count($vs); ++$i) {
                $ctmaps[$num][$vs[$i]] = (int) $ds[$i];
            }
        }

        $this->echo_editable_papt("pc_conflicts", $this->edit_title_html($option), ["id" => "pc_conflicts"]);
        $this->echo_field_hint($option);
        echo Ht::hidden("has_pc_conflicts", 1),
            '<div class="papev"><ul class="pc-ctable">';

        foreach ($pcm as $id => $p) {
            $ct = $pct = $ctmaps[0][$p->contactId] ?? 0;
            if ($this->useRequest) {
                $ct = $ctmaps[1][$p->contactId] ?? 0;
            }
            $pcconfmatch = false;
            '@phan-var false|array{string,list<string>} $pcconfmatch';
            if ($this->prow->paperId && $pct < CONFLICT_AUTHOR) {
                $pcconfmatch = $this->prow->potential_conflict_html($p, $pct <= 0);
            }

            $label = $this->user->reviewer_html_for($p);
            if ($p->affiliation) {
                $label .= '<span class="pcconfaff">' . htmlspecialchars(UnicodeHelper::utf8_abbreviate($p->affiliation, 60)) . '</span>';
            }

            echo '<li class="ctelt"><div class="ctelti';
            if (!$selectors) {
                echo ' checki';
            }
            echo ' clearfix';
            if (Conflict::is_conflicted($pct)) {
                echo ' boldtag';
            }
            if ($pcconfmatch) {
                echo ' need-tooltip" data-tooltip-class="gray" data-tooltip="', str_replace('"', '&quot;', PaperInfo::potential_conflict_tooltip_html($pcconfmatch));
            }
            echo '"><label>';

            $js = ["id" => "pcc$id"];
            if (Conflict::is_author($pct)
                || (!$this->admin && Conflict::is_pinned($pct))) {
                if ($selectors) {
                    echo '<span class="pcconf-editselector"><strong>';
                    if (Conflict::is_author($pct)) {
                        echo "Author";
                    } else if (Conflict::is_conflicted($pct)) {
                        echo "Conflict"; // XXX conflict type?
                    } else {
                        echo "Non-conflict";
                    }
                    echo '</strong></span>';
                } else {
                    echo '<span class="checkc">', Ht::checkbox(null, 1, Conflict::is_conflicted($pct), ["disabled" => true]), '</span>';
                }
                echo Ht::hidden("pcc$id", $pct, ["class" => "conflict-entry", "disabled" => true]);
            } else if ($selectors) {
                $xctypes = $ctypes;
                if (!isset($xctypes[$ct])) {
                    $xctypes[$ct] = $confset->unparse_text($ct);
                }
                $js["class"] = "conflict-entry";
                $js["data-default-value"] = $pct;
                echo '<span class="pcconf-editselector">',
                    Ht::select("pcc$id", $xctypes, $ct, $js),
                    '</span>';
            } else {
                $js["data-default-checked"] = Conflict::is_conflicted($pct);
                $js["data-range-type"] = "pcc";
                $js["class"] = "uic js-range-click conflict-entry";
                $checked = Conflict::is_conflicted($ct);
                echo '<span class="checkc">',
                    Ht::hidden("has_pcc$id", 1),
                    Ht::checkbox("pcc$id", $checked ? $ct : Conflict::GENERAL, $checked, $js),
                    '</span>';
            }

            echo $label, "</label>";
            if ($pcconfmatch) {
                echo $pcconfmatch[0];
            }
            echo "</div></li>";
        }
        echo "</ul></div></div>\n\n";
    }

    private function papstripPCConflicts() {
        assert(!$this->editable && $this->prow->paperId);
        $pcconf = [];
        $pcm = $this->conf->pc_members();
        foreach ($this->prow->pc_conflicts() as $id => $cflt) {
            if (Conflict::is_conflicted($cflt->conflictType)) {
                $p = $pcm[$id];
                $pcconf[$p->sort_position] = '<li class="odname">'
                    . $this->user->reviewer_html_for($p) . '</li>';
            }
        }
        ksort($pcconf);
        if (empty($pcconf)) {
            $pcconf[] = '<li class="odname">None</li>';
        }
        $this->_papstripBegin();
        $option = $this->conf->option_by_id(PaperOption::PCCONFID);
        echo $this->papt("pc_conflicts", $option->title_html(), ["type" => "ps"]),
            '<div class="psv"><ul class="x namelist-columns">', join("", $pcconf), "</ul></div></div>\n";
    }

    private function _papstripLeadShepherd($type, $name, $showedit) {
        $editable = $type === "manager" ? $this->user->privChair : $this->admin;
        $extrev_shepherd = $type === "shepherd" && $this->conf->setting("extrev_shepherd");

        $field = $type . "ContactId";
        if ($this->prow->$field == 0 && !$editable) {
            return;
        }
        $value = $this->prow->$field;

        $this->_papstripBegin($type, true, $editable ? ["class" => "ui-unfold js-unfold-pcselector js-unfold-focus need-paper-select-api"] : "");
        echo $this->papt($type, $name, array("type" => "ps", "fold" => $editable ? $type : false, "folded" => true)),
            '<div class="psv">';
        if (!$value) {
            $n = "";
        } else if (($p = $this->conf->cached_user_by_id($value))
                   && ($p->isPC
                       || ($extrev_shepherd && $this->prow->review_type($p) == REVIEW_EXTERNAL))) {
            $n = $this->user->reviewer_html_for($p);
        } else {
            $n = "<strong>[removed from PC]</strong>";
        }
        echo '<div class="pscopen"><p class="fn odname js-psedit-result">',
            $n, '</p></div>';

        if ($editable) {
            $this->conf->stash_hotcrp_pc($this->user);
            $selopt = "0 assignable";
            if ($type === "shepherd" && $this->conf->setting("extrev_shepherd")) {
                $selopt .= " extrev";
            }
            echo '<form class="ui-submit uin fx">',
                Ht::select($type, [], 0, ["class" => "w-99 want-focus", "data-pcselector-options" => $selopt . " selected", "data-pcselector-selected" => $value]),
                '</form>';
        }

        echo "</div></div>\n";
    }

    private function papstripLead($showedit) {
        $this->_papstripLeadShepherd("lead", "Discussion lead", $showedit || $this->qreq->atab === "lead");
    }

    private function papstripShepherd($showedit) {
        $this->_papstripLeadShepherd("shepherd", "Shepherd", $showedit || $this->qreq->atab === "shepherd");
    }

    private function papstripManager($showedit) {
        $this->_papstripLeadShepherd("manager", "Paper administrator", $showedit || $this->qreq->atab === "manager");
    }

    private function papstripTags() {
        if (!$this->prow->paperId || !$this->user->can_view_tags($this->prow)) {
            return;
        }
        $tags = $this->prow->all_tags_text();
        $is_editable = $this->user->can_change_some_tag($this->prow);
        if ($tags === "" && !$is_editable) {
            return;
        }

        // Note that tags MUST NOT contain HTML special characters.
        $tagger = new Tagger($this->user);
        $viewable = $this->prow->sorted_viewable_tags($this->user);

        $tx = $tagger->unparse_link($viewable);
        $unfolded = $is_editable && ($this->has_problem_at("tags") || $this->qreq->atab === "tags");

        $this->_papstripBegin("tags", true, $is_editable ? ["class" => "need-tag-form js-unfold-focus"] : []);

        if ($is_editable) {
            echo Ht::form($this->prow->hoturl(), ["data-pid" => $this->prow->paperId, "data-no-tag-report" => $unfolded ? 1 : null]);
        }

        echo $this->papt("tags", "Tags", ["type" => "ps", "fold" => $is_editable ? "tags" : false]),
            '<div class="psv">';
        if ($is_editable) {
            // tag report form
            $treport = PaperApi::tagreport($this->user, $this->prow);
            $tm0 = $tm1 = [];
            $tms = 0;
            foreach ($treport->tagreport as $tr) {
                $search = isset($tr->search) ? $tr->search : "#" . $tr->tag;
                $tm = Ht::link("#" . $tr->tag, $this->conf->hoturl("search", ["q" => $search]), ["class" => "q"]) . ": " . $tr->message;
                $tms = max($tms, $tr->status);
                $tm0[] = $tm;
                if ($tr->status > 0 && $this->prow->has_tag($tagger->expand($tr->tag))) {
                    $tm1[] = $tm;
                }
            }

            // uneditable
            echo '<div class="fn want-tag-report-warnings">';
            if (!empty($tm1)) {
                echo Ht::msg($tm1, 1);
            }
            echo '</div><div class="fn js-tag-result">',
                ($tx === "" ? "None" : $tx), '</div>';

            echo '<div class="fx js-tag-editor"><div class="want-tag-report">';
            if (!empty($tm0)) {
                echo Ht::msg($tm0, $tms);
            }
            echo "</div>";
            $editable = $this->prow->sorted_editable_tags($this->user);
            echo '<textarea cols="20" rows="4" name="tags" class="w-99 want-focus need-suggest tags">',
                $tagger->unparse($editable),
                '</textarea>',
                '<div class="aab aabr aab-compact"><div class="aabut">',
                Ht::submit("save", "Save", ["class" => "btn-primary"]),
                '</div><div class="aabut">',
                Ht::submit("cancel", "Cancel"),
                "</div></div>",
                '<span class="hint"><a href="', $this->conf->hoturl("help", "t=tags"), '">Learn more</a> <span class="barsep">·</span> <strong>Tip:</strong> Twiddle tags like “~tag” are visible only to you.</span>',
                "</div>";
        } else {
            echo '<div class="js-tag-result">', ($tx === "" ? "None" : $tx), '</div>';
        }
        echo "</div>";

        if ($is_editable) {
            echo "</form>";
        }
        if ($unfolded) {
            echo Ht::unstash_script('fold("tags",0)');
        }
        echo "</div>\n";
    }

    function papstripOutcomeSelector() {
        $this->_papstripBegin("decision", $this->qreq->atab !== "decision", ["class" => "need-paper-select-api js-unfold-focus"]);
        echo $this->papt("decision", "Decision", array("type" => "ps", "fold" => "decision")),
            '<div class="psv"><form class="ui-submit uin fx">';
        if (isset($this->qreq->forceShow)) {
            echo Ht::hidden("forceShow", $this->qreq->forceShow ? 1 : 0);
        }
        echo Ht::select("decision", $this->conf->decision_map(),
                        (string) $this->prow->outcome,
                        ["class" => "w-99 want-focus"]),
            '</form><p class="fn odname js-psedit-result">',
            htmlspecialchars($this->conf->decision_name($this->prow->outcome)),
            "</p></div></div>\n";
    }

    function papstripReviewPreference() {
        $this->_papstripBegin("revpref");
        echo $this->papt("revpref", "Review preference", ["type" => "ps"]),
            "<div class=\"psv\"><form class=\"ui\">";
        $rp = unparse_preference($this->prow->preference($this->user));
        $rp = ($rp == "0" ? "" : $rp);
        echo "<input id=\"revprefform_d\" type=\"text\" name=\"revpref", $this->prow->paperId,
            "\" size=\"4\" value=\"$rp\" class=\"revpref want-focus want-select\">",
            "</form></div></div>\n";
        Ht::stash_script("add_revpref_ajax(\"#revprefform_d\",true);shortcut(\"revprefform_d\").add()");
    }

    private function papstrip_tag_entry($id) {
        $this->_papstripBegin($id, !!$id, ["class" => "pste js-unfold-focus"]);
    }

    private function papstrip_tag_float($tag, $kind, $type) {
        if (!$this->user->can_view_tag($this->prow, $tag)) {
            return "";
        }
        $class = "is-nonempty-tags float-right";
        if (($totval = $this->prow->tag_value($tag)) === false) {
            $totval = "";
            $class .= " hidden";
        }
        $reverse = $type !== "rank";
        $extradiv = "";
        if (($type === "vote" || $type === "approval")
            && $this->user->can_view_peruser_tag($this->prow, $tag)) {
            $class .= " need-tooltip";
            $extradiv = ' data-tooltip-dir="h" data-tooltip-info="votereport" data-tag="' . htmlspecialchars($tag) . '"';
        }
        return '<div class="' . $class . '"' . $extradiv
            . '><a class="qq" href="' . $this->conf->hoturl("search", "q=" . urlencode("show:#$tag sort:" . ($reverse ? "-" : "") . "#$tag")) . '">'
            . '<span class="is-tag-index" data-tag-base="' . $tag . '">' . $totval . '</span> ' . $kind . '</a></div>';
    }

    private function papstrip_tag_entry_title($s, $tag, $value) {
        $ts = "#$tag";
        if (($color = $this->conf->tags()->color_classes($tag))) {
            $ts = '<span class="' . $color . ' taghh">' . $ts . '</span>';
        }
        $s = str_replace("{{}}", $ts, $s);
        if ($value !== false) {
            $s .= '<span class="fn is-nonempty-tags'
                . ($value === "" ? " hidden" : "")
                . '">: <span class="is-tag-index" data-tag-base="~'
                . $tag . '">' . $value . '</span></span>';
        }
        return $s;
    }

    private function papstrip_rank($tag) {
        $id = "rank_" . html_id_encode($tag);
        if (($myval = $this->prow->tag_value($this->user->contactId . "~$tag")) === false) {
            $myval = "";
        }
        $totmark = $this->papstrip_tag_float($tag, "overall", "rank");

        $this->papstrip_tag_entry($id);
        echo Ht::form("", ["class" => "need-tag-index-form", "data-pid" => $this->prow->paperId]);
        if (isset($this->qreq->forceShow)) {
            echo Ht::hidden("forceShow", $this->qreq->forceShow);
        }
        echo $this->papt($id, $this->papstrip_tag_entry_title("{{}} rank", $tag, $myval),
                         array("type" => "ps", "fold" => $id, "float" => $totmark)),
            '<div class="psv"><div class="fx">',
            Ht::entry("tagindex", $myval,
                      ["size" => 4, "class" => "is-tag-index want-focus",
                       "data-tag-base" => "~$tag", "inputmode" => "decimal"]),
            ' <span class="barsep">·</span> ',
            '<a href="', $this->conf->hoturl("search", "q=" . urlencode("editsort:#~$tag")), '">Edit all</a>',
            ' <div class="hint" style="margin-top:4px"><strong>Tip:</strong> <a href="', $this->conf->hoturl("search", "q=" . urlencode("editsort:#~$tag")), '">Search “editsort:#~', $tag, '”</a> to drag and drop your ranking, or <a href="', $this->conf->hoturl("offline"), '">use offline reviewing</a> to rank many papers at once.</div>',
            "</div></div></form></div>\n";
    }

    private function papstrip_allotment($tag, $allotment) {
        $id = "vote_" . html_id_encode($tag);
        if (($myval = $this->prow->tag_value($this->user->contactId . "~$tag")) === false) {
            $myval = "";
        }
        $totmark = $this->papstrip_tag_float($tag, "total", "vote");

        $this->papstrip_tag_entry($id);
        echo Ht::form("", ["class" => "need-tag-index-form", "data-pid" => $this->prow->paperId]);
        if (isset($this->qreq->forceShow)) {
            echo Ht::hidden("forceShow", $this->qreq->forceShow);
        }
        echo $this->papt($id, $this->papstrip_tag_entry_title("{{}} votes", $tag, $myval),
                         ["type" => "ps", "fold" => $id, "float" => $totmark]),
            '<div class="psv"><div class="fx">',
            Ht::entry("tagindex", $myval, ["size" => 4, "class" => "is-tag-index want-focus", "data-tag-base" => "~$tag", "inputmode" => "decimal"]),
            " &nbsp;of $allotment",
            ' <span class="barsep">·</span> ',
            '<a href="', $this->conf->hoturl("search", "q=" . urlencode("editsort:-#~$tag")), '">Edit all</a>',
            "</div></div></form></div>\n";
    }

    private function papstrip_approval($tag) {
        $id = "approval_" . html_id_encode($tag);
        if (($myval = $this->prow->tag_value($this->user->contactId . "~$tag")) === false) {
            $myval = "";
        }
        $totmark = $this->papstrip_tag_float($tag, "total", "approval");

        $this->papstrip_tag_entry(null);
        echo Ht::form("", ["class" => "need-tag-index-form", "data-pid" => $this->prow->paperId]);
        if (isset($this->qreq->forceShow)) {
            echo Ht::hidden("forceShow", $this->qreq->forceShow);
        }
        echo $this->papt($id,
            $this->papstrip_tag_entry_title('<label><span class="checkc">'
                . Ht::checkbox("tagindex", "0", $myval !== "", ["class" => "is-tag-index want-focus", "data-tag-base" => "~$tag"])
                . '</span>{{}} vote</label>', $tag, false),
            ["type" => "ps", "fnclass" => "checki", "float" => $totmark]),
            "</form></div>\n";
    }

    private function papstripWatch() {
        if ($this->prow->timeSubmitted <= 0
            || $this->user->contactId <= 0
            || ($this->prow->has_conflict($this->user)
                && !$this->prow->has_author($this->user)
                && !$this->user->is_admin_force())) {
            return;
        }
        // watch note
        $watch = $this->conf->fetch_ivalue("select watch from PaperWatch where paperId=? and contactId=?", $this->prow->paperId, $this->user->contactId);

        $this->_papstripBegin();

        echo '<form class="ui-submit uin">',
            $this->papt("watch",
                '<label><span class="checkc">'
                . Ht::checkbox("follow", 1, $this->user->following_reviews($this->prow, $watch), ["class" => "uich js-follow-change"])
                . '</span>Email notification</label>',
                ["type" => "ps", "fnclass" => "checki"]),
            '<div class="pshint">Select to receive email on updates to reviews and comments.</div>',
            "</form></div>\n";
    }


    // Functions for editing

    function deadline_setting_is($dname, $dl = "deadline") {
        global $Now;
        $deadline = $this->conf->printableTimeSetting($dname, "span");
        if ($deadline === "N/A") {
            return "";
        } else if ($Now < $this->conf->setting($dname)) {
            return " The $dl is $deadline.";
        } else {
            return " The $dl was $deadline.";
        }
    }

    private function _deadline_override_message() {
        if ($this->admin) {
            return " As an administrator, you can make changes anyway.";
        } else {
            return $this->_forceShow_message();
        }
    }
    private function _forceShow_message() {
        if (!$this->admin && $this->allow_admin) {
            return " " . Ht::link("(Override your conflict)", $this->conf->selfurl($this->qreq, ["forceShow" => 1]), ["class" => "nw"]);
        } else {
            return "";
        }
    }

    private function _edit_message_new_paper() {
        global $Now;
        $msg = "";
        if (!$this->conf->timeStartPaper()) {
            $sub_open = $this->conf->setting("sub_open");
            if ($sub_open <= 0 || $sub_open > $Now) {
                $msg = "The site is not open for submissions." . $this->_deadline_override_message();
            } else {
                $msg = 'The <a href="' . $this->conf->hoturl("deadlines") . '">deadline</a> for registering submissions has passed.' . $this->deadline_setting_is("sub_reg") . $this->_deadline_override_message();
            }
            if (!$this->admin) {
                $this->quit = true;
                return '<div class="merror">' . $msg . '</div>';
            }
            $msg = Ht::msg($msg, 1);
        }

        $t = [$this->conf->_("Enter information about your submission.")];
        $sub_reg = $this->conf->setting("sub_reg");
        $sub_upd = $this->conf->setting("sub_update");
        if ($sub_reg > 0 && $sub_upd > 0 && $sub_reg < $sub_upd) {
            $t[] = $this->conf->_("All submissions must be registered by %s and completed by %s.", $this->conf->printableTimeSetting("sub_reg"), $this->conf->printableTimeSetting("sub_sub"));
            if (!$this->conf->opt("noPapers")) {
                $t[] = $this->conf->_("PDF upload is not required to register.");
            }
        } else if ($sub_upd > 0) {
            $t[] = $this->conf->_("All submissions must be completed by %s.", $this->conf->printableTimeSetting("sub_update"));
        }
        $msg .= Ht::msg(space_join($t), 0);
        if (($v = $this->conf->_i("submit"))) {
            $msg .= Ht::msg($v, 0);
        }
        return $msg;
    }

    private function _edit_message_for_author() {
        $can_view_decision = $this->prow->outcome != 0
            && $this->user->can_view_decision($this->prow);
        if ($can_view_decision && $this->prow->outcome < 0) {
            return Ht::msg("The submission was not accepted." . $this->_forceShow_message(), 1);
        } else if ($this->prow->timeWithdrawn > 0) {
            if ($this->user->can_revive_paper($this->prow)) {
                return Ht::msg("The submission has been withdrawn, but you can still revive it." . $this->deadline_setting_is("sub_update"), 1);
            } else {
                return Ht::msg("The submission has been withdrawn." . $this->_forceShow_message(), 1);
            }
        } else if ($this->prow->timeSubmitted <= 0) {
            $whyNot = $this->user->perm_update_paper($this->prow);
            if (!$whyNot) {
                $t = [];
                if (empty($this->prow->missing_fields(false, $this->user))) {
                    $t[] = $this->conf->_("This submission is marked as not ready for review.");
                } else {
                    $t[] = $this->conf->_("This submission is incomplete.");
                }
                if ($this->conf->setting("sub_update")) {
                    $t[] = $this->conf->_("All submissions must be completed by %s to be considered.", $this->conf->printableTimeSetting("sub_update"));
                } else {
                    $t[] = $this->conf->_("Incomplete submissions will not be considered.");
                }
                return Ht::msg(space_join($t), 1);
            } else if (isset($whyNot["updateSubmitted"])
                       && $this->user->can_finalize_paper($this->prow)) {
                return Ht::msg('The submission is not ready for review. Although you cannot make any further changes, the current version can be still be submitted for review.' . $this->deadline_setting_is("sub_sub") . $this->_deadline_override_message(), 1);
            } else if (isset($whyNot["deadline"])) {
                if ($this->conf->deadlinesBetween("", "sub_sub", "sub_grace")) {
                    return Ht::msg('The site is not open for updates at the moment.' . $this->_deadline_override_message(), 1);
                } else {
                    return Ht::msg('The <a href="' . $this->conf->hoturl("deadlines") . '">submission deadline</a> has passed and the submission will not be reviewed.' . $this->deadline_setting_is("sub_sub") . $this->_deadline_override_message(), 1);
                }
            } else {
                return Ht::msg('The submission is not ready for review and can’t be changed further. It will not be reviewed.' . $this->_deadline_override_message(), 1);
            }
        } else if ($this->user->can_update_paper($this->prow)) {
            if ($this->mode === "edit") {
                return Ht::msg('The submission is ready and will be considered for review. You do not need to take further action. However, you can still make changes if you wish.' . $this->deadline_setting_is("sub_update", "submission deadline"), "confirm");
            }
        } else if ($this->conf->allow_final_versions()
                   && $this->prow->outcome > 0
                   && $can_view_decision) {
            if ($this->user->can_submit_final_paper($this->prow)) {
                if (($t = $this->conf->_i("finalsubmit", false, $this->deadline_setting_is("final_soft")))) {
                    return Ht::msg($t, 0);
                }
            } else if ($this->mode === "edit") {
                return Ht::msg("The deadline for updating final versions has passed. You can still change contact information." . $this->_deadline_override_message(), 1);
            }
        } else if ($this->mode === "edit") {
            if ($this->user->can_withdraw_paper($this->prow, true)) {
                $t = "The submission is under review and can’t be changed, but you can change its contacts or withdraw it from consideration.";
            } else {
                $t = "The submission is under review and can’t be changed or withdrawn, but you can change its contacts.";
            }
            return Ht::msg($t . $this->_deadline_override_message(), 0);
        }
        return "";
    }

    private function _edit_message() {
        if (!$this->prow->paperId) {
            return $this->_edit_message_new_paper();
        }

        $m = "";
        $has_author = $this->prow->has_author($this->user);
        $can_view_decision = $this->prow->outcome != 0 && $this->user->can_view_decision($this->prow);
        if ($has_author) {
            $m .= $this->_edit_message_for_author();
        } else if ($this->conf->allow_final_versions()
                   && $this->prow->outcome > 0
                   && !$this->prow->can_author_view_decision()) {
            $m .= Ht::msg("The submission has been accepted, but its authors can’t see that yet. Once decisions are visible, the system will allow accepted authors to upload final versions.", 0);
        } else {
            $m .= Ht::msg("You aren’t a contact for this submission, but as an administrator you can still make changes.", 0);
        }
        if ($this->user->call_with_overrides($this->user->overrides() | Contact::OVERRIDE_TIME, "can_update_paper", $this->prow)
            && ($v = $this->conf->_i("submit"))) {
            $m .= Ht::msg($v, 0);
        }
        if ($this->edit_status
            && $this->edit_status->has_problem()
            && ($this->edit_status->has_problem_at("contacts") || $this->editable)) {
            $fields = [];
            foreach ($this->edit_fields ? : [] as $o) {
                if ($this->edit_status->has_problem_at($o->formid))
                    $fields[] = Ht::link(htmlspecialchars($o->edit_title()), "#" . $o->readable_formid());
            }
            if (!empty($fields)) {
                $m .= Ht::msg($this->conf->_c("paper_edit", "Please check %s before completing your submission.", commajoin($fields)), $this->edit_status->problem_status());
            }
        }
        return $m;
    }

    private function _save_name() {
        if (!$this->is_ready(false)) {
            return "Save draft";
        } else if ($this->prow->timeSubmitted > 0) {
            return "Save and resubmit";
        } else {
            return "Save and submit";
        }
    }

    private function _collect_actions() {
        $pid = $this->prow->paperId ? : "new";

        // Withdrawn papers can be revived
        if ($this->prow->timeWithdrawn > 0) {
            $revivable = $this->conf->timeFinalizePaper($this->prow);
            if ($revivable) {
                return [Ht::submit("revive", "Revive submission", ["class" => "btn-primary"])];
            } else if ($this->admin) {
                return [[Ht::button("Revive submission", ["class" => "ui js-override-deadlines", "data-override-text" => 'The <a href="' . $this->conf->hoturl("deadlines") . '">deadline</a> for reviving withdrawn submissions has passed. Are you sure you want to override it?', "data-override-submit" => "revive"]), "(admin only)"]];
            } else {
                return [];
            }
        }

        $buttons = [];
        $want_override = false;

        if ($this->mode === "edit") {
            // check whether we can save
            $old_overrides = $this->user->set_overrides(Contact::OVERRIDE_CHECK_TIME);
            if ($this->canUploadFinal) {
                $whyNot = $this->user->perm_submit_final_paper($this->prow);
            } else if ($this->prow->paperId) {
                $whyNot = $this->user->perm_update_paper($this->prow);
            } else {
                $whyNot = $this->user->perm_start_paper();
            }
            $this->user->set_overrides($old_overrides);
            // produce button
            $save_name = $this->_save_name();
            if (!$whyNot) {
                $buttons[] = [Ht::submit("update", $save_name, ["class" => "btn-primary btn-savepaper uic js-mark-submit"]), ""];
            } else if ($this->admin) {
                $revWhyNot = filter_whynot($whyNot, ["deadline", "rejected"]);
                $x = whyNotText($revWhyNot) . " Are you sure you want to override the deadline?";
                $buttons[] = [Ht::button($save_name, ["class" => "btn-primary btn-savepaper ui js-override-deadlines", "data-override-text" => $x, "data-override-submit" => "update"]), "(admin only)"];
            } else if (isset($whyNot["updateSubmitted"])
                       && $this->user->can_finalize_paper($this->prow)) {
                $buttons[] = Ht::submit("update", $save_name, ["class" => "btn-savepaper uic js-mark-submit"]);
            } else if ($this->prow->paperId) {
                $buttons[] = Ht::submit("updatecontacts", "Save contacts", ["class" => "btn-savepaper btn-primary uic js-mark-submit", "data-contacts-only" => 1]);
            }
            if (!empty($buttons)) {
                $buttons[] = Ht::submit("cancel", "Cancel", ["class" => "uic js-mark-submit"]);
                $buttons[] = "";
            }
            $want_override = $whyNot && !$this->admin;
        }

        // withdraw button
        if (!$this->prow->paperId
            || !$this->user->call_with_overrides($this->user->overrides() | Contact::OVERRIDE_TIME, "can_withdraw_paper", $this->prow, true)) {
            $b = null;
        } else if ($this->prow->timeSubmitted <= 0) {
            $b = Ht::submit("withdraw", "Withdraw", ["class" => "uic js-mark-submit"]);
        } else {
            $args = ["class" => "ui js-withdraw"];
            if ($this->user->can_withdraw_paper($this->prow, !$this->admin)) {
                $args["data-withdrawable"] = "true";
            }
            if (($this->admin && !$this->prow->has_author($this->user))
                || $this->conf->timeFinalizePaper($this->prow)) {
                $args["data-revivable"] = "true";
            }
            $b = Ht::button("Withdraw", $args);
        }
        if ($b) {
            if ($this->admin && !$this->user->can_withdraw_paper($this->prow)) {
                $b = [$b, "(admin only)"];
            }
            $buttons[] = $b;
        }

        // override conflict button
        if ($want_override && !$this->admin) {
            if ($this->allow_admin) {
                $buttons[] = "";
                $buttons[] = [Ht::submit("updateoverride", "Override conflict", ["class" => "uic js-mark-submit"]), "(admin only)"];
            } else if ($this->user->privChair) {
                $buttons[] = "";
                $buttons[] = Ht::submit("updateoverride", "Override conflict", ["disabled" => true, "class" => "need-tooltip uic js-mark-submit", "title" => "You cannot override your conflict because this paper has an administrator."]);
            }
        }

        return $buttons;
    }

    private function echo_actions() {
        if ($this->admin) {
            $v = (string) $this->qreq->emailNote;
            echo '<div class="checki"><label><span class="checkc">', Ht::checkbox("doemail", 1, true, ["class" => "ignore-diff"]), "</span>",
                "Email authors, including:</label> ",
                Ht::entry("emailNote", $v, ["size" => 30, "placeholder" => "Optional explanation", "class" => "ignore-diff js-autosubmit", "aria-label" => "Explanation for update"]),
                "</div>";
        }
        if ($this->mode === "edit" && $this->canUploadFinal) {
            echo Ht::hidden("submitfinal", 1);
        }

        $buttons = $this->_collect_actions();
        if ($this->admin && $this->prow->paperId) {
            $buttons[] = [Ht::button("Delete", ["class" => "ui js-delete-paper"]), "(admin only)"];
        }
        echo Ht::actions($buttons, ["class" => "aab aabig"]);
    }


    // Functions for overall paper table viewing

    function _papstrip() {
        if (($this->prow->managerContactId
             || ($this->user->privChair && $this->mode === "assign"))
            && $this->user->can_view_manager($this->prow)) {
            $this->papstripManager($this->user->privChair);
        }
        $this->papstripTags();
        foreach ($this->conf->tags() as $ltag => $t) {
            if ($this->user->can_change_tag($this->prow, "~$ltag", null, 0)) {
                if ($t->approval) {
                    $this->papstrip_approval($t->tag);
                } else if ($t->vote) {
                    $this->papstrip_allotment($t->tag, $t->vote);
                } else if ($t->rank) {
                    $this->papstrip_rank($t->tag);
                }
            }
        }
        $this->papstripWatch();
        if ($this->user->can_view_conflicts($this->prow) && !$this->editable) {
            $this->papstripPCConflicts();
        }
        if ($this->user->allow_view_authors($this->prow) && !$this->editable) {
            $this->papstripCollaborators();
        }
        if ($this->user->can_set_decision($this->prow)) {
            $this->papstripOutcomeSelector();
        }
        if ($this->user->can_view_lead($this->prow)) {
            $this->papstripLead($this->mode === "assign");
        }
        if ($this->user->can_view_shepherd($this->prow)) {
            $this->papstripShepherd($this->mode === "assign");
        }
        if ($this->user->can_accept_review_assignment($this->prow)
            && $this->conf->timePCReviewPreferences()
            && ($this->user->roles & (Contact::ROLE_PC | Contact::ROLE_CHAIR))) {
            $this->papstripReviewPreference();
        }
    }

    function _paptabTabLink($text, $link, $image, $highlight) {
        return '<li class="papmode' . ($highlight ? " active" : "")
            . '"><a href="' . $link . '" class="noul">'
            . Ht::img($image, "[$text]", "papmodeimg")
            . "&nbsp;<u" . ($highlight ? ' class="x"' : "") . ">" . $text
            . "</u></a></li>";
    }

    private function _paptabBeginKnown() {
        // what actions are supported?
        $pid = $this->prow->paperId;
        $canEdit = $this->user->allow_edit_paper($this->prow);
        $canReview = $this->user->can_review($this->prow, null);
        $canAssign = $this->admin || $this->user->can_request_review($this->prow, null, true);
        $canHome = ($canEdit || $canAssign || $this->mode === "contact");

        $t = "";

        // paper tabs
        if ($canEdit || $canReview || $canAssign || $canHome) {
            $t .= '<nav class="submission-modes"><ul>';

            // home link
            $highlight = ($this->mode !== "assign" && $this->mode !== "edit"
                          && $this->mode !== "contact" && $this->mode !== "re");
            $t .= $this->_paptabTabLink("Main", $this->prow->hoturl(["m" => $this->first_mode === "p" ? null : "main"]), "view48.png", $highlight);

            if ($canEdit) {
                $t .= $this->_paptabTabLink("Edit", $this->prow->hoturl(["m" => "edit"]), "edit48.png", $this->mode === "edit");
            }

            if ($canReview) {
                $t .= $this->_paptabTabLink("Review", $this->prow->reviewurl(["m" => "re"]), "review48.png", $this->mode === "re" && (!$this->editrrow || $this->user->is_my_review($this->editrrow)));
            }

            if ($canAssign) {
                $assign = $this->allow_admin ? "Assign" : "Invite";
                $t .= $this->_paptabTabLink($assign, $this->conf->hoturl("assign", "p=$pid"), "assign48.png", $this->mode === "assign");
            }

            $t .= "</ul></nav>";
        }

        return $t;
    }

    static private function _echo_clickthrough($ctype) {
        global $Conf, $Now;
        $data = $Conf->_i("clickthrough_$ctype");
        $buttons = [Ht::submit("Agree", ["class" => "btnbig btn-success ui js-clickthrough"])];
        echo Ht::form("", ["class" => "ui"]), '<div>', $data,
            Ht::hidden("clickthrough_type", $ctype),
            Ht::hidden("clickthrough_id", sha1($data)),
            Ht::hidden("clickthrough_time", $Now),
            Ht::actions($buttons, ["class" => "aab aabig aabr"]), "</div></form>";
    }

    static function echo_review_clickthrough() {
        echo '<div class="pcard revcard js-clickthrough-terms"><div class="revcard-head"><h2>Reviewing terms</h2></div><div class="revcard-body">', Ht::msg("You must agree to these terms before you can save reviews.", 2);
        self::_echo_clickthrough("review");
        echo "</div></div>";
    }

    private function _echo_editable_form() {
        $form_js = [
            "id" => "form-paper",
            "class" => "need-unload-protection ui-submit js-submit-paper",
            "data-alert-toggle" => "paper-alert",
            "data-upload-limit" => ini_get_bytes("upload_max_filesize")
        ];
        if ($this->prow->timeSubmitted > 0) {
            $form_js["data-submitted"] = $this->prow->timeSubmitted;
        }
        if ($this->prow->paperId && !$this->editable) {
            $form_js["data-contacts-only"] = 1;
        }
        if ($this->useRequest) {
            $form_js["class"] .= " alert";
        }
        echo Ht::form($this->conf->hoturl_post("paper", "p=" . ($this->prow->paperId ? : "new") . "&amp;m=edit"), $form_js);
        Ht::stash_script('$(edit_paper_ui.load)');
    }

    private function _echo_editable_body() {
        $this->_echo_editable_form();
        $overrides = $this->user->add_overrides(Contact::OVERRIDE_EDIT_CONDITIONS);
        echo '<div>';

        $this->edit_fields = array_values(array_filter(
            $this->conf->paper_opts->form_field_list($this->prow),
            function ($o) {
                return $this->user->can_edit_option($this->prow, $o);
            }
        ));

        if (($m = $this->_edit_message())) {
            echo $m;
        }

        if (!$this->quit) {
            for ($this->edit_fields_position = 0;
                 $this->edit_fields_position < count($this->edit_fields);
                 ++$this->edit_fields_position) {
                $o = $this->edit_fields[$this->edit_fields_position];
                $ov = $reqov = $this->prow->force_option($o);
                if ($this->useRequest
                    && $this->qreq["has_{$o->formid}"]
                    && ($x = $o->parse_web($this->prow, $this->qreq))) {
                    $reqov = $x;
                }
                $o->echo_web_edit($this, $ov, $reqov);
            }

            // Submit button
            $this->echo_editable_complete();
            $this->echo_actions();
        }

        echo "</div></form>";
        $this->user->set_overrides($overrides);
    }

    function paptabBegin() {
        if ($this->prow->paperId) {
            $this->_papstrip();
        }
        if ($this->npapstrip) {
            Ht::stash_script("edit_paper_ui.prepare()");
            echo '</div></div><nav class="pslcard-nav">';
        } else {
            echo '<article class="pcontainer"><div class="pcard-left pcard-left-nostrip"><nav class="pslcard-nav">';
        }
        $viewable_tags = $this->prow->viewable_tags($this->user);
        echo '<h4 class="pslcard-home">';
        if ($viewable_tags || $this->user->can_view_tags($this->prow)) {
            $color = $this->prow->conf->tags()->color_classes($viewable_tags);
            echo '<span class="pslcard-home-tag has-tag-classes taghh',
                ($color ? " $color" : ""), '">';
            $close = '</span>';
        } else {
            $close = '';
        }
        echo '<a href="#top" class="qq"><span class="header-site-name">',
            htmlspecialchars($this->conf->short_name), '</span> ';
        if ($this->prow->paperId <= 0) {
            echo "new submission";
        } else if ($this->mode !== "re") {
            echo "#{$this->prow->paperId}";
        } else if (!$this->editrrow || !$this->editrrow->reviewOrdinal) {
            echo "#{$this->prow->paperId} review";
        } else {
            echo "#" . unparseReviewOrdinal($this->editrrow);
        }
        echo '</a>', $close, '</h4><ul class="pslcard"></ul></nav></div>';
        echo '<div class="pcard papcard"><div class="',
            ($this->editable ? "pedcard" : "papcard"), '-body">';

        if ($this->editable) {
            $need_clickthrough = !$this->user->can_clickthrough("submit");
            if ($need_clickthrough) {
                echo '<div id="foldpaper js-clickthrough-container">',
                    '<div class="js-clickthrough-terms">',
                    '<h2>Submission terms</h2>',
                    Ht::msg("You must agree to these terms to register a submission.", 2);
                self::_echo_clickthrough("submit");
                echo '</div><div class="need-clickthrough-show hidden">';
            } else {
                echo '<div id="foldpaper">';
            }
            $this->_echo_editable_body();
            echo ($need_clickthrough ? "</div>" : ""), '</div>';
        } else {
            $this->echoDivEnter();
            $this->_echo_normal_body();
            echo '</div>';

            if ($this->mode === "edit") {
                echo '</div></div><div class="pcard notecard"><div class="papcard-body">';
                if (($m = $this->_edit_message())) {
                    echo $m, "<hr class=\"g\">\n";
                }
                $this->_echo_editable_form();
                $option = $this->conf->option_by_id(PaperOption::CONTACTSID);
                $this->echo_editable_contact_author($option);
                $this->echo_actions();
                echo "</form>";
            }
        }

        echo '</div></div>';

        if (!$this->editable
            && $this->mode !== "edit"
            && $this->user->act_author_view($this->prow)
            && !$this->user->contactId) {
            echo '<div class="pcard papcard">',
                "To edit this submission, <a href=\"", $this->conf->hoturl("index"), "\">sign in using your email and password</a>.",
                '</div>';
        }

        Ht::stash_script("shortcut().add()");
    }

    private function _paptabSepContaining($t) {
        if ($t !== "") {
            echo '<div class="pcard notcard"><div class="papcard-body">', $t, '</div></div>';
        }
    }

    function _review_overview_card($rtable, $editrrow, $ifempty, $msgs) {
        require_once("reviewtable.php");
        $t = "";
        if ($rtable) {
            $t .= review_table($this->user, $this->prow, $this->all_rrows,
                               $editrrow, $this->mode);
        }
        $t .= $this->_review_links($editrrow);
        if (($empty = ($t === ""))) {
            $t = $ifempty;
        }
        if ($msgs) {
            $t .= join("", $msgs);
        }
        if ($t) {
            echo '<div class="pcard notecard"><div class="papcard-body">',
                $t, '</div></div>';
        }
        return $empty;
    }

    private function _review_links($editrrow) {
        $prow = $this->prow;
        $cflttype = $this->user->view_conflict_type($prow);
        $allow_admin = $this->user->allow_administer($prow);
        $any_comments = false;
        $admin = $this->user->can_administer($prow);
        $xsep = ' <span class="barsep">·</span> ';

        $nvisible = 0;
        $myrr = null;
        foreach ($this->all_rrows as $rr) {
            if ($this->user->can_view_review($prow, $rr)) {
                $nvisible++;
            }
            if ($rr->contactId == $this->user->contactId
                || (!$myrr && $this->user->is_my_review($rr))) {
                $myrr = $rr;
            }
        }

        // comments
        $pret = "";
        if ($this->mycrows
            && !$editrrow
            && $this->mode !== "edit") {
            $tagger = new Tagger($this->user);
            $viewable_crows = [];
            foreach ($this->mycrows as $cr) {
                if ($this->user->can_view_comment($cr->prow, $cr)) {
                    $viewable_crows[] = $cr;
                }
            }
            $cxs = CommentInfo::group_by_identity($viewable_crows, $this->user, true);
            if (!empty($cxs)) {
                $count = array_reduce($cxs, function ($n, $cx) { return $n + $cx[1]; }, 0);
                $cnames = array_map(function ($cx) {
                    $cid = $cx[0]->unparse_html_id();
                    $tclass = "cmtlink";
                    if (($tags = $cx[0]->viewable_tags($this->user))
                        && ($color = $cx[0]->conf->tags()->color_classes($tags))) {
                        $tclass .= " $color taghh";
                    }
                    return "<span class=\"nb\"><a class=\"{$tclass} track\" href=\"#{$cid}\">"
                        . $cx[0]->unparse_commenter_html($this->user)
                        . "</a>"
                        . ($cx[1] > 1 ? " ({$cx[1]})" : "")
                        . $cx[2] . "</span>";
                }, $cxs);
                $first_cid = $cxs[0][0]->unparse_html_id();
                $pret = '<div class="revnotes"><a class="track" href="#' . $first_cid . '"><strong>'
                    . plural($count, "Comment") . '</strong></a>: '
                    . join(" ", $cnames) . '</div>';
                $any_comments = true;
            }
        }

        $t = [];
        $dlimgjs = ["class" => "dlimg", "width" => 24, "height" => 24];

        // see all reviews
        $this->allreviewslink = false;
        if (($nvisible > 1 || ($nvisible > 0 && !$myrr))
            && ($this->mode !== "p" || $editrrow)) {
            $this->allreviewslink = true;
            $t[] = '<a href="' . $prow->hoturl() . '" class="xx revlink">'
                . Ht::img("view48.png", "[All reviews]", $dlimgjs) . "&nbsp;<u>All reviews</u></a>";
        }

        // edit paper
        if ($this->mode !== "edit"
            && $prow->has_author($this->user)
            && !$this->user->can_administer($prow)) {
            $t[] = '<a href="' . $prow->hoturl(["m" => "edit"]) . '" class="xx revlink">'
                . Ht::img("edit48.png", "[Edit]", $dlimgjs) . "&nbsp;<u><strong>Edit submission</strong></u></a>";
        }

        // edit review
        if ($this->mode === "re"
            || ($this->mode === "assign" && !empty($t))
            || !$prow) {
            /* no link */;
        } else if ($myrr && $editrrow != $myrr) {
            $a = '<a href="' . $prow->reviewurl(["r" => $myrr->unparse_ordinal()]) . '" class="xx revlink">';
            if ($this->user->can_review($prow, $myrr)) {
                $x = $a . Ht::img("review48.png", "[Edit review]", $dlimgjs) . "&nbsp;<u><b>Edit your review</b></u></a>";
            } else {
                $x = $a . Ht::img("review48.png", "[Your review]", $dlimgjs) . "&nbsp;<u><b>Your review</b></u></a>";
            }
            $t[] = $x;
        } else if (!$myrr && !$editrrow && $this->user->can_review($prow, null)) {
            $t[] = '<a href="' . $prow->reviewurl(["m" => "re"]) . '" class="xx revlink">'
                . Ht::img("review48.png", "[Write review]", $dlimgjs) . "&nbsp;<u><b>Write review</b></u></a>";
        }

        // review assignments
        if ($this->mode !== "assign"
            && $this->mode !== "edit"
            && $this->user->can_request_review($prow, null, true)) {
            $t[] = '<a href="' . $this->conf->hoturl("assign", "p=$prow->paperId") . '" class="xx revlink">'
                . Ht::img("assign48.png", "[Assign]", $dlimgjs) . "&nbsp;<u>" . ($admin ? "Assign reviews" : "External reviews") . "</u></a>";
        }

        // new comment
        $nocmt = preg_match('/\A(?:assign|contact|edit|re)\z/', $this->mode);
        if (!$this->allreviewslink
            && !$nocmt
            && $this->user->can_comment($prow, null)) {
            $t[] = '<a class="ui js-edit-comment xx revlink" href="#cnew">'
                . Ht::img("comment48.png", "[Add comment]", $dlimgjs) . "&nbsp;<u>Add comment</u></a>";
            $any_comments = true;
        }

        // new response
        if (!$nocmt
            && ($prow->has_author($this->user) || $allow_admin)
            && $this->conf->any_response_open) {
            foreach ($this->conf->resp_rounds() as $rrd) {
                $cr = null;
                foreach ($this->mycrows ? : [] as $crow) {
                    if (($crow->commentType & COMMENTTYPE_RESPONSE)
                        && $crow->commentRound == $rrd->number) {
                        $cr = $crow;
                    }
                }
                $cr = $cr ? : CommentInfo::make_response_template($rrd->number, $prow);
                if ($this->user->can_respond($prow, $cr)) {
                    $cid = $this->conf->resp_round_text($rrd->number) . "response";
                    $what = "Add";
                    if ($cr->commentId) {
                        $what = $cr->commentType & COMMENTTYPE_DRAFT ? "Edit draft" : "Edit";
                    }
                    $t[] = '<a class="ui js-edit-comment xx revlink" href="#' . $cid . '">'
                        . Ht::img("comment48.png", "[$what response]", $dlimgjs) . "&nbsp;"
                        . ($cflttype >= CONFLICT_AUTHOR ? '<u style="font-weight:bold">' : '<u>')
                        . $what . ($rrd->name == "1" ? "" : " $rrd->name") . ' response</u></a>';
                    $any_comments = true;
                }
            }
        }

        // override conflict
        if ($allow_admin && !$admin) {
            $t[] = '<span class="revlink"><a href="' . $prow->conf->selfurl(null, ["forceShow" => 1]) . '" class="xx">'
                . Ht::img("override24.png", "[Override]", "dlimg") . "&nbsp;<u>Override conflict</u></a> to show reviewers and allow editing</span>";
        } else if ($this->user->privChair && !$allow_admin) {
            $x = '<span class="revlink">You can’t override your conflict because this submission has an administrator.</span>';
        }

        if ($any_comments) {
            CommentInfo::echo_script($prow);
        }

        $t = empty($t) ? "" : '<p class="sd">' . join("", $t) . '</p>';
        if ($prow->has_author($this->user)) {
            $t = '<p class="sd">' . $this->conf->_('You are an <span class="author">author</span> of this submission.') . '</p>' . $t;
        } else if ($prow->has_conflict($this->user)) {
            $t = '<p class="sd">' . $this->conf->_('You have a <span class="conflict">conflict</span> with this submission.') . '</p>' . $t;
        }
        return $pret . $t;
    }

    function _privilegeMessage() {
        $a = "<a href=\"" . $this->conf->selfurl($this->qreq, ["forceShow" => 0]) . "\">";
        return $a . Ht::img("override24.png", "[Override]", "dlimg")
            . "</a>&nbsp;You have used administrator privileges to view and edit reviews for this submission. (" . $a . "Unprivileged view</a>)";
    }

    private function include_comments() {
        return !$this->allreviewslink
            && (!empty($this->mycrows)
                || $this->user->can_comment($this->prow, null)
                || $this->conf->any_response_open);
    }

    function paptabEndWithReviewsAndComments() {
        if ($this->user->is_admin_force()
            && !$this->user->call_with_overrides(0, "can_view_review", $this->prow, null)) {
            $this->_paptabSepContaining($this->_privilegeMessage());
        } else if ($this->user->contactId == $this->prow->managerContactId
                   && !$this->user->privChair
                   && $this->user->contactId > 0) {
            $this->_paptabSepContaining("You are this submission’s administrator.");
        }

        // text format link
        $m = $viewable = [];
        foreach ($this->viewable_rrows as $rr) {
            if ($rr->reviewModified > 1) {
                $viewable[] = "reviews";
                break;
            }
        }
        foreach ($this->crows as $cr) {
            if ($this->user->can_view_comment($this->prow, $cr)) {
                $viewable[] = "comments";
                break;
            }
        }
        if (!empty($viewable)) {
            $m[] = '<p class="sd mt-5"><a href="' . $this->prow->reviewurl(["m" => "r", "text" => 1]) . '" class="xx">'
                . Ht::img("txt24.png", "[Text]", "dlimg")
                . "&nbsp;<u>" . ucfirst(join(" and ", $viewable))
                . " in plain text</u></a></p>";
        }

        if (!$this->_review_overview_card(true, null, '<p>There are no reviews or comments for you to view.</p>', $m)) {
            $this->render_rc(true, $this->include_comments());
        }
    }

    private function has_response($respround) {
        foreach ($this->mycrows as $cr) {
            if (($cr->commentType & COMMENTTYPE_RESPONSE)
                && $cr->commentRound == $respround)
                return true;
        }
        return false;
    }

    private function render_rc($reviews, $comments) {
        $rcs = [];
        $any_submitted = false;
        if ($reviews) {
            foreach ($this->viewable_rrows as $rrow) {
                if ($rrow->reviewSubmitted || $rrow->reviewModified > 1) {
                    $rcs[] = $rrow;
                }
                if ($rrow->reviewSubmitted || $rrow->reviewOrdinal) {
                    $any_submitted = true;
                }
            }
        }
        if ($comments && $this->mycrows) {
            $rcs = $this->prow->merge_reviews_and_comments($rcs, $this->mycrows);
        }

        $s = "";
        $ncmt = 0;
        $rf = $this->conf->review_form();
        foreach ($rcs as $rc) {
            if (isset($rc->reviewId)) {
                $rcj = $rf->unparse_review_json($this->user, $this->prow, $rc);
                if ($any_submitted
                    && !$rc->reviewSubmitted
                    && !$rc->reviewOrdinal
                    && !$this->user->is_my_review($rc)) {
                    $rcj->folded = true;
                }
                $s .= "review_form.add_review(" . json_encode_browser($rcj) . ");\n";
            } else {
                ++$ncmt;
                $rcj = $rc->unparse_json($this->user);
                $s .= "papercomment.add(" . json_encode_browser($rcj) . ");\n";
            }
        }

        if ($comments) {
            $cs = [];
            if ($this->user->can_comment($this->prow, null)) {
                $commentType = $this->prow->has_author($this->user) ? COMMENTTYPE_BYAUTHOR : 0;
                $cs[] = new CommentInfo(["commentType" => $commentType], $this->prow);
            }
            if ($this->admin || $this->prow->has_author($this->user)) {
                foreach ($this->conf->resp_rounds() as $rrd) {
                    if (!$this->has_response($rrd->number)
                        && $rrd->relevant($this->user, $this->prow)) {
                        $crow = CommentInfo::make_response_template($rrd->number, $this->prow);
                        if ($this->user->can_respond($this->prow, $crow))
                            $cs[] = $crow;
                    }
                }
            }
            foreach ($cs as $c) {
                ++$ncmt;
                $s .= "papercomment.add(" . json_encode_browser($c->unparse_json($this->user)) . ");\n";
            }
        }

        if ($ncmt) {
            CommentInfo::echo_script($this->prow);
        }
        if ($s !== "") {
            echo Ht::unstash_script($s);
        }
    }

    function paptabComments() {
        $this->render_rc(false, $this->include_comments());
    }

    function paptabEndWithoutReviews() {
        echo "</div></div>\n";
    }

    function paptabEndWithReviewMessage() {
        assert(!$this->editable);

        $m = [];
        if ($this->all_rrows
            && ($whyNot = $this->user->perm_view_review($this->prow, null))) {
            $m[] = "<p class=\"sd\">You can’t see the reviews for this submission. " . whyNotText($whyNot) . "</p>";
        }
        if (!$this->conf->time_review_open()
            && $this->prow->review_type($this->user)) {
            if ($this->rrow) {
                $m[] = "<p class=\"sd\">You can’t edit your review because the site is not open for reviewing.</p>";
            } else {
                $m[] = "<p class=\"sd\">You can’t begin your assigned review because the site is not open for reviewing.</p>";
            }
        }

        $this->_review_overview_card($this->user->can_view_review_assignment($this->prow, null), null, "", $m);
    }

    function paptabEndWithEditableReview() {
        $act_pc = $this->user->act_pc($this->prow);

        // review messages
        $msgs = [];
        if ($this->editrrow && !$this->user->is_signed_in()) {
            $msgs[] = $this->conf->_("You followed a review link to edit this review. You can also <a href=\"%s\">sign in to the site</a>.", $this->conf->hoturl("index", ["signin" => 1, "email" => $this->editrrow->email, "cap" => null]));
        }
        if (!$this->rrow && !$this->prow->review_type($this->user)) {
            $msgs[] = "You haven’t been assigned to review this submission, but you can review it anyway.";
        }
        if ($this->user->is_admin_force()) {
            if (!$this->user->call_with_overrides(0, "can_view_review", $this->prow, null)) {
                $msgs[] = $this->_privilegeMessage();
            }
        } else if (($whyNot = $this->user->perm_view_review($this->prow, null))
                   && isset($whyNot["reviewNotComplete"])
                   && ($this->user->isPC || $this->conf->setting("extrev_view"))) {
            $nother = 0;
            $myrrow = null;
            foreach ($this->all_rrows as $rrow) {
                if ($this->user->is_my_review($rrow)) {
                    $myrrow = $rrow;
                } else if ($rrow->reviewSubmitted) {
                    ++$nother;
                }
            }
            if ($nother > 0) {
                if ($myrrow && $myrrow->timeApprovalRequested > 0) {
                    $msgs[] = $this->conf->_("You’ll be able to see %d other reviews once yours is approved.", $nother);
                } else {
                    $msgs[] = $this->conf->_("You’ll be able to see %d other reviews once you complete your own.", $nother);
                }
            }
        }
        $msgs = array_map(function ($t) { return "<p class=\"sd\">{$t}</p>"; }, $msgs);

        // links
        //$this->_review_overview_card(true, $this->editrrow, "", $msgs);

        // review form, possibly with deadline warning
        $opt = array("edit" => $this->mode === "re");

        if ($this->editrrow
            && ($this->user->is_owned_review($this->editrrow) || $this->admin)
            && !$this->conf->time_review($this->editrrow, $act_pc, true)) {
            if ($this->admin) {
                $override = " As an administrator, you can override this deadline.";
            } else {
                $override = "";
                if ($this->editrrow->reviewSubmitted) {
                    $opt["edit"] = false;
                }
            }
            if ($this->conf->time_review_open()) {
                $opt["editmessage"] = 'The <a href="' . $this->conf->hoturl("deadlines") . '">review deadline</a> has passed, so the review can no longer be changed.' . $override;
            } else {
                $opt["editmessage"] = "The site is not open for reviewing, so the review cannot be changed." . $override;
            }
        } else if (!$this->user->can_review($this->prow, $this->editrrow)) {
            $opt["edit"] = false;
        }

        // maybe clickthrough
        if ($opt["edit"] && !$this->user->can_clickthrough("review", $this->prow)) {
            self::echo_review_clickthrough();
        }
        $rf = $this->conf->review_form();
        $rf->show($this->prow, $this->editrrow, $this->user, $opt, $this->review_values);
    }


    // Functions for loading papers

    static function clean_request(Qrequest $qreq) {
        if (!isset($qreq->paperId) && isset($qreq->p)) {
            $qreq->paperId = $qreq->p;
        }
        if (!isset($qreq->reviewId) && isset($qreq->r)) {
            $qreq->reviewId = $qreq->r;
        }
        if (!isset($qreq->commentId) && isset($qreq->c)) {
            $qreq->commentId = $qreq->c;
        }
        if (($pc = $qreq->path_component(0))) {
            if (!isset($qreq->reviewId) && preg_match('/\A\d+[A-Z]+\z/i', $pc)) {
                $qreq->reviewId = $pc;
            } else if (!isset($qreq->paperId)) {
                $qreq->paperId = $pc;
            }
        }
        if (!isset($qreq->paperId)
            && isset($qreq->reviewId)
            && preg_match('/\A(\d+)[A-Z]+\z/i', $qreq->reviewId, $m)) {
            $qreq->paperId = $m[1];
        }
        if (isset($qreq->paperId) || isset($qreq->reviewId)) {
            unset($qreq->q);
        }
    }

    static private function simple_qreq($qreq) {
        return $qreq->method() === "GET"
            && !array_diff($qreq->keys(), ["p", "paperId", "m", "mode", "forceShow", "go", "actas", "t", "q", "r", "reviewId"]);
    }

    /** @param Qrequest $qreq
     * @param Contact $user
     * @return ?int */
    static private function lookup_pid($qreq, $user) {
        // if a number, don't search
        $pid = isset($qreq->paperId) ? $qreq->paperId : $qreq->q;
        if (preg_match('/\A\s*#?(\d+)\s*\z/', $pid, $m)) {
            return intval($m[1]);
        }

        // look up a review ID
        if (!isset($pid) && isset($qreq->reviewId)) {
            return $user->conf->fetch_ivalue("select paperId from PaperReview where reviewId=?", $qreq->reviewId);
        }

        // if a complex request, or a form upload, or empty user, don't search
        if (!self::simple_qreq($qreq) || $user->is_empty()) {
            return null;
        }

        // if no paper ID set, find one
        if (!isset($pid)) {
            $q = "select min(Paper.paperId) from Paper ";
            if ($user->isPC) {
                $q .= "where timeSubmitted>0";
            } else if ($user->has_review()) {
                $q .= "join PaperReview on (PaperReview.paperId=Paper.paperId and PaperReview.contactId=$user->contactId)";
            } else {
                $q .= "join PaperConflict on (PaperConflict.paperId=Paper.paperId and PaperConflict.contactId=$user->contactId and PaperConflict.conflictType>=" . CONFLICT_AUTHOR . ")";
            }
            return $user->conf->fetch_ivalue($q);
        }

        // actually try to search
        if ($pid === "" || $pid === "(All)") {
            return null;
        }

        $search = new PaperSearch($user, ["q" => $pid, "t" => $qreq->get("t")]);
        $ps = $search->paper_ids();
        if (count($ps) == 1) {
            $list = $search->session_list_object();
            // DISABLED: check if the paper is in the current list
            unset($qreq->ls);
            $list->set_cookie($user);
            return $ps[0];
        } else {
            return null;
        }
    }

    /** @param ?int $pid */
    static function redirect_request($pid, Qrequest $qreq, Contact $user) {
        if ($pid !== null) {
            $qreq->paperId = $pid;
            unset($qreq->q, $qreq->p);
            $user->conf->self_redirect($qreq);
        } else if ((isset($qreq->paperId) || isset($qreq->q))
                   && !$user->is_empty()) {
            $q = "q=" . urlencode(isset($qreq->paperId) ? $qreq->paperId : $qreq->q);
            if ($qreq->t) {
                $q .= "&t=" . urlencode($qreq->t);
            }
            if ($qreq->page() === "assign") {
                $q .= "&linkto=" . $qreq->page();
            }
            go($user->conf->hoturl("search", $q));
        }
    }

    static function fetch_paper_request(Qrequest $qreq, Contact $user) {
        self::clean_request($qreq);
        $pid = self::lookup_pid($qreq, $user);
        if (self::simple_qreq($qreq)
            && ($pid === null || (string) $pid !== $qreq->paperId)) {
            self::redirect_request($pid, $qreq, $user);
        }
        if ($pid !== null) {
            $options = ["topics" => true, "options" => true];
            if ($user->privChair
                || ($user->isPC && $user->conf->timePCReviewPreferences())) {
                $options["reviewerPreference"] = true;
            }
            $prow = $user->paper_by_id($pid, $options);
        } else {
            $prow = null;
        }
        $whynot = $user->perm_view_paper($prow, false, $pid);
        if (!$whynot
            && !isset($qreq->paperId)
            && isset($qreq->reviewId)
            && !$user->privChair
            && (!($rrow = $prow->review_of_id($qreq->reviewId))
                || !$user->can_view_review($prow, $rrow))) {
            $whynot = ["conf" => $user->conf, "invalidId" => "paper"];
        }
        if ($whynot) {
            $qreq->set_annex("paper_whynot", $whynot);
        }
        $user->conf->paper = $whynot ? null : $prow;
        return $user->conf->paper;
    }

    function resolveReview($want_review) {
        $this->prow->ensure_full_reviews();
        $this->all_rrows = $this->prow->reviews_by_display($this->user);

        $this->viewable_rrows = array();
        $round_mask = 0;
        $min_view_score = VIEWSCORE_EMPTYBOUND;
        foreach ($this->all_rrows as $rrow) {
            if ($this->user->can_view_review($this->prow, $rrow)) {
                $this->viewable_rrows[] = $rrow;
                if ($rrow->reviewRound !== null) {
                    $round_mask |= 1 << (int) $rrow->reviewRound;
                }
                $min_view_score = min($min_view_score, $this->user->view_score_bound($this->prow, $rrow));
            }
        }
        $rf = $this->conf->review_form();
        Ht::stash_script("review_form.set_form(" . json_encode_browser($rf->unparse_json($round_mask, $min_view_score)) . ")");

        $want_rid = $want_rordinal = -1;
        $rtext = (string) $this->qreq->reviewId;
        if ($rtext !== "" && $rtext !== "new") {
            if (ctype_digit($rtext)) {
                $want_rid = intval($rtext);
            } else if (str_starts_with($rtext, (string) $this->prow->paperId)
                       && ($x = substr($rtext, strlen((string) $this->prow->paperId))) !== ""
                       && ctype_alpha($x)) {
                $want_rordinal = parseReviewOrdinal(strtoupper($x));
            }
        }

        $this->rrow = $myrrow = $approvable_rrow = null;
        foreach ($this->viewable_rrows as $rrow) {
            if (($want_rid > 0 && $rrow->reviewId == $want_rid)
                || ($want_rordinal > 0 && $rrow->reviewOrdinal == $want_rordinal)) {
                $this->rrow = $rrow;
            }
            if ($rrow->contactId == $this->user->contactId
                || (!$myrrow && $this->user->is_my_review($rrow))) {
                $myrrow = $rrow;
            }
            if (($rrow->requestedBy == $this->user->contactId || $this->admin)
                && !$rrow->reviewSubmitted
                && $rrow->timeApprovalRequested > 0
                && !$approvable_rrow) {
                $approvable_rrow = $rrow;
            }
        }

        if ($this->rrow) {
            $this->editrrow = $this->rrow;
        } else if (!$approvable_rrow
                   || ($myrrow
                       && $myrrow->reviewModified
                       && !$this->prefer_approvable)) {
            $this->editrrow = $myrrow;
        } else {
            $this->editrrow = $approvable_rrow;
        }

        if ($want_review
            && $this->user->can_review($this->prow, $this->editrrow, false)) {
            $this->mode = "re";
        }
    }

    function resolveComments() {
        $this->crows = $this->prow->all_comments();
        $this->mycrows = $this->prow->viewable_comments($this->user, true);
    }

    function all_reviews() {
        return $this->all_rrows;
    }

    function fixReviewMode() {
        if ($this->mode === "re"
            && $this->rrow
            && !$this->user->can_review($this->prow, $this->rrow, false)
            && ($this->rrow->contactId != $this->user->contactId
                || $this->rrow->reviewSubmitted)) {
            $this->mode = "p";
        }
        if ($this->mode === "p"
            && $this->rrow
            && !$this->user->can_view_review($this->prow, $this->rrow)) {
            $this->rrow = $this->editrrow = null;
        }
        if ($this->mode === "p"
            && $this->prow->paperId
            && empty($this->viewable_rrows)
            && empty($this->mycrows)
            && $this->prow->has_author($this->user)
            && !$this->allow_admin
            && ($this->conf->timeFinalizePaper($this->prow) || $this->prow->timeSubmitted <= 0)) {
            $this->mode = "edit";
        }
    }
}

class PaperTableFieldRender {
    /** @var PaperOption */
    public $option;
    /** @var int */
    public $view_state;
    public $title;
    public $value;
    /** @var ?bool */
    public $value_long;

    /** @param PaperOption $option */
    function __construct($option, $view_state, FieldRender $fr) {
        $this->option = $option;
        $this->view_state = $view_state;
        $this->title = $fr->title;
        $this->value = $fr->value;
        $this->value_long = $fr->value_long;
    }
}
