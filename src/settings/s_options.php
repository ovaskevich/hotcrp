<?php
// src/settings/s_options.php -- HotCRP settings > submission form page
// Copyright (c) 2006-2019 Eddie Kohler; see LICENSE.

class Options_SettingRenderer {
    private $option_classes = [];
    private $have_options = null;
    static private function find_option_req(SettingValues $sv, PaperOption $o, $xpos) {
        if ($o->id) {
            for ($i = 1; $sv->has_reqv("optid_$i"); ++$i)
                if ($sv->reqv("optid_$i") == $o->id)
                    return $i;
        }
        return $xpos;
    }
    function add_option_class($class) {
        $this->option_classes[] = $class;
    }
    static function render_type_property(SettingValues $sv, PaperOption $o, $xpos, $self, $gj) {
        $optvt = $o->type;
        if ($optvt === "text" && $o->display_space > 3)
            $optvt .= ":ds_" . $o->display_space;

        $self->add_option_class("fold4" . ($o->has_selector() ? "o" : "c"));

        $jtypes = $sv->conf->option_type_map();
        if (!isset($jtypes[$optvt])
            && ($made_type = $sv->conf->option_type($optvt)))
            $jtypes[$optvt] = $made_type;
        uasort($jtypes, "Conf::xt_position_compare");

        $otypes = [];
        foreach ($jtypes as $uf) {
            if (!isset($uf->display_if)
                || $sv->conf->xt_check($uf->display_if, $uf, $sv->user)
                || $uf->name === $optvt)
                $otypes[$uf->name] = get($uf, "title", $uf->name);
        }

        $t = '<div class="' . $sv->control_class("optvt_$xpos", "entryi")
            . '">' . $sv->label("optvt_$xpos", "Type")
            . '<div class="entry">'
            . Ht::select("optvt_$xpos", $otypes, $optvt, ["class" => "uich js-settings-option-type", "id" => "optvt_$xpos"])
            . $sv->render_messages_at("optvt_$xpos")
            . "</div></div>\n";

        $rows = 3;
        $value = "";
        if ($o->has_selector() && count($o->selector_options())) {
            $value = join("\n", $o->selector_options()) . "\n";
            $rows = max(count($o->selector_options()), 3);
        }
        return $t . '<div class="' . $sv->control_class("optv_$xpos", "entryi fx4")
            . '">' . $sv->label("optv_$xpos", "Choices")
            . '<div class="entry">'
            . Ht::textarea("optv_$xpos", $value, $sv->sjs("optv_$xpos", ["rows" => $rows, "cols" => 50, "id" => "optv_$xpos", "class" => "reviewtext need-autogrow need-tooltip", "data-tooltip-info" => "settings-option", "data-tooltip-type" => "focus"]))
            . $sv->render_messages_at("optv_$xpos")
            . "</div></div>\n";
    }
    static function render_description_property(SettingValues $sv, PaperOption $o, $xpos, $self, $gj) {
        $self->add_option_class("fold3" . ((string) $o->description !== "" || !$o->id ? "o" : "c"));
        return '<div class="' . $sv->control_class("optd_$xpos", "entryi fx3")
            . '">' . $sv->label("optd_$xpos", "Description")
            . '<div class="entry">'
            . Ht::textarea("optd_$xpos", $o->description, ["rows" => 2, "cols" => 80, "id" => "optd_$xpos", "class" => "reviewtext settings-opt-description need-autogrow"])
            . $sv->render_messages_at("optd_$xpos")
            . '</div></div>';
    }
    static function render_presence_property(SettingValues $sv, PaperOption $o, $xpos, $self, $gj) {
        $self->add_option_class("fold5" . ($o->final || !$o->id ? "o" : "c"));
        return '<div class="' . $sv->control_class("optec_$xpos", "entryi fx5")
            . '">' . $sv->label("optec_$xpos", "Condition")
            . '<div class="entry">'
            . '<span class="sep">'
            . Ht::select("optec_$xpos", ["" => "Always shown", "final" => "Shown on final versions"], $o->final ? "final" : "", ["class" => "uich js-settings-option-condition settings-opt-presence", "id" => "optec_$xpos"])
            . $sv->render_messages_at("optec_$xpos")
            . "</span></div></div>";
    }
    static function render_required_property(SettingValues $sv, PaperOption $o, $xpos, $self, $gj) {
        $self->add_option_class("fold9" . ($o->required || !$o->id ? "o" : "c"));
        return '<div class="' . $sv->control_class("optreq_$xpos", "entryi fx9")
            . '">' . $sv->label("optreq_$xpos", "Required")
            . '<div class="entry">'
            . Ht::select("optreq_$xpos", ["" => "No", "1" => "Yes"], $o->required ? "1" : "", ["id" => "optreq_$xpos"])
            . $sv->render_messages_at("optreq_$xpos")
            . "</div></div>";
    }
    static function render_visibility_property(SettingValues $sv, PaperOption $o, $xpos, $self, $gj) {
        $self->add_option_class("fold6" . ($o->visibility !== "rev" || !$o->id ? "o" : "c"));
        return '<div class="' . $sv->control_class("optp_$xpos", "entryi short fx6")
            . '">' . $sv->label("optp_$xpos", "Visible to")
            . '<div class="entry">'
            . Ht::select("optp_$xpos", ["rev" => "PC and reviewers", "nonblind" => "PC and reviewers, if authors are visible", "admin" => "Administrators only"], $o->visibility, ["id" => "optp_$xpos", "class" => "settings-opt-visibility"])
            . $sv->render_messages_at("optp_$xpos")
            . '</div></div>';
    }
    static function render_display_property(SettingValues $sv, PaperOption $o, $xpos, $self, $gj) {
        $self->add_option_class("fold7" . ($o->display() !== PaperOption::DISP_PROMINENT || !$o->id ? "o" : "c"));
        return '<div class="' . $sv->control_class("optdt_$xpos", "entryi short fx7")
            . '">' . $sv->label("optdt_$xpos", "Display")
            . '<div class="entry">'
            . Ht::select("optdt_$xpos", ["prominent" => "Normal",
                                         "topics" => "Grouped with topics",
                                         "submission" => "Near submission"],
                         $o->display_name(), ["id" => "optdt_$xpos", "class" => "settings-opt-display"])
            . $sv->render_messages_at("optdt_$xpos")
            . "</div></div>";
    }
    private function render_option(SettingValues $sv, PaperOption $o = null, $xpos) {
        if (!$o) {
            $o = PaperOption::make(array("id" => 0,
                    "name" => "Field name",
                    "description" => "",
                    "type" => "checkbox",
                    "position" => count($sv->conf->paper_opts->nonfixed_option_list()) + 1,
                    "display" => "prominent"), $sv->conf);
        }

        if ($sv->use_req()) {
            $oxpos = self::find_option_req($sv, $o, $xpos);
            if ($sv->has_reqv("optn_$oxpos")) {
                $id = cvtint($sv->reqv("optid_$oxpos"));
                $args = [
                    "id" => $id <= 0 ? 0 : $id,
                    "name" => $sv->reqv("optn_$oxpos"),
                    "description" => $sv->reqv("optd_$oxpos"),
                    "type" => $sv->reqv("optvt_$oxpos", "checkbox"),
                    "visibility" => $sv->reqv("optp_$oxpos", ""),
                    "position" => $sv->reqv("optfp_$oxpos", 1),
                    "display" => $sv->reqv("optdt_$oxpos"),
                    "required" => $sv->reqv("optreq_$oxpos")
                ];
                if ($sv->reqv("optec_$oxpos") === "final")
                    $args["final"] = true;
                else if ($sv->reqv("optec_$oxpos") === "search")
                    $args["exists_if"] = $sv->reqv("optecs_$oxpos");
                $o = PaperOption::make($args, $sv->conf);
                if ($o->has_selector())
                    $o->set_selector_options(explode("\n", rtrim($sv->reqv("optv_$oxpos", ""))));
            }
        }

        $this->option_classes = ["settings-opt", "has-fold", "fold2o"];

        $t = "";
        foreach ($sv->group_members("options/properties") as $gj) {
            if (isset($gj->render_option_property_callback)) {
                Conf::xt_resolve_require($gj);
                $t .= call_user_func($gj->render_option_property_callback, $sv, $o, $xpos, $this, $gj);
            }
        }

        echo '<div class="', join(" ", $this->option_classes),
            '"><a href="" class="q ui settings-field-folder"><span class="expander"><span class="in0 fx2">▼</span></span></a>';

        echo '<div class="', $sv->control_class("optn_$xpos", "f-i"), '">',
            Ht::entry("optn_$xpos", $o->name, $sv->sjs("optn_$xpos", ["placeholder" => "Field name", "size" => 50, "id" => "optn_$xpos", "style" => "font-weight:bold", "class" => "need-tooltip", "data-tooltip-info" => "settings-option", "data-tooltip-type" => "focus", "aria-label" => "Field name"])),
            $sv->render_messages_at("optn_$xpos"),
            Ht::hidden("optid_$xpos", $o->id ? : "new", ["class" => "settings-opt-id"]),
            Ht::hidden("optfp_$xpos", $xpos, ["class" => "settings-opt-fp", "data-default-value" => $xpos]),
            '</div>';

        Ht::stash_script('$(settings_option_move_enable)', 'settings_optvt');
        Ht::stash_html('<div id="option_caption_name" class="hidden"><p>Field names should be short and memorable (they are used as search keywords).</p></div><div id="option_caption_options" class="hidden"><p>Enter choices one per line.</p></div>', 'settings_option_caption');

        echo $t;

        if ($o->id && $this->have_options === null) {
            $this->have_options = [];
            foreach ($sv->conf->fetch_rows("select optionId, count(distinct paperId) from PaperOption group by optionId") as $row)
                $this->have_options[$row[0]] = $row[1];
        }

        echo '<div class="f-i entryi"><label></label><div class="btnp entry">',
            '<span class="btnbox">',
            Ht::button(Icons::ui_description(), ["class" => "btn-licon ui js-settings-option-description need-tooltip", "aria-label" => "Description"]),
            Ht::button(Icons::ui_edit_hide(), ["class" => "btn-licon ui js-settings-option-presence need-tooltip", "aria-label" => "Form properties"]),
            Ht::button(Icons::ui_visibility_hide(), ["class" => "btn-licon ui js-settings-option-visibility need-tooltip", "aria-label" => "Reviewer visibility"]),
            Ht::button(Icons::ui_display(), ["class" => "btn-licon ui js-settings-option-display need-tooltip", "aria-label" => "Display type"]),
            '</span>',
            '<span class="btnbox">',
            Ht::button(Icons::ui_movearrow(0), ["class" => "btn-licon ui js-settings-option-move moveup need-tooltip", "aria-label" => "Move up in display order"]),
            Ht::button(Icons::ui_movearrow(2), ["class" => "btn-licon ui js-settings-option-move movedown need-tooltip", "aria-label" => "Move down in display order"]),
            '</span>',
            Ht::button(Icons::ui_trash(), ["class" => "btn-licon ui js-settings-option-move delete need-tooltip", "aria-label" => "Delete", "data-option-exists" => get($this->have_options, $o->id)]),
            "</div></div>\n";

        echo '</div>';
    }

    static function render(SettingValues $sv) {
        echo "<h3 class=\"settings\">Submission fields</h3>\n";
        echo "<hr class=\"g\">\n",
            Ht::hidden("has_options", 1), "\n\n";

        echo '<div id="settings_opts" class="c">';
        $self = new Options_SettingRenderer;
        $pos = 0;
        $all_options = array_merge($sv->conf->paper_opts->nonfixed_option_list()); // get our own iterator
        foreach ($all_options as $o)
            $self->render_option($sv, $o, ++$pos);
        echo "</div>\n";

        ob_start();
        $self->render_option($sv, null, 0);
        $newopt = ob_get_clean();

        echo '<div style="margin-top:2em" id="settings_newopt" data-template="',
            htmlspecialchars($newopt), '">',
            Ht::button("Add submission field", ["class" => "ui js-settings-option-new"]),
            "</div>\n";
    }
    static function crosscheck(SettingValues $sv) {
        if (($sv->has_interest("options") || $sv->has_interest("sub_blind"))
            && $sv->newv("options")
            && $sv->newv("sub_blind") == Conf::BLIND_ALWAYS) {
            $options = (array) json_decode($sv->newv("options"));
            usort($options, function ($a, $b) { return $a->position - $b->position; });
            foreach ($options as $pos => $o)
                if (get($o, "visibility") === "nonblind")
                    $sv->warning_at("optp_" . ($pos + 1), "The “" . htmlspecialchars($o->name) . "” field is “visible if authors are visible,” but authors are not visible. You may want to change " . $sv->setting_link("Settings &gt; Submissions &gt; Blind submission", "sub_blind") . " to “Blind until review.”");
        }
    }
}

class Options_SettingParser extends SettingParser {
    private $next_optionid;
    private $req_optionid;
    private $stashed_options = false;
    private $fake_prow;

    function option_request_to_json(SettingValues $sv, $xpos) {
        $name = simplify_whitespace($sv->reqv("optn_$xpos", ""));
        if ($name === "" || $name === "(Enter new option)" || $name === "Field name")
            return null;
        if (preg_match('/\A(?:paper|submission|final|none|any|all|true|false|opt(?:ion)?[-:_ ]?\d+)\z/i', $name))
            $sv->error_at("optn_$xpos", "Option name “" . htmlspecialchars($name) . "” is reserved. Please pick another name.");

        $id = cvtint($sv->reqv("optid_$xpos", "new"));
        $is_new = $id < 0;
        if ($is_new) {
            if (!$this->next_optionid) {
                $oid1 = $sv->conf->fetch_ivalue("select coalesce(max(optionId),0) + 1 from PaperOption where optionId<" . PaperOption::MINFIXEDID);
                $oid2 = $sv->conf->fetch_ivalue("select coalesce(max(documentType),0) + 1 from PaperStorage where documentType>0 and documentType<" . PaperOption::MINFIXEDID);
                $this->next_optionid = max($oid1, $oid2, $this->req_optionid);
            }
            assert($this->next_optionid > 0 && $this->next_optionid < PaperOption::MINFIXEDID);
            $id = $this->next_optionid++;
        }
        $oarg = ["name" => $name, "id" => $id, "final" => false];

        if ($sv->reqv("optd_$xpos") && trim($sv->reqv("optd_$xpos")) != "") {
            $t = CleanHTML::basic_clean($sv->reqv("optd_$xpos"), $err);
            if ($t !== false)
                $oarg["description"] = $t;
            else
                $sv->error_at("optd_$xpos", $err);
        }

        if (($optvt = $sv->reqv("optvt_$xpos"))) {
            if (($pos = strpos($optvt, ":")) !== false) {
                $oarg["type"] = substr($optvt, 0, $pos);
                if (preg_match('/:ds_(\d+)/', $optvt, $m))
                    $oarg["display_space"] = (int) $m[1];
            } else
                $oarg["type"] = $optvt;
        } else
            $oarg["type"] = "checkbox";

        if (($optec = $sv->reqv("optec_$xpos"))) {
            if ($optec === "final")
                $oarg["final"] = true;
            else if ($optec === "search") {
                $optecs = (string) $sv->reqv("optecs_$xpos");
                if ($optecs !== "" && $optecs !== "(All)") {
                    $ps = new PaperSearch($sv->conf->site_contact(), $optecs);
                    if (!$this->fake_prow)
                        $this->fake_prow = new PaperInfo(null, null, $sv->conf);
                    if ($ps->term()->compile_condition($this->fake_prow, $ps) === null)
                        $sv->error_at("optecs_$xpos", "Search too complex for field condition. (Not all search keywords are supported for field conditions.)");
                    else
                        $oarg["exists_if"] = $optecs;
                    if (!empty($ps->warnings))
                        $sv->warning_at("optecs_$xpos", join("<br>", $ps->warnings));
                }
            }
        }

        $jtype = $sv->conf->option_type($oarg["type"]);
        if ($jtype && get($jtype, "has_selector")) {
            $oarg["selector"] = array();
            $seltext = trim(cleannl($sv->reqv("optv_$xpos", "")));
            if ($seltext != "") {
                foreach (explode("\n", $seltext) as $t)
                    $oarg["selector"][] = $t;
            } else
                $sv->error_at("optv_$xpos", "Enter selectors one per line.");
        }

        $oarg["visibility"] = $sv->reqv("optp_$xpos", "rev");
        $oarg["position"] = (int) $sv->reqv("optfp_$xpos", 1);
        $oarg["display"] = $sv->reqv("optdt_$xpos");
        $oarg["required"] = !!$sv->reqv("optreq_$xpos");

        $o = PaperOption::make($oarg, $sv->conf);
        $o->req_xpos = $xpos;
        $o->is_new = $is_new;
        return $o;
    }

    function parse(SettingValues $sv, Si $si) {
        $new_opts = $sv->conf->paper_opts->nonfixed_option_list();

        // consider option ids
        $optids = array_map(function ($o) { return $o->id; }, $new_opts);
        for ($i = 1; $sv->has_reqv("optid_$i"); ++$i)
            $optids[] = intval($sv->reqv("optid_$i"));
        $optids[] = 0;
        $this->req_optionid = max($optids) + 1;

        // convert request to JSON
        for ($i = 1; $sv->has_reqv("optid_$i"); ++$i) {
            if ($sv->reqv("optfp_$i") === "deleted")
                unset($new_opts[cvtint($sv->reqv("optid_$i"))]);
            else if (($o = $this->option_request_to_json($sv, $i)))
                $new_opts[$o->id] = $o;
        }

        if (!$sv->has_error()) {
            uasort($new_opts, "PaperOption::compare");
            $this->stashed_options = $new_opts;
            $sv->need_lock["PaperOption"] = true;
            return true;
        }
    }

    function unparse_json(SettingValues $sv, Si $si, $j) {
        $oj = [];
        foreach ($sv->conf->paper_opts->nonfixed_option_list() as $o)
            $oj[] = $o->unparse();
        $j->options = $oj;
    }

    function save(SettingValues $sv, Si $si) {
        $newj = [];
        foreach ($this->stashed_options as $o)
            $newj[] = $o->unparse();
        $sv->save("next_optionid", null);
        $sv->save("options", empty($newj) ? null : json_encode_db($newj));

        $deleted_ids = array();
        foreach ($sv->conf->paper_opts->nonfixed_option_list() as $o) {
            $newo = get($this->stashed_options, $o->id);
            if (!$newo
                || ($newo->type !== $o->type
                    && !$newo->change_type($o, true, true)
                    && !$o->change_type($newo, false, true)))
                $deleted_ids[] = $o->id;
        }
        if (!empty($deleted_ids))
            $sv->conf->qe("delete from PaperOption where optionId?a", $deleted_ids);

        // invalidate cached option list
        $sv->conf->invalidate_caches(["options" => true]);
    }
}
