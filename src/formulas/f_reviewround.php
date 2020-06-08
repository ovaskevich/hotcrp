<?php
// formulas/f_reviewround.php -- HotCRP helper class for formula expressions
// Copyright (c) 2009-2020 Eddie Kohler; see LICENSE.

class ReviewRound_Fexpr extends Fexpr {
    function __construct() {
        $this->_format = self::FROUND;
    }
    function inferred_index() {
        return Fexpr::IDX_PC;
    }
    function view_score(Contact $user) {
        return VIEWSCORE_PC;
    }
    function compile(FormulaCompiler $state) {
        $rrow = $state->_rrow();
        if ($state->index_type === Fexpr::IDX_MY) {
            return $state->define_gvar("myrevround", "{$rrow} ? {$rrow}->reviewRound : null");
        } else {
            $view_score = $state->user->permissive_view_score_bound();
            if (VIEWSCORE_PC <= $view_score) {
                return "null";
            }
            $state->queryOptions["reviewSignatures"] = true;
            $rrow_vsb = $state->_rrow_view_score_bound();
            return "(" . VIEWSCORE_PC . " > $rrow_vsb ? {$rrow}->reviewRound : null)";
        }
    }
}
