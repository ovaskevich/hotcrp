<?php
// formulas/f_pdfsize.php -- HotCRP helper class for formula expressions
// Copyright (c) 2009-2020 Eddie Kohler; see LICENSE.

class PdfSize_Fexpr extends Fexpr {
    function compile(FormulaCompiler $state) {
        $state->queryOptions["pdfSize"] = true;
        $prow = $state->_prow();
        return "(\$contact->can_view_pdf({$prow}) ? (int) {$prow}->size : null)";
    }
}
