<?php
// filefilter.php -- HotCRP helper class for filtering documents
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class FileFilter {
    public $id;
    public $name;

    /** @return array<string,FileFilter> */
    static function all_by_name(Conf $conf) {
        if ($conf->_file_filters === null) {
            $conf->_file_filters = [];
            if (($flist = $conf->opt("documentFilters"))) {
                $ffa = new FileFilterJsonExpander($conf);
                expand_json_includes_callback($flist, [$ffa, "_add_json"]);
            }
        }
        return $conf->_file_filters;
    }
    /** @param string $name
     * @return ?FileFilter */
    static function find_by_name(Conf $conf, $name) {
        return (self::all_by_name($conf))[$name] ?? null;
    }

    /** @param DocumentInfo $doc
     * @param string $name
     * @return DocumentInfo */
    static function apply_named($doc, PaperInfo $prow, $name) {
        if (($filter = self::find_by_name($prow->conf, $name))
            && ($xdoc = $filter->apply($doc, $prow))) {
            return $xdoc;
        } else {
            return $doc;
        }
    }

    /** @param DocumentInfo $doc
     * @return ?DocumentInfo */
    function find_filtered($doc) {
        if ($this->id) {
            $result = $doc->conf->qe("select PaperStorage.* from FilteredDocument join PaperStorage on (PaperStorage.paperStorageId=FilteredDocument.outDocId) where inDocId=? and FilteredDocument.filterType=?", $doc->paperStorageId, $this->id);
            $fdoc = DocumentInfo::fetch($result, $doc->conf);
            Dbl::free($result);
        } else {
            $fdoc = null;
        }
        if ($fdoc) {
            $fdoc->filters_applied = $doc->filters_applied;
            $fdoc->filters_applied[] = $this;
        }
        return $fdoc;
    }

    function mimetype($doc, $mimetype) {
        return $mimetype;
    }

    function apply($doc, PaperInfo $prow) {
        return false;
    }
}

class FileFilterJsonExpander {
    /** @var Conf */
    private $conf;
    function __construct(Conf $conf) {
        $this->conf = $conf;
    }
    function _add_json($fj) {
        if (is_object($fj)
            && (!isset($fj->id) || is_int($fj->id))
            && isset($fj->name) && is_string($fj->name) && $fj->name !== ""
            && ctype_alnum($fj->name) && !ctype_digit($fj->name)
            && isset($fj->callback) && is_string($fj->callback)) {
            $ff = null;
            if ($fj->callback[0] === "+") {
                $class = substr($fj->callback, 1);
                /** @phan-suppress-next-line PhanTypeExpectedObjectOrClassName */
                $ff = new $class($this->conf, $fj);
            } else {
                $ff = call_user_func($fj->callback, $this->conf, $fj);
            }
            if ($ff) {
                $ff->id = get($fj, "id");
                $ff->name = $fj->name;
                $this->conf->_file_filters[$ff->name] = $ff;
                return true;
            }
        }
        return false;
    }
}
