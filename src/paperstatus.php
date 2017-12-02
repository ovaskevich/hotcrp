<?php
// paperstatus.php -- HotCRP helper for reading/storing papers as JSON
// HotCRP is Copyright (c) 2008-2017 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

class PaperStatus extends MessageSet {
    private $conf;
    private $contact;
    private $uploaded_documents;
    private $no_email = false;
    private $forceShow = null;
    private $export_ids = false;
    private $hide_docids = false;
    private $export_content = false;
    private $disable_users = false;
    private $allow_any_content_file = false;
    private $content_file_prefix = false;
    private $add_topics = false;
    private $prow;
    private $paperid;
    private $_on_document_export = [];
    private $_on_document_import = [];
    private $qf;
    private $qv;

    const SUBMITTED_AT_FOR_WITHDRAWN = 1000000000;

    function __construct(Conf $conf, Contact $contact = null, $options = array()) {
        $this->conf = $conf;
        $this->contact = $contact;
        foreach (array("no_email", "forceShow", "export_ids", "hide_docids",
                       "export_content", "disable_users",
                       "allow_any_content_file", "content_file_prefix",
                       "add_topics") as $k)
            if (array_key_exists($k, $options))
                $this->$k = $options[$k];
        $this->_on_document_import[] = [$this, "document_import_check_filename"];
        $this->clear();
    }

    function clear() {
        parent::clear();
        $this->uploaded_documents = [];
        $this->prow = null;
    }

    function on_document_export($cb) {
        // arguments: $document_json, DocumentInfo $doc, $dtype, PaperStatus $pstatus
        $this->_on_document_export[] = $cb;
    }

    function on_document_import($cb) {
        // arguments: $document_json, $prow
        $this->_on_document_import[] = $cb;
    }

    function user() {
        return $this->contact;
    }

    function paper_row() {
        return $this->prow;
    }

    private function _() {
        return call_user_func_array([$this->conf->ims(), "x"], func_get_args());
    }

    function document_to_json($dtype, $docid) {
        if (!is_object($docid))
            $doc = $this->prow ? $this->prow->document($dtype, $docid) : null;
        else {
            $doc = $docid;
            $docid = $doc->paperStorageId;
        }
        if (!$doc)
            return null;
        assert($doc instanceof DocumentInfo);

        $d = (object) array();
        if ($docid && !$this->hide_docids)
            $d->docid = $docid;
        if ($doc->mimetype)
            $d->mimetype = $doc->mimetype;
        if ($doc->has_hash())
            $d->hash = $doc->text_hash();
        if ($doc->timestamp)
            $d->timestamp = $doc->timestamp;
        if ($doc->size)
            $d->size = $doc->size;
        if ($doc->filename)
            $d->filename = $doc->filename;
        $meta = null;
        if (isset($doc->infoJson) && is_object($doc->infoJson))
            $meta = $doc->infoJson;
        else if (isset($doc->infoJson) && is_string($doc->infoJson))
            $meta = json_decode($doc->infoJson);
        if ($meta)
            $d->metadata = $meta;
        if ($this->export_content
            && $doc->docclass->load($doc))
            $d->content_base64 = base64_encode(Filer::content($doc));
        foreach ($this->_on_document_export as $cb)
            if (call_user_func($cb, $d, $doc, $dtype, $this) === false)
                return null;
        if (!count(get_object_vars($d)))
            $d = null;
        return $d;
    }

    function paper_json($prow, $args = array()) {
        if (is_int($prow))
            $prow = $this->conf->paperRow(["paperId" => $prow, "topics" => true, "options" => true], $this->contact);
        $contact = $this->contact;
        if (get($args, "forceShow"))
            $contact = null;

        if (!$prow || ($contact && !$contact->can_view_paper($prow)))
            return null;
        $was_no_msgs = $this->ignore_msgs;
        $this->ignore_msgs = !get($args, "msgs");

        $this->prow = $prow;
        $this->paperId = $prow->paperId;

        $pj = (object) array();
        $pj->pid = (int) $prow->paperId;
        $pj->title = $prow->title;

        $submitted_status = "submitted";
        if ($prow->outcome != 0
            && (!$contact || $contact->can_view_decision($prow, $this->forceShow))) {
            $pj->decision = $this->conf->decision_name($prow->outcome);
            if ($pj->decision === false) {
                $pj->decision = (int) $prow->outcome;
                $submitted_status = $pj->decision > 0 ? "accepted" : "rejected";
            } else
                $submitted_status = $pj->decision;
        }

        if ($prow->timeWithdrawn > 0) {
            $pj->status = "withdrawn";
            $pj->withdrawn = true;
            $pj->withdrawn_at = (int) $prow->timeWithdrawn;
            if (get($prow, "withdrawReason"))
                $pj->withdraw_reason = $prow->withdrawReason;
        } else if ($prow->timeSubmitted > 0) {
            $pj->status = $submitted_status;
            $pj->submitted = true;
        } else {
            $pj->status = "inprogress";
            $pj->draft = true;
        }
        if ($prow->timeSubmitted > 0)
            $pj->submitted_at = (int) $prow->timeSubmitted;
        else if ($prow->timeSubmitted == -100 && $prow->timeWithdrawn > 0)
            $pj->submitted_at = self::SUBMITTED_AT_FOR_WITHDRAWN;
        else if ($prow->timeSubmitted < -100 && $prow->timeWithdrawn > 0)
            $pj->submitted_at = -$prow->timeSubmitted;

        $can_view_authors = !$contact
            || $contact->can_view_authors($prow, $this->forceShow);
        if ($can_view_authors) {
            $contacts = array();
            foreach ($prow->named_contacts() as $cflt)
                $contacts[strtolower($cflt->email)] = $cflt;

            $pj->authors = array();
            foreach ($prow->author_list() as $au) {
                $aux = (object) array();
                if ($au->email)
                    $aux->email = $au->email;
                if ($au->firstName)
                    $aux->first = $au->firstName;
                if ($au->lastName)
                    $aux->last = $au->lastName;
                if ($au->affiliation)
                    $aux->affiliation = $au->affiliation;
                $lemail = strtolower((string) $au->email);
                if ($lemail && ($cflt = get($contacts, $lemail))
                    && $cflt->conflictType >= CONFLICT_AUTHOR) {
                    $aux->contact = true;
                    unset($contacts[$lemail]);
                }
                $pj->authors[] = $aux;
            }

            $other_contacts = array();
            foreach ($contacts as $cflt)
                if ($cflt->conflictType >= CONFLICT_AUTHOR) {
                    $aux = (object) array("email" => $cflt->email);
                    if ($cflt->firstName)
                        $aux->first = $cflt->firstName;
                    if ($cflt->lastName)
                        $aux->last = $cflt->lastName;
                    if ($cflt->affiliation)
                        $aux->affiliation = $cflt->affiliation;
                    $other_contacts[] = $aux;
                }
            if (!empty($other_contacts))
                $pj->contacts = $other_contacts;
        }

        if ($this->conf->submission_blindness() == Conf::BLIND_OPTIONAL)
            $pj->nonblind = !(isset($pj->paperBlind) ? $prow->paperBlind : $prow->blind);

        if ($prow->abstract !== "" || !$this->conf->opt("noAbstract"))
            $pj->abstract = $prow->abstract;

        $topics = array();
        foreach ($prow->named_topic_map() as $tid => $tname)
            $topics[$this->export_ids ? $tid : $tname] = true;
        if (!empty($topics))
            $pj->topics = (object) $topics;

        if ($prow->paperStorageId > 1
            && (!$contact || $contact->can_view_pdf($prow))
            && ($doc = $this->document_to_json(DTYPE_SUBMISSION, (int) $prow->paperStorageId)))
            $pj->submission = $doc;

        if ($prow->finalPaperStorageId > 1
            && (!$contact || $contact->can_view_pdf($prow))
            && ($doc = $this->document_to_json(DTYPE_FINAL, (int) $prow->finalPaperStorageId)))
            $pj->final = $doc;
        if ($prow->timeFinalSubmitted > 0) {
            $pj->final_submitted = true;
            $pj->final_submitted_at = (int) $prow->timeFinalSubmitted;
        }

        $options = array();
        foreach ($this->conf->paper_opts->option_list() as $o) {
            if ($contact && !$contact->can_view_paper_option($prow, $o, $this->forceShow))
                continue;
            $ov = $prow->option($o->id) ? : new PaperOptionValue($prow, $o);
            $oj = $o->unparse_json($ov, $this, $contact);
            if ($oj !== null)
                $options[$this->export_ids ? $o->id : $o->json_key()] = $oj;
        }
        if (!empty($options))
            $pj->options = (object) $options;

        if ($can_view_authors) {
            $pcconflicts = array();
            foreach ($prow->pc_conflicts(true) as $id => $cflt) {
                if (($ctname = get(Conflict::$type_names, $cflt->conflictType)))
                    $pcconflicts[$cflt->email] = $ctname;
            }
            if (!empty($pcconflicts))
                $pj->pc_conflicts = (object) $pcconflicts;
            if ($prow->collaborators)
                $pj->collaborators = $prow->collaborators;
        }

        // Now produce messages.
        if (!$this->ignore_msgs
            && $can_view_authors) {
            $msg1 = $msg2 = false;
            foreach ($prow->author_list() as $n => $au)
                if (strpos($au->email, "@") === false
                    && strpos($au->affiliation, "@") !== false) {
                    $msg1 = true;
                    $this->warning_at("author" . ($n + 1), null);
                } else if ($au->firstName === "" && $au->lastName === ""
                           && $au->email === "" && $au->affiliation !== "") {
                    $msg2 = true;
                    $this->warning_at("author" . ($n + 1), null);
                }
            if ($msg1)
                $this->warning_at("authors", "You may have entered an email address in the wrong place. The first author field is for author name, the second for email address, and the third for affiliation.");
            if ($msg2)
                $this->warning_at("authors", "Please enter a name and optional email address for every author.");
        }
        if (!$this->ignore_msgs
            && $can_view_authors
            && $this->conf->setting("sub_collab")
            && ($prow->outcome <= 0 || ($contact && !$contact->can_view_decision($prow)))) {
            $field = $this->_($this->conf->setting("sub_pcconf") ? "Other conflicts" : "Potential conflicts");
            if (!$prow->collaborators)
                $this->warning_at("collaborators", $this->_("Enter the authors’ external conflicts of interest in the %s field. If none of the authors have external conflicts, enter “None”.", $field));
            else {
                if ($prow->collaborators !== Contact::fix_collaborator_affiliations($prow->collaborators, true))
                    $this->warning_at("collaborators", $this->_("Please use parentheses to indicate affiliations in the %s field. (It looks like you might have used other punctuation.)", $field));
                if (Contact::suspect_collaborator_one_line($prow->collaborators))
                    $this->warning_at("collaborators", $this->_("Please enter one potential conflict per line in the %s field. (It looks like you might have multiple conflicts per line.)", $field));
            }
        }
        if (!$this->ignore_msgs
            && $can_view_authors
            && $this->conf->setting("sub_pcconf")
            && ($prow->outcome <= 0 || ($contact && !$contact->can_view_decision($prow)))) {
            foreach ($this->conf->full_pc_members() as $p)
                if (!$prow->has_conflict($p)
                    && $prow->potential_conflict($p)) {
                    $this->warning_at("pcconf", $this->_("You may have missed some PC conflicts of interest. Please verify the highlighted PC members."));
                    break;
                }
        }

        $this->ignore_msgs = $was_no_msgs;
        return $pj;
    }


    static function clone_json($pj) {
        $x = (object) [];
        foreach ($pj ? get_object_vars($pj) : [] as $k => $v)
            if (is_object($v))
                $x->$k = self::clone_json($v);
            else
                $x->$k = $v;
        return $x;
    }


    function error_at_option(PaperOption $o, $html) {
        $this->error_at($o->field_key(), htmlspecialchars($o->name) . ": " . $html);
    }

    function warning_at_option(PaperOption $o, $html) {
        $this->warning_at($o->field_key(), htmlspecialchars($o->name) . ": " . $html);
    }


    function set_document_prow($prow) {
        // XXX this is butt ugly
        $this->prow = $prow;
        $this->paperId = $prow->paperId ? : -1;
    }

    function document_import_check_filename($docj, PaperOption $o, PaperStatus $pstatus) {
        unset($docj->filestore);
        if (isset($docj->content_file) && is_string($docj->content_file)) {
            if (!$this->allow_any_content_file && preg_match(',\A/|(?:\A|/)\.\.(?:/|\z),', $docj->content_file)) {
                $pstatus->error_at_option($o, "Bad content_file: only simple filenames allowed.");
                return false;
            }
            if ((string) $this->content_file_prefix !== "")
                $docj->content_file = $this->content_file_prefix . $docj->content_file;
        }
    }

    function upload_document($docj, PaperOption $o) {
        if (!is_object($docj) && is_array($docj) && count($docj) === 1)
            $docj = $docj[0];
        if (!is_object($docj)) {
            $this->error_at($o->json_key, "Format error [{$o->json_key}]");
            return false;
        } else if (get($docj, "error") || get($docj, "error_html")) {
            $this->error_at_option($o, get($docj, "error_html", "Upload error."));
            $docj->docid = 1;
            return $docj;
        }

        // check on_document_import
        foreach ($this->_on_document_import as $cb)
            if (call_user_func($cb, $docj, $o, $this) === false) {
                $docj->docid = 1;
                return $docj;
            }

        // look for an existing document with same hash;
        // check existing docid's hash
        $docid = get($docj, "docid");
        if (!isset($docj->hash) && isset($docj->sha1)) {
            if (($hash = Filer::sha1_hash_as_text($docj->sha1)) !== false)
                $docj->hash = $hash;
            unset($docj->sha1);
        }
        $dochash = (string) get($docj, "hash");

        if ($docid) {
            $oldj = $this->document_to_json($o->id, $docid);
            if (!$oldj
                || ($dochash !== "" && !isset($oldj->hash))
                || ($dochash !== "" && !Filer::check_text_hash($oldj->hash, $dochash)))
                $docid = null;
        } else if ($this->paperId != -1 && $dochash !== "") {
            $oldj = Dbl::fetch_first_object($this->conf->dblink, "select paperStorageId, sha1 as hash, timestamp, size, mimetype from PaperStorage where paperId=? and documentType=? and PaperStorage.sha1=?", $this->paperId, $o->id, Filer::hash_as_binary($dochash));
            if ($oldj)
                $docid = (int) $oldj->paperStorageId;
        }
        if ($docid) {
            $docj->docid = $docid;
            $docj->hash = Filer::hash_as_binary($oldj->hash);
            $docj->timestamp = (int) $oldj->timestamp;
            $docj->size = (int) $oldj->size;
            $docj->mimetype = $oldj->mimetype;
            return $docj;
        }

        // check filter
        if (get($docj, "filter") && is_int($docj->filter)) {
            if (is_int(get($docj, "original_id")))
                $result = $this->conf->qe("select paperStorageId, timestamp, sha1 from PaperStorage where paperId=? and paperStorageId=?", $this->paperId, $docj->original_id);
            else if (is_string(get($docj, "original_hash")))
                $result = $this->conf->qe("select paperStorageId, timestamp, sha1 from PaperStorage where paperId=? and sha1=?", $this->paperId, Filer::hash_as_binary($docj->original_hash));
            else if ($o->id == DTYPE_SUBMISSION || $o->id == DTYPE_FINAL)
                $result = $this->conf->qe("select PaperStorage.paperStorageId, PaperStorage.timestamp, PaperStorage.sha1 from PaperStorage join Paper on (Paper.paperId=PaperStorage.paperId and Paper." . ($o->id == DTYPE_SUBMISSION ? "paperStorageId" : "finalPaperStorageId") . "=PaperStorage.paperStorageId) where Paper.paperId=?", $this->paperId);
            else
                $result = null;
            if (($row = edb_orow($result))) {
                $docj->original_id = (int) $row->paperStorageId;
                $docj->original_timestamp = (int) $row->timestamp;
                $docj->original_hash = $row->sha1;
                if (get($docj, "preserve_timestamp"))
                    $docj->timestamp = (int) $docj->original_timestamp;
            } else
                unset($docj->original_id);
            Dbl::free($result);
        }

        // if no hash match, upload
        $docclass = $this->conf->docclass($o->id);
        $docj->paperId = $this->paperId;
        $newdoc = new DocumentInfo($docj);
        if ($docclass->upload($newdoc) && $newdoc->paperStorageId > 1) {
            foreach (["size", "mimetype", "timestamp"] as $k)
                $docj->$k = $newdoc->$k;
            $docj->hash = $newdoc->text_hash();
            $this->uploaded_documents[] = $docj->docid = $newdoc->paperStorageId;
        } else {
            $docj->docid = 1;
            $this->error_at_option($o, $newdoc ? $newdoc->error_html : "Empty document.");
        }
        return $docj;
    }

    private function normalize_string($pj, $k, $simplify, $preserve) {
        if (isset($pj->$k) && is_string($pj->$k)) {
            if (!$preserve && $simplify)
                $pj->$k = simplify_whitespace($pj->$k);
            else if (!$preserve)
                $pj->$k = trim($pj->$k);
        } else if (isset($pj->$k)) {
            $this->error_at($k, "Format error [$k]");
            unset($pj, $k);
        }
    }

    private function normalize_author($pj, $au, &$au_by_email, $old_au_by_email, $preserve) {
        if (!$preserve) {
            $aux = Text::analyze_name($au);
            $aux->first = simplify_whitespace($aux->firstName);
            $aux->last = simplify_whitespace($aux->lastName);
            $aux->email = simplify_whitespace($aux->email);
            $aux->affiliation = simplify_whitespace($aux->affiliation);
        } else {
            $aux = clone $au;
            foreach (["first", "last", "email", "affiliation"] as $k)
                if (!isset($aux->$k))
                    $aux->$k = "";
        }
        // borrow from old author information
        if ($aux->email && $aux->first === "" && $aux->last === ""
            && ($old_au = get($old_au_by_email, strtolower($aux->email)))) {
            $aux->first = get($old_au, "first", "");
            $aux->last = get($old_au, "last", "");
            if ($aux->affiliation === "")
                $aux->affiliation = get($old_au, "affiliation", "");
        }
        if ($aux->first !== "" || $aux->last !== ""
            || $aux->email !== "" || $aux->affiliation !== "")
            $pj->authors[] = $aux;
        else
            $pj->bad_authors[] = $aux;
        $aux->index = count($pj->authors) + count($pj->bad_authors);
        if (is_object($au) && isset($au->contact))
            $aux->contact = !!$au->contact;
        if ($aux->email) {
            $lemail = strtolower($aux->email);
            $au_by_email[$lemail] = $aux;
            if (!validate_email($lemail) && !isset($old_au_by_email[$lemail]))
                $pj->bad_email_authors[] = $aux;
        }
    }

    private function normalize_topics($pj) {
        $topics = $pj->topics;
        unset($pj->topics);
        if (is_string($topics))
            $topics = explode("\n", cleannl($topics));
        if (is_array($topics)) {
            $new_topics = (object) array();
            foreach ($topics as $v) {
                if ($v && (is_int($v) || is_string($v)))
                    $new_topics->$v = true;
                else if ($v)
                    $this->error_at("topics", "Format error [topics]");
            }
            $topics = $new_topics;
        }
        if (is_object($topics)) {
            $topic_map = $this->conf->topic_map();
            $pj->topics = (object) array();
            foreach ($topics as $k => $v) {
                if (!$v)
                    /* skip */;
                else if (isset($topic_map[$k]))
                    $pj->topics->$k = true;
                else {
                    $tid = array_search($k, $topic_map, true);
                    if ($tid === false && $k !== "" && !ctype_digit($k)) {
                        $tmatches = [];
                        foreach ($topic_map as $tid => $tname)
                            if (strcasecmp($k, $tname) == 0)
                                $tmatches[] = $tid;
                        if (empty($tmatches) && $this->add_topics) {
                            $this->conf->qe("insert into TopicArea set topicName=?", $k);
                            if (!$this->conf->has_topics())
                                $this->conf->save_setting("has_topics", 1);
                            $this->conf->invalidate_topics();
                            $topic_map = $this->conf->topic_map();
                            if (($tid = array_search($k, $topic_map, true)) !== false)
                                $tmatches[] = $tid;
                        }
                        $tid = (count($tmatches) == 1 ? $tmatches[0] : false);
                    }
                    if ($tid !== false)
                        $pj->topics->$tid = true;
                    else
                        $pj->bad_topics[] = $k;
                }
            }
        } else if ($topics)
            $this->error_at("topics", "Format error [topics]");
    }

    private function normalize_options($pj, $options) {
        // canonicalize option values to use IDs, not abbreviations
        $pj->options = (object) array();
        foreach ($options as $id => $oj) {
            $omatches = $this->conf->paper_opts->find_all($id);
            if (count($omatches) != 1)
                $pj->bad_options[$id] = true;
            else {
                $o = current($omatches);
                // XXX setting decision in JSON?
                if (($o->final && (!$this->prow || $this->prow->outcome <= 0))
                    || $o->id <= 0)
                    continue;
                $oid = $o->id;
                $pj->options->$oid = $oj;
            }
        }
    }

    private function normalize_pc_conflicts($pj) {
        $conflicts = get($pj, "pc_conflicts");
        $pj->pc_conflicts = (object) array();
        if (is_object($conflicts))
            $conflicts = (array) $conflicts;
        foreach ($conflicts as $email => $ct) {
            if (is_int($email) && is_string($ct))
                list($email, $ct) = array($ct, true);
            if (!($pccid = $this->conf->pc_member_by_email($email)))
                $pj->bad_pc_conflicts->$email = true;
            else if (!is_bool($ct) && !is_int($ct) && !is_string($ct))
                $this->error_at("pc_conflicts", "Format error [PC conflicts]");
            else {
                if (is_int($ct) && isset(Conflict::$type_names[$ct]))
                    $ctn = $ct;
                else if ((is_bool($ct) || is_string($ct))
                         && ($ctn = Conflict::parse($ct, CONFLICT_AUTHORMARK)) !== false)
                    /* OK */;
                else {
                    $pj->bad_pc_conflicts->$email = $ct;
                    $ctn = Conflict::parse("other", 1);
                }
                $pj->pc_conflicts->$email = $ctn;
            }
        }
    }

    private function valid_contact($lemail, $old_contacts) {
        global $Me;
        return $lemail
            && (get($old_contacts, $lemail) || validate_email($lemail)
                || strcasecmp($lemail, $Me->email) == 0);
    }

    private function normalize($pj, $old_pj, $preserve) {
        // Errors prevent saving
        global $Now;

        // Title, abstract
        $this->normalize_string($pj, "title", true, $preserve);
        $this->normalize_string($pj, "abstract", false, $preserve);
        $this->normalize_string($pj, "collaborators", false, $preserve);
        if (isset($pj->collaborators))
            $pj->collaborators = Contact::clean_collaborator_lines($pj->collaborators);

        // Authors
        $au_by_email = array();
        $pj->bad_authors = $pj->bad_email_authors = array();
        if (isset($pj->authors)) {
            if (!is_array($pj->authors))
                $this->error_at("authors", "Format error [authors]");
            // old author information
            $old_au_by_email = [];
            if ($old_pj && isset($old_pj->authors)) {
                foreach ($old_pj->authors as $au)
                    if (isset($au->email))
                        $old_au_by_email[strtolower($au->email)] = $au;
            }
            // new author information
            $curau = is_array($pj->authors) ? $pj->authors : array();
            $pj->authors = array();
            foreach ($curau as $k => $au)
                if (is_string($au) || is_object($au))
                    $this->normalize_author($pj, $au, $au_by_email, $old_au_by_email, $preserve);
                else
                    $this->error_at("authors", "Format error [authors]");
        }

        // Status
        foreach (array("withdrawn_at", "submitted_at", "final_submitted_at") as $k)
            if (isset($pj->$k)) {
                if (is_numeric($pj->$k))
                    $pj->$k = (int) $pj->$k;
                else if (is_string($pj->$k))
                    $pj->$k = $this->conf->parse_time($pj->$k, $Now);
                else
                    $pj->$k = false;
                if ($pj->$k === false || $pj->$k < 0)
                    $pj->$k = $Now;
            }

        // Blindness
        if (isset($pj->nonblind)) {
            if (($x = friendly_boolean($pj->nonblind)) !== null)
                $pj->nonblind = $x;
            else {
                $this->error_at("nonblind", "Format error [nonblind]");
                unset($pj->nonblind);
            }
        }

        // Topics
        $pj->bad_topics = array();
        if (isset($pj->topics))
            $this->normalize_topics($pj);

        // Options
        $pj->bad_options = array();
        if (isset($pj->options)) {
            if (is_associative_array($pj->options) || is_object($pj->options))
                $this->normalize_options($pj, $pj->options);
            else if (is_array($pj->options) && count($pj->options) == 1 && is_object($pj->options[0]))
                $this->normalize_options($pj, $pj->options[0]);
            else if ($pj->options === false)
                $pj->options = (object) array();
            else {
                $this->error_at("options", "Format error [options]");
                unset($pj->options);
            }
        }

        // PC conflicts
        $pj->bad_pc_conflicts = (object) array();
        if (get($pj, "pc_conflicts")
            && (is_object($pj->pc_conflicts) || is_array($pj->pc_conflicts)))
            $this->normalize_pc_conflicts($pj);
        else if (get($pj, "pc_conflicts") === false)
            $pj->pc_conflicts = (object) array();
        else if (isset($pj->pc_conflicts)) {
            $this->error_at("pc_conflicts", "Format error [PC conflicts]");
            unset($pj->pc_conflicts);
        }

        // Old contacts (to avoid validate_email errors on unchanged contacts)
        $old_contacts = array();
        if ($old_pj && get($old_pj, "authors"))
            foreach ($old_pj->authors as $au)
                if (get($au, "contact"))
                    $old_contacts[strtolower($au->email)] = true;
        if ($old_pj && get($old_pj, "contacts"))
            foreach ($old_pj->contacts as $cflt)
                $old_contacts[strtolower($cflt->email)] = true;

        // verify emails on authors marked as contacts
        $pj->bad_contacts = array();
        foreach (get($pj, "authors") ? : array() as $au)
            if (get($au, "contact")
                && (!get($au, "email")
                    || !$this->valid_contact(strtolower($au->email), $old_contacts)))
                $pj->bad_contacts[] = $au;

        // Contacts
        $contacts = get($pj, "contacts");
        if ($contacts !== null) {
            if (is_object($contacts) || is_array($contacts))
                $contacts = (array) $contacts;
            else {
                $this->error_at("contacts", "Format error [contacts]");
                $contacts = array();
            }
            $pj->contacts = array();
            // verify emails on explicitly named contacts
            foreach ($contacts as $k => $v) {
                if (!$v)
                    continue;
                if ($v === true)
                    $v = (object) array();
                else if (is_string($v) && is_int($k)) {
                    $v = trim($v);
                    if ($this->valid_contact(strtolower($v), $old_contacts))
                        $v = (object) array("email" => $v);
                    else
                        $v = Text::analyze_name($v);
                }
                if (is_object($v) && !get($v, "email") && is_string($k))
                    $v->email = $k;
                if (is_object($v) && get($v, "email")) {
                    $lemail = strtolower($v->email);
                    if ($this->valid_contact($lemail, $old_contacts))
                        $pj->contacts[] = (object) array_merge((array) get($au_by_email, $lemail), (array) $v);
                    else
                        $pj->bad_contacts[] = $v;
                } else
                    $this->error_at("contacts", "Format error [contacts]");
            }
        }

        // Inherit contactness
        if (isset($pj->authors) && $old_pj && isset($old_pj->authors)) {
            foreach ($old_pj->authors as $au)
                if (get($au, "contact") && $au->email
                    && ($aux = get($au_by_email, strtolower($au->email)))
                    && !isset($aux->contact))
                    $aux->contact = true;
        }
        if (isset($pj->authors) && $old_pj && isset($old_pj->contacts)) {
            foreach ($old_pj->contacts as $au)
                if (($aux = get($au_by_email, strtolower($au->email)))
                    && !isset($aux->contact))
                    $aux->contact = true;
        }
    }

    private function check_options($pj) {
        $pj->parsed_options = array();
        foreach ($pj->options as $oid => $oj) {
            $o = $this->conf->paper_opts->get($oid);
            $result = null;
            if ($oj !== null)
                $result = $o->store_json($oj, $this);
            if ($result === null || $result === false)
                $result = [];
            if (!is_array($result))
                $result = [[$result]];
            else if (count($result) == 2 && !is_int($result[1]))
                $result = [$result];
            $pj->parsed_options[$o->id] = $result;
        }
        ksort($pj->parsed_options);
    }

    private function check_invariants($pj, $old_pj) {
        // Errors don't prevent saving
        if (get($pj, "title") === ""
            || (get($pj, "title") === null && (!$old_pj || !$old_pj->title)))
            $this->error_at("title", $this->_("Each submission must have a title."));
        if (get($pj, "abstract") === ""
            || (get($pj, "abstract") === null && (!$old_pj || !get($old_pj, "abstract")))) {
            if (!$this->conf->opt("noAbstract"))
                $this->error_at("abstract", $this->_("Each submission must have an abstract."));
        }
        if ((is_array(get($pj, "authors")) && empty($pj->authors))
            || (get($pj, "authors") === null && (!$old_pj || empty($old_pj->authors))))
            $this->error_at("authors", $this->_("Each submission must have at least one author."));
        $max_authors = $this->conf->opt("maxAuthors");
        if ($max_authors > 0 && is_array(get($pj, "authors")) && count($pj->authors) > $max_authors)
            $this->error_at("authors", $this->_("Each submission can have at most %d authors.", $max_authors));
        if (!empty($pj->bad_authors))
            $this->error_at("authors", $this->_("Some authors ignored."));
        foreach ($pj->bad_email_authors as $k => $aux) {
            $this->error_at("authors", null);
            $this->error_at("auemail" . ($k + 1), $this->_("“%s” is not a valid email address.", htmlspecialchars($aux->email)));
        }
        $ncontacts = 0;
        foreach ($this->conflicts_array($pj, $old_pj) as $c)
            if ($c >= CONFLICT_CONTACTAUTHOR)
                ++$ncontacts;
        if (!$ncontacts && $old_pj) {
            $noldcontacts = 0;
            foreach (self::contacts_array($old_pj) as $c) {
                if (isset($c->contact) && $c->contact)
                    ++$noldcontacts;
            }
            if ($noldcontacts)
                $this->error_at("contacts", $this->_("Each submission must have at least one contact."));
        }
        foreach ($pj->bad_contacts as $reg)
            if (!isset($reg->email))
                $this->error_at("contacts", $this->_("Contact %s has no associated email.", Text::user_html($reg)));
            else
                $this->error_at("contacts", $this->_("Contact email %s is invalid.", htmlspecialchars($reg->email)));
        if (get($pj, "options"))
            $this->check_options($pj);
        if (!empty($pj->bad_topics))
            $this->warning_at("topics", $this->_("Unknown topics ignored (%2\$s).", count($pj->bad_topics), htmlspecialchars(join("; ", $pj->bad_topics))));
        if (!empty($pj->bad_options))
            $this->warning_at("options", $this->_("Unknown options ignored (%2\$s).", count($pj->bad_options), htmlspecialchars(join("; ", array_keys($pj->bad_options)))));
    }

    static private function author_information($pj) {
        $x = "";
        foreach (($pj && get($pj, "authors") ? $pj->authors : array()) as $au) {
            $x .= get($au, "first", get($au, "firstName", "")) . "\t"
                . get($au, "last", get($au, "lastName", "")) . "\t"
                . get($au, "email", "") . "\t"
                . get($au, "affiliation", "") . "\n";
        }
        return $x;
    }

    static function topics_sql($pj, $paperid) {
        $x = array();
        foreach (($pj ? (array) get($pj, "topics") : array()) as $id => $v)
            $x[] = "($id,$paperid)";
        sort($x);
        return join(",", $x);
    }

    private function options_sql($pj, $paperid) {
        $q = [];
        foreach ($pj->parsed_options as $id => $ovs)
            foreach ($ovs as $ov) {
                if (is_int($ov))
                    $q[] = "($paperid,$id,$ov,null)";
                else
                    $q[] = Dbl::format_query($this->conf->dblink, "($paperid,$id,?,?)", $ov[0], get($ov, 1));
            }
        sort($q);
        return join(", ", $q);
    }

    static private function contacts_array($pj) {
        $contacts = array();
        foreach (get($pj, "authors") ? : array() as $au)
            if (get($au, "email") && validate_email($au->email)) {
                $c = clone $au;
                $contacts[strtolower($c->email)] = $c;
            }
        foreach (get($pj, "contacts") ? : array() as $v) {
            $lemail = strtolower($v->email);
            $c = (object) array_merge((array) get($contacts, $lemail), (array) $v);
            $c->contact = true;
            $contacts[$lemail] = $c;
        }
        return $contacts;
    }

    function conflicts_array($pj, $old_pj) {
        $x = array();

        if ($pj && isset($pj->pc_conflicts))
            $c = $pj->pc_conflicts;
        else
            $c = ($old_pj ? get($old_pj, "pc_conflicts") : null) ? : array();
        foreach ((array) $c as $email => $type)
            $x[strtolower($email)] = $type;

        if ($pj && isset($pj->authors))
            $c = $pj->authors;
        else
            $c = $old_pj ? $old_pj->authors : array();
        foreach ($c as $au)
            if (get($au, "email")) {
                $lemail = strtolower($au->email);
                $x[$lemail] = get($au, "contact") ? CONFLICT_CONTACTAUTHOR : CONFLICT_AUTHOR;
            }

        if ($pj && isset($pj->contacts))
            $c = $pj->contacts;
        else
            $c = $old_pj ? (get($old_pj, "contacts") ? : []) : [];
        foreach ($c as $v) {
            $lemail = strtolower($v->email);
            $x[$lemail] = max((int) get($x, $lemail), CONFLICT_CONTACTAUTHOR);
        }

        if ($old_pj && get($old_pj, "pc_conflicts")) {
            $can_administer = !$this->contact
                || $this->contact->can_administer($this->prow, $this->forceShow);
            foreach ($old_pj->pc_conflicts as $email => $type)
                if ($type == CONFLICT_CHAIRMARK) {
                    $lemail = strtolower($email);
                    if (get_i($x, $lemail) < CONFLICT_CHAIRMARK
                        && !$can_administer)
                        $x[$lemail] = CONFLICT_CHAIRMARK;
                }
        }

        ksort($x);
        return $x;
    }

    private function addf($f, $v) {
        $this->qf[] = "$f=?";
        $this->qv[] = $v;
    }

    function save_paper_json($pj) {
        global $Now;
        assert(!$this->hide_docids);
        assert(is_object($pj));

        $paperid = get($pj, "pid", get($pj, "id", null));
        if ($paperid !== null && is_int($paperid) && $paperid <= 0)
            $paperid = null;
        if ($paperid !== null && !is_int($paperid)) {
            $key = isset($pj->pid) ? "pid" : "id";
            $this->error_at($key, "Format error [$key]");
            return false;
        }

        if (get($pj, "error") || get($pj, "error_html")) {
            $this->error_at("error", $this->_("Refusing to save submission with error"));
            return false;
        }

        $this->prow = $old_pj = null;
        $this->paperId = $paperid ? : -1;
        if ($paperid)
            $this->prow = $this->conf->paperRow(["paperId" => $paperid, "topics" => true, "options" => true], $this->contact);
        if ($this->prow)
            $old_pj = $this->paper_json($this->prow, ["forceShow" => true]);
        if ($pj && $old_pj && $paperid != $old_pj->pid) {
            $this->error_at("pid", $this->_("Saving submission with different ID"));
            return false;
        }

        $this->normalize($pj, $old_pj, false);
        if ($old_pj)
            $this->normalize($old_pj, null, true);
        if ($this->has_error())
            return false;
        $this->check_invariants($pj, $old_pj);

        // store documents (options already stored)
        if (isset($pj->submission) && $pj->submission)
            $pj->submission = $this->upload_document($pj->submission, $this->conf->paper_opts->get(DTYPE_SUBMISSION));
        if (isset($pj->final) && $pj->final)
            $pj->final = $this->upload_document($pj->final, $this->conf->paper_opts->get(DTYPE_FINAL));

        // create contacts
        foreach (self::contacts_array($pj) as $c) {
            $c->only_if_contactdb = !get($c, "contact");
            $c->disabled = !!$this->disable_users;
            if (!Contact::create($this->conf, $c, !$this->no_email)
                && get($c, "contact"))
                $this->error_at("contacts", $this->_("Could not create an account for contact %s.", Text::user_html($c)));
        }

        // catch errors
        if ($this->has_error())
            return false;

        // update Paper table
        $this->qf = $this->qv = [];
        foreach (array("title", "abstract", "collaborators") as $k) {
            $v = convert_to_utf8((string) get($pj, $k));
            if (!$old_pj || (isset($pj->$k) && $v !== (string) get($old_pj, $k)))
                $this->addf($k, $v);
        }

        if (!$old_pj || isset($pj->authors)) {
            $autext = convert_to_utf8(self::author_information($pj));
            $old_autext = self::author_information($old_pj);
            if ($autext !== $old_autext || !$old_pj)
                $this->addf("authorInformation", $autext);
        }

        if ($this->conf->submission_blindness() == Conf::BLIND_OPTIONAL
            && (!$old_pj || (isset($pj->nonblind) && !$pj->nonblind != !$old_pj->nonblind)))
            $this->addf("blind", get($pj, "nonblind") ? 0 : 1);

        $newPaperStorageId = null;
        if (!$old_pj || isset($pj->submission)) {
            $new_id = get($pj, "submission") ? $pj->submission->docid : 1;
            $old_id = $old_pj && get($old_pj, "submission") ? $old_pj->submission->docid : 1;
            if (!$old_pj || $new_id != $old_id) {
                $this->addf("paperStorageId", $new_id);
                $newPaperStorageId = $new_id;
            }
        }

        $newFinalPaperStorageId = null;
        if (!$old_pj || isset($pj->final)) {
            $new_id = get($pj, "final") ? $pj->final->docid : 0;
            $old_id = $old_pj && get($old_pj, "final") ? $old_pj->final->docid : 0;
            if (!$old_pj || $new_id != $old_id) {
                $this->addf("finalPaperStorageId", $new_id);
                $newFinalPaperStorageId = $new_id;
            }
        }

        $pj_withdrawn = get($pj, "withdrawn");
        $pj_submitted = get($pj, "submitted");
        $pj_draft = get($pj, "draft");
        if ($pj_withdrawn === null && $pj_submitted === null && $pj_draft === null) {
            $pj_status = get($pj, "status");
            if ($pj_status === "submitted")
                $pj_submitted = true;
            else if ($pj_status === "withdrawn")
                $pj_withdrawn = true;
            else if ($pj_status === "draft")
                $pj_draft = true;
        }

        $submitted = false;
        if ($pj_withdrawn !== null || $pj_submitted !== null || $pj_draft !== null) {
            if ($pj_submitted !== null)
                $submitted = $pj_submitted;
            else if ($pj_draft !== null)
                $submitted = !$pj_draft;
            else if ($old_pj)
                $submitted = get($old_pj, "submitted_at") > 0;
            $submitted_at = get($pj, "submitted_at", get($old_pj, "submitted_at", 0));
            if ($pj_withdrawn) {
                if ($submitted && $submitted_at <= 0)
                    $submitted_at = -100;
                else if (!$submitted)
                    $submitted_at = 0;
                else
                    $submitted_at = -$submitted_at;
                if (!$old_pj || !get($old_pj, "withdrawn")) {
                    $this->addf("timeWithdrawn", get($pj, "withdrawn_at") ? : $Now);
                    $this->addf("timeSubmitted", $submitted_at);
                } else if ((get($old_pj, "submitted_at") > 0) !== $submitted)
                    $this->addf("timeSubmitted", $submitted_at);
            } else if ($submitted) {
                if (!$old_pj || !get($old_pj, "submitted")) {
                    if ($submitted_at <= 0 || $submitted_at === self::SUBMITTED_AT_FOR_WITHDRAWN)
                        $submitted_at = $Now;
                    $this->addf("timeSubmitted", $submitted_at);
                }
                if ($old_pj && get($old_pj, "withdrawn"))
                    $this->addf("timeWithdrawn", 0);
            } else if ($old_pj && (get($old_pj, "withdrawn") || get($old_pj, "submitted"))) {
                $this->addf("timeSubmitted", 0);
                $this->addf("timeWithdrawn", 0);
            }
        }

        if (isset($pj->final_submitted)) {
            if ($pj->final_submitted)
                $time = get($pj, "final_submitted_at") ? : $Now;
            else
                $time = 0;
            if (!$old_pj || get($old_pj, "final_submitted_at") != $time)
                $this->addf("timeFinalSubmitted", $time);
        }

        if (!empty($this->qf)) {
            if ($this->conf->submission_blindness() == Conf::BLIND_NEVER)
                $this->addf("blind", 0);
            else if ($this->conf->submission_blindness() != Conf::BLIND_OPTIONAL)
                $this->addf("blind", 1);

            if ($old_pj && isset($old_pj->final))
                $old_joindoc = $old_pj->final;
            else if ($old_pj && isset($old_pj->submission))
                $old_joindoc = $old_pj->submission;
            else
                $old_joindoc = null;
            if ($newFinalPaperStorageId > 0)
                $new_joindoc = $pj->final;
            else if ($newFinalPaperStorageId === null && $old_pj && isset($old_pj->final))
                $new_joindoc = $old_pj->final;
            else if ($newPaperStorageId > 1)
                $new_joindoc = $pj->submission;
            else if ($newPaperStorageId === null && $old_pj && isset($old_pj->submission))
                $new_joindoc = $old_pj->submission;
            else
                $new_joindoc = null;
            if ($new_joindoc
                && (!$old_joindoc || $old_joindoc->docid != $new_joindoc->docid)) {
                $this->addf("size", $new_joindoc->size);
                $this->addf("mimetype", $new_joindoc->mimetype);
                $this->addf("sha1", Filer::hash_as_binary($new_joindoc->hash));
                $this->addf("timestamp", $new_joindoc->timestamp);
                if ($this->conf->sversion >= 145)
                    $this->addf("pdfFormatStatus", 0);
            } else if (!$paperid || ($new_joindoc && !$old_joindoc)) {
                $this->addf("size", 0);
                $this->addf("mimetype", "");
                $this->addf("sha1", "");
                $this->addf("timestamp", 0);
                if ($this->conf->sversion >= 145)
                    $this->addf("pdfFormatStatus", 0);
            }

            $this->addf("timeModified", $Now);

            if ($paperid) {
                $this->qv[] = $paperid;
                $result = $this->conf->qe_apply("update Paper set " . join(", ", $this->qf) . " where paperId=?", $this->qv);
                if ($result
                    && $result->affected_rows === 0
                    && edb_nrows($this->conf->qe("select paperId from Paper where paperId=?", $paperid)) === 0)
                    $result = $this->conf->qe_apply("insert into Paper set " . join(", ", $this->qf) . ", paperId=?", $this->qv);
            } else {
                $result = $this->conf->qe_apply("insert into Paper set " . join(", ", $this->qf), $this->qv);
                if (!$result
                    || !($paperid = $pj->pid = $result->insert_id))
                    return $this->error_at(false, $this->_("Could not create paper."));
                if (!empty($this->uploaded_documents))
                    $this->conf->qe("update PaperStorage set paperId=? where paperStorageId?a", $paperid, $this->uploaded_documents);
            }

            // maybe update `papersub` settings
            $is_submitted = !$pj_withdrawn && $submitted;
            $was_submitted = $old_pj && !get($old_pj, "withdrawn") && get($old_pj, "submitted");
            if ($is_submitted != $was_submitted)
                $this->conf->update_papersub_setting($is_submitted ? 1 : -1);
        }

        // update PaperTopics
        if (get($pj, "topics")) {
            $topics = self::topics_sql($pj, $paperid);
            $old_topics = self::topics_sql($old_pj, $paperid);
            if ($topics !== $old_topics) {
                $this->conf->qe_raw("delete from PaperTopic where paperId=$paperid");
                if ($topics)
                    $this->conf->qe_raw("insert into PaperTopic (topicId, paperId) values $topics");
            }
        }

        // update PaperOption
        if (get($pj, "options")) {
            $options = convert_to_utf8($this->options_sql($pj, $paperid));
            if ($old_pj && isset($old_pj->options)) {
                $this->check_options($old_pj);
                $old_options = $this->options_sql($old_pj, $paperid);
            } else
                $old_options = "";
            if ($options !== $old_options) {
                $this->conf->qe("delete from PaperOption where paperId=? and optionId?a", $paperid, array_keys($pj->parsed_options));
                if ($options)
                    $this->conf->qe_raw("insert into PaperOption (paperId,optionId,value,data) values $options");
            }
        }

        // update PaperConflict
        $conflict = $this->conflicts_array($pj, $old_pj);
        $old_conflict = $this->conflicts_array($old_pj, null);
        if (join(",", array_keys($conflict)) !== join(",", array_keys($old_conflict))
            || join(",", array_values($conflict)) !== join(",", array_values($old_conflict))) {
            $ins = array();
            if (!empty($conflict)) {
                $result = $this->conf->qe("select contactId, email from ContactInfo where email?a", array_keys($conflict));
                while (($row = edb_row($result)))
                    $ins[] = "($paperid,$row[0]," . $conflict[strtolower($row[1])] . ")";
            }
            $this->conf->qe("delete from PaperConflict where paperId=?", $paperid);
            if (!empty($ins))
                $this->conf->qe_raw("insert into PaperConflict (paperId,contactId,conflictType) values " . join(",", $ins));
        }

        // update autosearch
        $this->conf->update_autosearch_tags($paperid);

        return $paperid;
    }
}
