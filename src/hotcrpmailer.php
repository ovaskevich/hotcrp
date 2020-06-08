<?php
// hotcrpmailer.php -- HotCRP mail template manager
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

class HotCRPMailPreparation extends MailPreparation {
    public $paperId = -1;
    public $author_recipient = false;
    public $paper_expansions = 0;
    public $combination_type = 0;
    public $fake = false;
    public $censored_preparation; // used in mail tool

    function __construct($conf, $recipient) {
        parent::__construct($conf, $recipient);
    }
    function can_merge($p) {
        return parent::can_merge($p)
            && $p instanceof HotCRPMailPreparation
            && $this->combination_type == $p->combination_type
            && (($this->combination_type == 2
                 && !$this->paper_expansions
                 && !$p->paper_expansions)
                || ($this->author_recipient === $p->author_recipient
                    && $this->combination_type != 0
                    && $this->paperId === $p->paperId)
                || ($this->author_recipient === $p->author_recipient
                    && $this->to === $p->to));
    }
}

class HotCRPMailer extends Mailer {
    /** @var array<string,Contact|Author> */
    protected $contacts = [];

    /** @var ?PaperInfo */
    protected $row;
    /** @var ?ReviewInfo */
    protected $rrow;
    protected $rrow_unsubmitted = false;
    /** @var ?CommentInfo */
    protected $comment_row;
    protected $newrev_since = false;
    protected $no_send = false;
    public $combination_type = false;

    protected $_tagger = null;
    protected $_statistics = null;
    protected $_tagless = array();


    /** @param ?Contact $recipient */
    function __construct(Conf $conf, $recipient = null, $rest = []) {
        parent::__construct($conf);
        $this->reset($recipient, $rest);
        if (isset($rest["combination_type"])) {
            $this->combination_type = $rest["combination_type"];
        }
    }

    static private function make_reviewer_contact($x) {
        return Author::make_keyed([
            "email" => $x->reviewEmail,
            "firstName" => $x->reviewFirstName,
            "lastName" => $x->reviewLastName
        ]);
    }

    /** @param ?Contact $recipient */
    function reset($recipient = null, $rest = []) {
        global $Me;
        parent::reset($recipient, $rest);
        if ($recipient) {
            assert($recipient instanceof Contact);
            assert(!($recipient->overrides() & Contact::OVERRIDE_CONFLICT));
        }
        foreach (["requester", "reviewer", "other"] as $k) {
            $this->contacts[$k] = $rest[$k . "_contact"] ?? null;
        }
        $this->row = $rest["prow"] ?? null;
        assert(!$this->row || $this->row->paperId > 0);
        foreach (["rrow", "comment_row", "newrev_since"] as $k) {
            $this->$k = $rest[$k] ?? null;
        }
        if ($rest["rrow_unsubmitted"] ?? false) {
            $this->rrow_unsubmitted = true;
        }
        if ($rest["no_send"] ?? false) {
            $this->no_send = true;
        }
        // Infer reviewer contact from rrow/comment_row
        if (!$this->contacts["reviewer"]) {
            if ($this->rrow && ($this->rrow->reviewEmail ?? null)) {
                $this->contacts["reviewer"] = self::make_reviewer_contact($this->rrow);
            } else if ($this->comment_row && ($this->comment_row->reviewEmail ?? null)) {
                $this->contacts["reviewer"] = self::make_reviewer_contact($this->comment_row);
            }
        }
        // Do not put passwords in email that is cc'd elsewhere
        if ((!$Me || !$Me->privChair || $this->conf->opt("chairHidePasswords"))
            && (($rest["cc"] ?? null) || ($rest["bcc"] ?? null))
            && (!$this->censor || $this->censor === self::CENSOR_DISPLAY)) {
            $this->censor = self::CENSOR_ALL;
        }
    }


    // expansion helpers
    private function _expand_reviewer($type, $isbool) {
        if (!($c = $this->contacts["reviewer"])) {
            return false;
        }
        if ($this->row
            && $this->rrow
            && $this->conf->is_review_blind($this->rrow)
            && !$this->recipient->privChair
            && !$this->recipient->can_view_review_identity($this->row, $this->rrow)) {
            if ($isbool) {
                return false;
            } else if ($this->expansionType == self::EXPAND_EMAIL) {
                return "<hidden>";
            } else {
                return "Hidden for blind review";
            }
        }
        return $this->expand_user($c, $type);
    }

    /** @return Tagger */
    private function tagger()  {
        if (!$this->_tagger) {
            $this->_tagger = new Tagger($this->recipient);
        }
        return $this->_tagger;
    }

    private function get_reviews() {
        // save old au_seerev setting, and reset it so authors can see them.
        if (!($au_seerev = $this->conf->au_seerev)) {
            $this->conf->au_seerev = Conf::AUSEEREV_YES;
        }
        assert(!($this->recipient->overrides() & contact::OVERRIDE_CONFLICT));

        if ($this->rrow) {
            $rrows = [$this->rrow];
        } else {
            $this->row->ensure_full_reviews();
            $rrows = $this->row->reviews_by_display($this->recipient);
        }

        $text = "";
        $rf = $this->conf->review_form();
        foreach ($rrows as $rrow) {
            if (($rrow->reviewSubmitted
                 || ($rrow == $this->rrow && $this->rrow_unsubmitted))
                && $this->recipient->can_view_review($this->row, $rrow)) {
                if ($text !== "") {
                    $text .= "\n\n*" . str_repeat(" *", 37) . "\n\n\n";
                }
                $text .= $rf->pretty_text($this->row, $rrow, $this->recipient, $this->no_send, true);
            }
        }

        $this->conf->au_seerev = $au_seerev;
        if ($text === ""
            && $au_seerev == Conf::AUSEEREV_UNLESSINCOMPLETE
            && !empty($rrows)) {
            $text = "[Reviews are hidden since you have incomplete reviews of your own.]\n";
        }
        return $text;
    }

    private function get_comments($tag) {
        // save old au_seerev setting, and reset it so authors can see them.
        if (!($au_seerev = $this->conf->au_seerev))
            $this->conf->au_seerev = Conf::AUSEEREV_YES;
        assert(!($this->recipient->overrides() & Contact::OVERRIDE_CONFLICT));

        if ($this->comment_row) {
            $crows = [$this->comment_row];
        } else {
            $crows = $this->row->all_comments();
        }

        $crows = array_filter($crows, function ($crow) use ($tag) {
            return (!$tag || $crow->has_tag($tag))
                && $this->recipient->can_view_comment($this->row, $crow);
        });

        $text = "";
        if (count($crows) > 1) {
            $text .= "Comments\n" . str_repeat("=", 75) . "\n";
        }
        foreach ($crows as $crow) {
            if ($text !== "") {
                $text .= "\n";
            }
            $text .= $crow->unparse_text($this->recipient, true);
        }

        $this->conf->au_seerev = $au_seerev;
        return $text;
    }

    private function get_new_assignments($contact) {
        $since = "";
        if ($this->newrev_since) {
            $since = " and r.timeRequested>=$this->newrev_since";
        }
        $result = $this->conf->qe("select r.paperId, p.title
                from PaperReview r join Paper p using (paperId)
                where r.contactId=" . $contact->contactId . "
                and r.timeRequested>r.timeRequestNotified$since
                and r.reviewSubmitted is null
                and r.reviewNeedsSubmit!=0
                and p.timeSubmitted>0
                order by r.paperId");
        $text = "";
        while (($row = $result->fetch_row())) {
            $text .= ($text ? "\n#" : "#") . $row[0] . " " . $row[1];
        }
        Dbl::free($result);
        return $text;
    }


    function infer_user_name($r, $contact) {
        // If user hasn't entered a name, try to infer it from author records
        if ($this->row && $this->row->paperId > 0) {
            $e1 = $contact->email ?? "";
            $e2 = $contact->preferredEmail ?? "";
            foreach ($this->row->author_list() as $au) {
                if (($au->firstName !== "" || $au->lastName !== "")
                    && $au->email !== ""
                    && (strcasecmp($au->email, $e1) === 0
                        || strcasecmp($au->email, $e2) === 0)) {
                    $r->firstName = $au->firstName;
                    $r->lastName = $au->lastName;
                    return;
                }
            }
        }
    }

    function kw_deadline($args, $isbool, $uf) {
        if ($uf->is_review && $args) {
            $args .= "rev_soft";
        } else if ($uf->is_review) {
            if (!$this->row
                || !($rt = $this->row->review_type($this->recipient))) {
                $p = $this->conf->setting("pcrev_soft");
                $e = $this->conf->setting("extrev_soft");
                if ($p == $e) {
                    $rt = REVIEW_EXTERNAL;
                } else if ($isbool && ($p > 0) == ($e > 0)) {
                    return $p > 0;
                } else {
                    return null;
                }
            }
            $args = ($rt >= REVIEW_PC ? "pc" : "ext") . "rev_soft";
        }
        if ($args && $isbool) {
            return $this->conf->setting($args) > 0;
        } else if ($args) {
            return $this->conf->printableTimeSetting($args);
        } else {
            return null;
        }
    }
    function kw_statistic($args, $isbool, $uf) {
        if ($this->_statistics === null) {
            $this->_statistics = $this->conf->count_submitted_accepted();
        }
        return $this->_statistics[$uf->statindex];
    }
    function kw_contactdbdescription() {
        return $this->conf->opt("contactdb_description") ? : "HotCRP";
    }
    function kw_reviewercontact($args, $isbool, $uf) {
        if ($uf->match_data[1] === "REVIEWER") {
            if (($x = $this->_expand_reviewer($uf->match_data[2], $isbool)) !== false) {
                return $x;
            }
        } else if (($u = $this->contacts[strtolower($uf->match_data[1])])) {
            return $this->expand_user($u, $uf->match_data[2]);
        }
        return $isbool ? false : null;
    }

    function kw_newassignments() {
        return $this->get_new_assignments($this->recipient);
    }
    function kw_haspaper() {
        if ($this->row && $this->row->paperId > 0) {
            if ($this->preparation
                && $this->preparation instanceof HotCRPMailPreparation) {
                ++$this->preparation->paper_expansions;
            }
            return true;
        } else {
            return false;
        }
    }
    function kw_hasreview() {
        return !!$this->rrow;
    }

    function kw_title() {
        return $this->row->title;
    }
    function kw_titlehint() {
        if (($tw = UnicodeHelper::utf8_abbreviate($this->row->title, 40))) {
            return "\"$tw\"";
        } else {
            return "";
        }
    }
    function kw_abstract() {
        return $this->row->abstract_text();
    }
    function kw_pid() {
        return $this->row->paperId;
    }
    function kw_authors($args, $isbool) {
        if (!$this->recipient->is_root_user()
            && !$this->row->has_author($this->recipient)
            && !$this->recipient->can_view_authors($this->row)) {
            return $isbool ? false : "Hidden for blind review";
        }
        return rtrim($this->row->pretty_text_author_list());
    }
    function kw_authorviewcapability($args, $isbool) {
        $this->sensitive = true;
        if ($this->conf->opt("disableCapabilities")
            || $this->censor === self::CENSOR_ALL) {
            return "";
        }
        if ($this->row
            && isset($this->row->capVersion)
            && $this->recipient->act_author_view($this->row)) {
            if (!$this->censor) {
                return "cap=" . AuthorView_Capability::make($this->row);
            } else if ($this->censor === self::CENSOR_DISPLAY) {
                return "cap=HIDDEN";
            }
        }
        return null;
    }
    function kw_decision($args, $isbool) {
        if (!$this->row->outcome && $isbool) {
            return false;
        } else {
            return $this->conf->decision_name($this->row->outcome);
        }
    }
    function kw_tagvalue($args, $isbool, $uf) {
        $tag = isset($uf->match_data) ? $uf->match_data[1] : $args;
        $tag = $this->tagger()->check($tag, Tagger::NOVALUE | Tagger::NOPRIVATE);
        if (!$tag) {
            return null;
        }
        $value = $this->row->tag_value($tag);
        if ($isbool) {
            return $value !== false;
        } else if ($value !== false) {
            return (string) $value;
        } else {
            $this->_tagless[$this->row->paperId] = true;
            return "(none)";
        }
    }
    function kw_paperpc($args, $isbool, $uf) {
        $k = $uf->pctype . "ContactId";
        $cid = $this->row->$k;
        if ($cid > 0 && ($u = $this->conf->cached_user_by_id($cid))) {
            return $this->expand_user($u, $uf->userx);
        } else if ($isbool)  {
            return false;
        } else if ($this->expansionType == self::EXPAND_EMAIL
                   || $uf->userx === "EMAIL") {
            return "<none>";
        } else {
            return "(no $uf->pctype assigned)";
        }
    }
    function kw_reviewname($args) {
        $s = $args === "SUBJECT";
        if ($this->rrow && $this->rrow->reviewOrdinal) {
            return ($s ? "review #" : "Review #") . $this->row->paperId . unparseReviewOrdinal($this->rrow->reviewOrdinal);
        } else {
            return ($s ? "review" : "A review");
        }
    }
    function kw_reviewid($args, $isbool) {
        if ($isbool && !$this->rrow) {
            return false;
        } else {
            return $this->rrow ? $this->rrow->reviewId : "";
        }
    }
    function kw_reviewacceptor() {
        if ($this->rrow && ($acc = $this->rrow->acceptor()->text)) {
            if (ctype_digit($acc[0])) { // XXX backward compat
                return $this->rrow->reviewId . "ra" . $acc;
            } else {
                return "ra" . $this->rrow->reviewId . $acc;
            }
        } else {
            return false;
        }
    }
    function kw_reviews() {
        return $this->get_reviews();
    }
    function kw_comments($args, $isbool) {
        $tag = null;
        if ($args === ""
            || ($tag = $this->tagger()->check($args, Tagger::NOVALUE))) {
            return $this->get_comments($tag);
        } else {
            return null;
        }
    }

    function kw_ims_expand_authors($args, $isbool) {
        preg_match('/\A\s*(.*?)\s*(?:|,\s*(\d+)\s*)\z/', $args, $m);
        if ($m[1] === "Authors") {
            $nau = 0;
            if ($this->row
                && ($this->recipient->is_root_user()
                    || $this->row->has_author($this->recipient)
                    || $this->recipient->can_view_authors($this->row))) {
                $nau = count($this->row->author_list());
            }
            $t = $this->conf->_c("mail", $m[1], $nau);
        } else {
            $t = $this->conf->_c("mail", $m[1]);
        }
        if (($n = (int) $m[2]) && strlen($t) < $n) {
            $t = str_repeat(" ", $n - strlen($t)) . $t;
        }
        return $t;
    }


    protected function unexpanded_warning_html() {
        $h = parent::unexpanded_warning_html();
        foreach ($this->_unexpanded as $t => $x) {
            if (preg_match('/\A%(?:NUMBER|TITLE|PAPER|AUTHOR|REVIEW|COMMENT)/', $t))
                $h .= " Paper-specific keywords like <code>" . htmlspecialchars($t) . "</code> weren’t recognized because this set of recipients is not linked to a paper collection.";
        }
        if (isset($this->_unexpanded["%AUTHORVIEWCAPABILITY%"])) {
            $h .= " Author view capabilities weren’t recognized because this mail isn’t meant for paper authors.";
        }
        return $h;
    }

    function warning_count() {
        return count($this->_unexpanded) + count($this->_tagless);
    }

    function warning_htmls() {
        $e = array();
        if (count($this->_unexpanded)) {
            $e[] = $this->unexpanded_warning_html();
        }
        if (count($this->_tagless)) {
            $a = array_keys($this->_tagless);
            sort($a, SORT_NUMERIC);
            $e[] = pluralx(count($this->_tagless), "Paper") . " " . commajoin($a) . " did not have some requested tag values.";
        }
        return $e;
    }

    /** @return HotCRPMailPreparation */
    function prepare($template, $rest = []) {
        assert($this->recipient && $this->recipient->email);
        $prep = new HotCRPMailPreparation($this->conf, $this->recipient);
        if ($this->row && ($this->row->paperId ?? 0) > 0) {
            $prep->paperId = $this->row->paperId;
            $prep->author_recipient = $this->row->has_author($this->recipient);
        }
        $prep->combination_type = $this->combination_type;
        $this->populate_preparation($prep, $template, $rest);
        return $prep;
    }


    /** @param Contact $recipient
     * @param PaperInfo $prow
     * @param ?ReviewInfo $rrow
     * @return bool */
    static function check_can_view_review($recipient, $prow, $rrow) {
        assert(!($recipient->overrides() & Contact::OVERRIDE_CONFLICT));
        return $recipient->can_view_review($prow, $rrow);
    }

    /** @param Contact $recipient */
    static function prepare_to($recipient, $template, $rest = []) {
        $answer = null;
        if (!$recipient->is_disabled()) {
            $old_overrides = $recipient->remove_overrides(Contact::OVERRIDE_CONFLICT);
            $mailer = new HotCRPMailer($recipient->conf, $recipient, $rest);
            $checkf = $rest["check_function"] ?? null;
            if (!$checkf
                || call_user_func($checkf, $recipient, $mailer->row, $mailer->rrow)) {
                $answer = $mailer->prepare($template, $rest);
            }
            $recipient->set_overrides($old_overrides);
        }
        return $answer;
    }

    /** @param Contact $recipient */
    static function send_to($recipient, $template, $rest = []) {
        if (($prep = self::prepare_to($recipient, $template, $rest))) {
            $prep->send();
        }
    }

    /** @param PaperInfo $row */
    static function send_contacts($template, $row, $rest = []) {
        global $Me;

        $result = $row->conf->qe("select ContactInfo.contactId,
                firstName, lastName, email, preferredEmail, password,
                roles, disabled, contactTags,
                conflictType, '' myReviewPermissions
                from ContactInfo join PaperConflict using (contactId)
                where paperId=$row->paperId and conflictType>=" . CONFLICT_AUTHOR . "
                group by ContactInfo.contactId");

        // must set the current conflict type in $row for each contact
        $contact_info_map = $row->replace_contact_info_map([]);

        $preps = $contacts = [];
        $rest["prow"] = $row;
        $rest["combination_type"] = 1;
        while (($contact = Contact::fetch($result, $row->conf))) {
            assert(empty($contact->review_tokens()));
            $row->load_my_contact_info($contact, $contact);
            if (($p = self::prepare_to($contact, $template, $rest))) {
                $preps[] = $p;
                $contacts[] = $contact->name_h(NAME_EB);
            }
        }
        self::send_combined_preparations($preps);
        Dbl::free($result);

        $row->replace_contact_info_map($contact_info_map);
        if ($Me->allow_administer($row)
            && !$row->has_author($Me)
            && !empty($contacts)) {
            $endmsg = (isset($rest["infoMsg"]) ? ", " . $rest["infoMsg"] : ".");
            if (isset($rest["infoNames"]) && $Me->allow_administer($row)) {
                $contactsmsg = pluralx($contacts, "contact") . ", " . commajoin($contacts);
            } else {
                $contactsmsg = "contact(s)";
            }
            $row->conf->infoMsg("Sent email to paper #{$row->paperId}’s $contactsmsg$endmsg");
        }
        return !empty($contacts);
    }

    /** @param PaperInfo $row */
    static function send_administrators($template, $row, $rest = []) {
        $preps = array();
        $rest["prow"] = $row;
        $rest["combination_type"] = 1;
        foreach ($row->administrators() as $u) {
            if (($p = self::prepare_to($u, $template, $rest))) {
                $preps[] = $p;
            }
        }
        self::send_combined_preparations($preps);
    }
}
