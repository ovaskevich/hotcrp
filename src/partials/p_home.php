<?php
// src/partials/p_home.php -- HotCRP home page partials
// Copyright (c) 2006-2019 Eddie Kohler; see LICENSE.

class Home_Partial {
    private $_in_reviews;
    private $_merit_field;
    private $_my_rinfo;
    private $_pc_rinfo;
    private $_tokens_done;

    static function signin_requests(Contact $user, Qrequest $qreq) {
        // prepare auto-signin when email & password set
        if (isset($qreq->email) && isset($qreq->password)) {
            $qreq->action = $qreq->get("action", "login");
            $qreq->signin = $qreq->get("signin", "go");
        }
        // clean up request: no signin without email/action
        $signin = $qreq->signin && isset($qreq->email) && isset($qreq->action);
        $signout = $qreq->signout;
        // clean up request: ignore signin to same email
        if ($signin
            && !$user->is_empty()
            && strcasecmp($qreq->email, $user->email) === 0) {
            unset($qreq->signin);
            $signin = false;
        }
        // CSRF protection for signin/signout
        $sid = session_id();
        if (($signin || $signout) && !$qreq->post_ok()) {
            if ($qreq->method() === "POST") {
                $msg = "{$user->conf->dbname}: ignoring unvalidated "
                    . ($signin ? "signin" : "signout")
                    . ", sid=" . ($sid === "" ? ".empty" : $sid)
                    . ", action=" . ($signin ? $qreq->action : "signout");
                if ($qreq->email)
                    $msg .= ", email=" . $qreq->email;
                if ($qreq->password)
                    $msg .= ", password";
                if (isset($_GET["post"]))
                    $msg .= ", post=" . $_GET["post"];
                error_log($msg);
            }
            if ($qreq->method() === "POST" || $qreq->post) {
                ensure_session(0);
                $user->conf->msg(1, "Your session has changed since you last used this tab. Please try again.");
                unset($qreq->signin, $qreq->signout);
                $user->conf->self_redirect($qreq);
                $signin = $signout = false;
            }
        }
        // signout
        if ($signout && $qreq->post_ok()) {
            if (!$user->is_empty() && !$user->conf->opt("httpAuthLogin")) {
                $user->conf->msg("xconfirm", "You have been signed out.");
            }
            $user = LoginHelper::logout($user, true);
        }
        // signin
        if ($user->conf->opt("httpAuthLogin")) {
            LoginHelper::check_http_auth($user, $qreq);
        } else if ($signin) {
            LoginHelper::login_redirect($user->conf, $qreq);
        } else if (($signin || $signout) && $qreq->post) {
            unset($qreq->signin, $qreq->signout);
            $user->conf->self_redirect($qreq);
        } else if (isset($qreq->postlogin)) {
            LoginHelper::check_postlogin($user, $qreq);
        }
        // disabled
        if (!$user->is_empty() && $user->is_disabled()) {
            $user->conf->header("Account disabled", "home", ["action_bar" => false]);
            $user->conf->msg(0, "Your account on this site has been disabled by a site administrator. Please contact them with questions.");
            $user->conf->footer();
            exit;
        }
        return $user;
    }


    static function profile_redirect_request(Contact $user, Qrequest $qreq) {
        if ($user->has_account_here()
            && $user->session("freshlogin") === true) {
            if (self::need_profile_redirect($user)) {
                $user->save_session("freshlogin", "redirect");
                go($user->conf->hoturl("profile", "redirect=1"));
            }
            $user->save_session("freshlogin", null);
        }
    }

    static function need_profile_redirect(Contact $user) {
        if (!$user->firstName && !$user->lastName)
            return true;
        if ($user->conf->opt("noProfileRedirect"))
            return false;
        if (!$user->affiliation)
            return true;
        if ($user->is_pc_member()
            && !$user->has_review()
            && (!$user->collaborators
                || ($user->conf->has_topics() && !$user->topic_interest_map())))
            return true;
        return false;
    }


    function render_head(Contact $user, Qrequest $qreq) {
        if ($user->is_empty() || isset($qreq->signin))
            $user->conf->header("Sign in", "home");
        else
            $user->conf->header("Home", "home");
        echo '<noscript><div class="msg msg-error"><strong>This site requires JavaScript.</strong> Your browser does not support JavaScript.<br><a href="https://github.com/kohler/hotcrp/">Report bad compatibility problems</a></div></noscript>', "\n";
        if ($user->privChair)
            echo '<div id="msg-clock-drift"></div>';
    }

    function render_sidebar(Contact $user, Qrequest $qreq, $gx) {
        $conf = $user->conf;
        echo '<div class="homeside">';
        $gx->start_render();
        foreach ($gx->members("home/sidebar/*") as $gj)
            $gx->render($gj, [$user, $qreq, $gx, $gj]);
        $gx->end_render();
        echo "</div>\n";
    }

    function render_admin_sidebar(Contact $user, Qrequest $qreq, $gx) {
        echo '<div class="homeinside"><h4>Administration</h4><ul>';
        $gx->start_render();
        foreach ($gx->members("home/sidebar/admin/*") as $gj)
            $gx->render($gj, [$user, $qreq, $gx, $gj]);
        $gx->end_render();
        echo '</ul></div>';
    }
    function render_admin_settings(Contact $user) {
        echo '<li>', Ht::link("Settings", $user->conf->hoturl("settings")), '</li>';
    }
    function render_admin_users(Contact $user) {
        echo '<li>', Ht::link("Users", $user->conf->hoturl("users", "t=all")), '</li>';
    }
    function render_admin_assignments(Contact $user) {
        echo '<li>', Ht::link("Assignments", $user->conf->hoturl("autoassign")), '</li>';
    }
    function render_admin_mail(Contact $user) {
        echo '<li>', Ht::link("Mail", $user->conf->hoturl("mail")), '</li>';
    }
    function render_admin_log(Contact $user) {
        echo '<li>', Ht::link("Action log", $user->conf->hoturl("log")), '</li>';
    }

    function render_info_sidebar(Contact $user, Qrequest $qreq, $gx) {
        ob_start();
        $gx->start_render();
        foreach ($gx->members("home/sidebar/info/*") as $gj)
            $gx->render($gj, [$user, $qreq, $gx, $gj]);
        $gx->end_render();
        if (($t = ob_get_clean()))
            echo '<div class="homeinside"><h4>',
                $user->conf->_c("home", "Conference information"),
                '</h4><ul>', $t, '</ul></div>';
    }
    function render_info_deadline(Contact $user) {
        if ($user->has_reportable_deadline())
            echo '<li>', Ht::link("Deadlines", $user->conf->hoturl("deadlines")), '</li>';
    }
    function render_info_pc(Contact $user) {
        if ($user->can_view_pc())
            echo '<li>', Ht::link("Program committee", $user->conf->hoturl("users", "t=pc")), '</li>';
    }
    function render_info_site(Contact $user) {
        if (($site = $user->conf->opt("conferenceSite"))
            && $site !== $user->conf->opt("paperSite"))
            echo '<li>', Ht::link("Conference site", $site), '</li>';
    }
    function render_info_accepted(Contact $user) {
        if ($user->conf->can_all_author_view_decision()) {
            list($n, $nyes) = $user->conf->count_submitted_accepted();
            echo '<li>', $user->conf->_("%d papers accepted out of %d submitted.", $nyes, $n), '</li>';
        }
    }

    function render_message(Contact $user) {
        if (($t = $user->conf->_i("home", false)))
            $user->conf->msg(0, $t);
    }

    function render_welcome(Contact $user) {
        echo '<div class="homegrp">Welcome to the ', htmlspecialchars($user->conf->full_name()), " submissions site.";
        if (($site = $user->conf->opt("conferenceSite"))
            && $site !== $user->conf->opt("paperSite"))
            echo " For general conference information, see ", Ht::link(htmlspecialchars($site), htmlspecialchars($site)), ".";
        echo '</div>';
    }

    function render_signin(Contact $user, Qrequest $qreq) {
        global $Now;
        if ($user->has_email() && !isset($qreq->signin))
            return;

        $conf = $user->conf;
        echo '<div class="homegrp">', $conf->_("Sign in to submit or review papers."), '</div>';
        echo '<div class="homegrp foldo" id="homeacct">',
            Ht::form($conf->hoturl("index", ["signin" => 1, "action" => "login", "post" => post_value(true)]), ["class" => "ui-submit js-signin"]),
            '<div class="f-contain">';
        if ($conf->opt("contactdb_dsn")
            && ($x = $conf->opt("contactdb_loginFormHeading"))) {
            echo $x;
        }
        $password_reset = $user->session("password_reset");
        $password_status = Ht::problem_status_at("password");
        $focus_email = !$password_status
            && (!$qreq->email || Ht::problem_status_at("email"));
        $email_value = $qreq->get("email", $password_reset ? $password_reset->email : "");
        $password_value = (string) $qreq->password === "" || $password_status !== 1 ? "" : $qreq->password;
        if ($password_reset && $password_reset->time < $Now - 900) {
            $password_reset = null;
            $user->save_session("password_reset", null);
        }
        $is_external_login = $conf->external_login();
        echo '<div class="', Ht::control_class("email", "f-i"), '">',
            Ht::label($is_external_login ? "Username" : "Email", "signin_email"),
            Ht::entry("email", $email_value, [
                "size" => 36, "id" => "signin_email", "class" => "fullw",
                "autocomplete" => "username", "tabindex" => 1,
                "type" => $is_external_login || str_ends_with($email_value, "@_.com") ? "text" : "email",
                "autofocus" => $focus_email
            ]),
            Ht::render_messages_at("email"),
            '</div><div class="', Ht::control_class("password", "f-i fx"), '">';
        if (!$is_external_login)
            echo '<div class="float-right"><a href="" class="n x small ui js-forgot-password">Forgot your password?</a></div>';
        echo Ht::label("Password", "signin_password"),
            Ht::password("password", $password_value, [
                "size" => 36, "id" => "signin_password", "class" => "fullw",
                "autocomplete" => "current-password", "tabindex" => 1,
                "autofocus" => !$focus_email
            ]),
            Ht::render_messages_at("password"),
            "</div>\n";
        if ($password_reset)
            echo Ht::unstash_script("jQuery(function(){jQuery(\"#signin_password\").val(" . json_encode_browser($password_reset->password) . ")})");
        if ($is_external_login)
            echo Ht::hidden("action", "login");
        echo '<div class="popup-actions">',
            Ht::submit(null, "Sign in", ["id" => "signin_signin", "class" => "btn-success", "tabindex" => 1]),
            '</div>';
        if (!$is_external_login
            && !$conf->opt("disableNewUsers")
            && !$conf->opt("disableNonPC"))
            echo '<p class="hint">New to the site? <a href="" class="ui js-create-account">Create an account</a></p>';
        echo '</div></form></div>';
    }

    private function render_h2_home($x, $gx) {
        $i = +$gx->annex("h2_home_count") + 1;
        $gx->set_annex("h2_home_count", $i);
        return "<h2 class=\"home home-$i\">" . $x . "</h2>";
    }

    function render_search(Contact $user, Qrequest $qreq, $gx) {
        $conf = $user->conf;
        if (!$user->privChair
            && ((!$conf->has_any_submitted()
                 && !($user->isPC && $conf->setting("pc_seeall")))
                || !$user->is_reviewer()))
            return;

        echo '<div class="homegrp" id="homelist">',
            Ht::form($conf->hoturl("search"), ["method" => "get"]),
            $this->render_h2_home('<a class="qq" href="' . $conf->hoturl("search") . '" id="homesearch-label">Search</a>', $gx);

        $tOpt = PaperSearch::search_types($user);
        echo Ht::entry("q", (string) $qreq->q,
                       array("id" => "homeq", "size" => 32, "title" => "Enter paper numbers or search terms",
                             "class" => "papersearch need-suggest", "placeholder" => "(All)",
                             "aria-labelledby" => "homesearch-label")),
            " &nbsp;in&nbsp; ",
            PaperSearch::searchTypeSelector($tOpt, key($tOpt)), "
        &nbsp; ", Ht::submit("Search"),
            "</form></div>\n";
    }

    function render_reviews(Contact $user, Qrequest $qreq, $gx) {
        $conf = $user->conf;
        if (!$user->privChair
            && !($user->is_reviewer() && $conf->has_any_submitted()))
            return;

        $this->_merit_field = null;
        $all_review_fields = $conf->all_review_fields();
        $merit_field = get($all_review_fields, "overAllMerit");
        if ($merit_field && $merit_field->displayed && $merit_field->main_storage)
            $this->_merit_field = $merit_field;

        // Information about my reviews
        $where = array();
        if ($user->contactId)
            $where[] = "PaperReview.contactId=" . $user->contactId;
        if (($tokens = $user->review_tokens()))
            $where[] = "reviewToken in (" . join(",", $tokens) . ")";
        $this->_my_rinfo = null;
        if (!empty($where)) {
            $rinfo = (object) ["num_submitted" => 0, "num_needs_submit" => 0, "unsubmitted_rounds" => [], "scores" => []];
            $mfs = $this->_merit_field ? $this->_merit_field->main_storage : "null";
            $result = $user->conf->qe("select reviewType, reviewSubmitted, reviewNeedsSubmit, timeApprovalRequested, reviewRound, $mfs from PaperReview join Paper using (paperId) where (" . join(" or ", $where) . ") and (reviewSubmitted is not null or timeSubmitted>0)");
            while (($row = $result->fetch_row())) {
                if ($row[1] || $row[3] < 0) {
                    $rinfo->num_submitted += 1;
                    $rinfo->num_needs_submit += 1;
                    if ($row[5] !== null) {
                        $rinfo->scores[] = $row[5];
                    }
                } else if ($row[2]) {
                    $rinfo->num_needs_submit += 1;
                    $rinfo->unsubmitted_rounds[$row[4]] = true;
                }
            }
            Dbl::free($result);
            $rinfo->unsubmitted_rounds = join(",", array_keys($rinfo->unsubmitted_rounds));
            $rinfo->scores = join(",", $rinfo->scores);
            $rinfo->mean_score = ScoreInfo::mean_of($rinfo->scores, true);
            if ($rinfo->num_submitted > 0 || $rinfo->num_needs_submit > 0) {
                $this->_my_rinfo = $rinfo;
            }
        }

        // Information about PC reviews
        $npc = $sumpcSubmit = $npcScore = $sumpcScore = 0;
        if ($user->isPC || $user->privChair) {
            $result = Dbl::qe_raw("select count(reviewId) num_submitted,
        group_concat(overAllMerit) scores
        from ContactInfo
        left join PaperReview on (PaperReview.contactId=ContactInfo.contactId and PaperReview.reviewSubmitted is not null)
            where roles!=0 and (roles&" . Contact::ROLE_PC . ")!=0
        group by ContactInfo.contactId");
            while (($row = edb_row($result))) {
                ++$npc;
                if ($row[0]) {
                    $sumpcSubmit += $row[0];
                    ++$npcScore;
                    $sumpcScore += ScoreInfo::mean_of($row[1], true);
                }
            }
            Dbl::free($result);
        }

        echo '<div class="homegrp" id="homerev">';

        // Overview
        echo $this->render_h2_home("Reviews", $gx);
        if ($this->_my_rinfo) {
            echo $conf->_("You have submitted %1\$d of <a href=\"%3\$s\">%2\$d reviews</a> with average %4\$s score %5\$s.",
                $this->_my_rinfo->num_submitted, $this->_my_rinfo->num_needs_submit,
                $conf->hoturl("search", "q=&amp;t=r"),
                $this->_merit_field ? $this->_merit_field->name_html : false,
                $this->_merit_field ? $this->_merit_field->unparse_average($this->_my_rinfo->mean_score) : false),
                "<br>\n";
        }
        if (($user->isPC || $user->privChair) && $npc) {
            echo $conf->_("The average PC member has submitted %.1f reviews with average %s score %s.",
                $sumpcSubmit / $npc,
                $this->_merit_field && $npcScore ? $this->_merit_field->name_html : false,
                $this->_merit_field && $npcScore ? $this->_merit_field->unparse_average($sumpcScore / $npcScore) : false);
            if ($user->isPC || $user->privChair)
                echo "&nbsp; <small class=\"nw\">(<a href=\"", $conf->hoturl("users", "t=pc&amp;score%5B%5D=0"), "\">details</a><span class=\"barsep\">·</span><a href=\"", $conf->hoturl("graph", "g=procrastination"), "\">graphs</a>)</small>";
            echo "<br>\n";
        }
        if ($this->_my_rinfo
            && $this->_my_rinfo->num_submitted < $this->_my_rinfo->num_needs_submit
            && !$conf->time_review_open()) {
            echo ' <span class="deadline">The site is not open for reviewing.</span><br>', "\n";
        } else if ($this->_my_rinfo
                   && $this->_my_rinfo->num_submitted < $this->_my_rinfo->num_needs_submit) {
            $missing_rounds = explode(",", $this->_my_rinfo->unsubmitted_rounds);
            sort($missing_rounds, SORT_NUMERIC);
            foreach ($missing_rounds as $round) {
                if (($rname = $conf->round_name($round))) {
                    if (strlen($rname) == 1)
                        $rname = "“{$rname}”";
                    $rname .= " ";
                }
                if ($conf->time_review($round, $user->isPC, false)) {
                    $dn = $conf->review_deadline($round, $user->isPC, false);
                    $d = $conf->printableTimeSetting($dn, "span");
                    if ($d == "N/A")
                        $d = $conf->printableTimeSetting($conf->review_deadline($round, $user->isPC, true), "span");
                    if ($d != "N/A")
                        echo ' <span class="deadline">Please submit your ', $rname, ($this->_my_rinfo->num_needs_submit == 1 ? "review" : "reviews"), " by $d.</span><br>\n";
                } else if ($conf->time_review($round, $user->isPC, true)) {
                    echo ' <span class="deadline"><strong class="overdue">', $rname, ($rname ? "reviews" : "Reviews"), ' are overdue.</strong> They were requested by ', $conf->printableTimeSetting($conf->review_deadline($round, $user->isPC, false), "span"), ".</span><br>\n";
                } else {
                    echo ' <span class="deadline"><strong class="overdue">The <a href="', $conf->hoturl("deadlines"), '">deadline</a> for submitting ', $rname, "reviews has passed.</strong></span><br>\n";
                }
            }
        } else if ($user->isPC && $user->can_review_any()) {
            $d = $conf->printableTimeSetting($conf->review_deadline(null, $user->isPC, false), "span");
            if ($d != "N/A")
                echo " <span class=\"deadline\">The review deadline is $d.</span><br>\n";
        }
        if ($user->isPC && $user->can_review_any()) {
            echo '  <span class="hint">As a PC member, you may review <a href="', $conf->hoturl("search", "q=&amp;t=s"), "\">any submitted paper</a>.</span><br>\n";
        } else if ($user->privChair) {
            echo '  <span class="hint">As an administrator, you may review <a href="', $conf->hoturl("search", "q=&amp;t=s"), "\">any submitted paper</a>.</span><br>\n";
        }

        if ($this->_my_rinfo) {
            echo '<div id="foldre" class="homesubgrp foldo">';
        }

        // Actions
        $sep = "";
        $xsep = ' <span class="barsep">·</span> ';
        if ($this->_my_rinfo) {
            echo $sep, foldupbutton(), "<a href=\"", $conf->hoturl("search", "q=re%3Ame"), "\" title=\"Search in your reviews (more display and download options)\"><strong>Your Reviews</strong></a>";
            $sep = $xsep;
        }
        if ($user->isPC && $user->is_discussion_lead()) {
            echo $sep, '<a href="', $conf->hoturl("search", "q=lead%3Ame"), '" class="nw">Your discussion leads</a>';
            $sep = $xsep;
        }
        if ($conf->deadlinesAfter("rev_open") || $user->privChair) {
            echo $sep, '<a href="', $conf->hoturl("offline"), '">Offline reviewing</a>';
            $sep = $xsep;
        }
        if ($user->isPC && $conf->timePCReviewPreferences()) {
            echo $sep, '<a href="', $conf->hoturl("reviewprefs"), '">Review preferences</a>';
            $sep = $xsep;
        }
        if ($conf->setting("rev_tokens")) {
            echo $sep;
            $this->_in_reviews = true;
            $this->render_review_tokens($user, $qreq, $gx);
            $sep = $xsep;
        }

        if ($this->_my_rinfo && $conf->setting("rev_ratings") != REV_RATINGS_NONE) {
            $badratings = PaperSearch::unusableRatings($user);
            $qx = (count($badratings) ? " and not (PaperReview.reviewId in (" . join(",", $badratings) . "))" : "");
            $result = $conf->qe_raw("select sum((rating&" . ReviewInfo::RATING_GOODMASK . ")!=0), sum((rating&" . ReviewInfo::RATING_BADMASK . ")!=0) from PaperReview join ReviewRating using (reviewId) where PaperReview.contactId={$user->contactId} $qx");
            $row = edb_row($result);
            Dbl::free($result);

            $a = [];
            if ($row[0])
                $a[] = Ht::link(plural($row[0], "positive rating"), $conf->hoturl("search", "q=re:me+rate:good"));
            if ($row[1])
                $a[] = Ht::link(plural($row[1], "negative rating"), $conf->hoturl("search", "q=re:me+rate:bad"));
            if (!empty($a))
                echo '<div class="hint g">Your reviews have received ', commajoin($a), '.</div>';
        }

        if ($user->has_review()) {
            $plist = new PaperList(new PaperSearch($user, ["q" => "re:me"]));
            $plist->set_table_id_class(null, "pltable-reviewerhome");
            $ptext = $plist->table_html("reviewerHome", ["list" => true]);
            if ($plist->count > 0)
                echo "<div class=\"fx\"><hr class=\"g\">", $ptext, "</div>";
        }

        if ($this->_my_rinfo)
            echo "</div>";

        if ($user->is_reviewer()) {
            echo "<div class=\"homesubgrp has-fold fold20c ui-unfold js-open-activity\" id=\"homeactivity\" data-fold-session=\"foldhomeactivity\">",
                foldupbutton(20),
                "<a href=\"\" class=\"q homeactivity ui js-foldup\" data-fold-target=\"20\">Recent activity<span class=\"fx20\">:</span></a>",
                "</div>";
            if (!$user->session("foldhomeactivity", 1))
                Ht::stash_script("foldup.call(\$(\"#homeactivity\")[0],null,20)");
        }

        echo "</div>\n";
    }

    // Review token printing
    function render_review_tokens(Contact $user, Qrequest $qreq, $gx) {
        if ($this->_tokens_done
            || !$user->has_email()
            || !$user->conf->setting("rev_tokens")
            || ($this->_in_reviews && !$user->is_reviewer()))
            return;

        $tokens = [];
        foreach ($user->session("rev_tokens", []) as $tt)
            $tokens[] = encode_token((int) $tt);

        if (!$this->_in_reviews)
            echo '<div class="homegrp" id="homerev">',
                $this->render_h2_home("Reviews", $gx);
        echo '<table id="foldrevtokens" class="fold2', empty($tokens) ? "c" : "o", '" style="display:inline-table">',
            '<tr><td class="fn2"><a href="" class="fn2 ui js-foldup">Add review tokens</a></td>',
            '<td class="fx2">Review tokens: &nbsp;';

        echo Ht::form($user->conf->hoturl_post("index")),
            Ht::entry("token", join(" ", $tokens), ["size" => max(15, count($tokens) * 8)]),
            " &nbsp;", Ht::submit("Save");
        if (empty($tokens))
            echo '<div class="f-h">Enter tokens to gain access to the corresponding reviews.</div>';
        echo '</form>';

        echo '</td></tr></table>', "\n";
        if (!$this->_in_reviews)
            echo '</div>', "\n";
        $this->_tokens_done = true;
    }

    function render_review_requests(Contact $user, Qrequest $qreq, $gx) {
        $conf = $user->conf;
        if (!$user->is_requester()
            && !$user->has_review_pending_approval()
            && !$user->has_proposal_pending())
            return;

        echo '<div class="homegrp">', $this->render_h2_home("Requested Reviews", $gx);
        if ($user->has_review_pending_approval()) {
            echo '<a href="', $conf->hoturl("paper", "m=rea&amp;p=has%3Apending-approval"),
                ($user->has_review_pending_approval(true) ? '" class="attention' : ''),
                '">Reviews pending approval</a> <span class="barsep">·</span> ';
        }
        if ($user->has_proposal_pending()) {
            echo '<a href="', $conf->hoturl("assign", "p=has%3Aproposal"),
                '" class="attention">Review proposals</a> <span class="barsep">·</span> ';
        }
        echo '<a href="', $conf->hoturl("mail", "monreq=1"), '">Monitor requested reviews</a></div>', "\n";
    }

    function render_submissions(Contact $user, Qrequest $qreq, $gx) {
        $conf = $user->conf;
        if (!$user->is_author()
            && $conf->timeStartPaper() <= 0
            && !$user->privChair
            && $user->is_reviewer())
            return;

        echo '<div class="homegrp" id="homeau">',
            $this->render_h2_home($user->is_author() ? "Your Submissions" : "Submissions", $gx);

        $startable = $conf->timeStartPaper();
        if ($startable && !$user->has_email())
            echo '<span class="deadline">', $conf->printableDeadlineSetting("sub_reg", "span"), "</span><br />\n<small>You must sign in to start a submission.</small>";
        else if ($startable || $user->privChair) {
            echo '<strong><a href="', $conf->hoturl("paper", "p=new"), '">New submission</a></strong> <span class="deadline">(', $conf->printableDeadlineSetting("sub_reg", "span"), ")</span>";
            if ($user->privChair)
                echo '<br><span class="hint">As an administrator, you can start a submission regardless of deadlines and on behalf of others.</span>';
        }

        $plist = null;
        if ($user->is_author()) {
            $plist = new PaperList(new PaperSearch($user, ["t" => "a"]));
            $ptext = $plist->table_html("authorHome", ["noheader" => true, "list" => true]);
            if ($plist->count > 0)
                echo '<hr class="g">', $ptext;
        }

        $deadlines = array();
        if ($plist && $plist->has("need_submit")) {
            if (!$conf->timeFinalizePaper()) {
                // Be careful not to refer to a future deadline; perhaps an admin
                // just turned off submissions.
                if ($conf->deadlinesBetween("", "sub_sub", "sub_grace"))
                    $deadlines[] = "The site is not open for submissions at the moment.";
                else
                    $deadlines[] = 'The <a href="' . $conf->hoturl("deadlines") . '">submission deadline</a> has passed.';
            } else if (!$conf->timeUpdatePaper()) {
                $deadlines[] = 'The <a href="' . $conf->hoturl("deadlines") . '">update deadline</a> has passed, but you can still submit.';
                $time = $conf->printableTimeSetting("sub_sub", "span", " to submit papers");
                if ($time != "N/A")
                    $deadlines[] = "You have until $time.";
            } else {
                $time = $conf->printableTimeSetting("sub_update", "span", " to submit papers");
                if ($time != "N/A")
                    $deadlines[] = "You have until $time.";
            }
        }
        if (!$startable && !count($deadlines)) {
            if ($conf->deadlinesAfter("sub_open"))
                $deadlines[] = 'The <a href="' . $conf->hoturl("deadlines") . '">deadline</a> for registering submissions has passed.';
            else
                $deadlines[] = "The site is not open for submissions at the moment.";
        }
        // NB only has("accepted") if author can see an accepted paper
        if ($plist && $plist->has("accepted")) {
            $time = $conf->printableTimeSetting("final_soft");
            if ($conf->deadlinesAfter("final_soft") && $plist->has("need_final"))
                $deadlines[] = "<strong class=\"overdue\">Final versions are overdue.</strong> They were requested by $time.";
            else if ($time != "N/A")
                $deadlines[] = "Submit final versions of your accepted papers by $time.";
        }
        if (!empty($deadlines)) {
            if ($plist && $plist->count > 0)
                echo '<hr class="g">';
            else if ($startable || $user->privChair)
                echo "<br>";
            echo '<span class="deadline">',
                join("</span><br>\n<span class=\"deadline\">", $deadlines),
                "</span>";
        }

        echo "</div>\n";
    }
}
