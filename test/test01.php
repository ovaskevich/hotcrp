<?php
// test01.php -- HotCRP tests: permissions, assignments, search
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

global $ConfSitePATH;
$ConfSitePATH = preg_replace(",/[^/]+/[^/]+$,", "", __FILE__);

require_once("$ConfSitePATH/test/setup.php");
$Conf->check_invariants();

$Conf->save_setting("sub_open", 1);
$Conf->save_setting("sub_update", $Now + 10);
$Conf->save_setting("sub_sub", $Now + 10);

// load users
$user_chair = $Conf->checked_user_by_email("chair@_.com");
$user_estrin = $Conf->checked_user_by_email("estrin@usc.edu"); // pc
$user_kohler = $Conf->checked_user_by_email("kohler@seas.harvard.edu"); // none
$user_marina = $Conf->checked_user_by_email("marina@poema.ru"); // pc
$user_van = $Conf->checked_user_by_email("van@ee.lbl.gov"); // none
$user_mgbaker = $Conf->checked_user_by_email("mgbaker@cs.stanford.edu"); // pc
$user_shenker = $Conf->checked_user_by_email("shenker@parc.xerox.com"); // pc, chair
$user_jon = $Conf->checked_user_by_email("jon@cs.ucl.ac.uk"); // pc, red
$user_varghese = $Conf->checked_user_by_email("varghese@ccrc.wustl.edu"); // pc
$user_wilma = $Conf->checked_user_by_email("ojuelegba@gmail.com"); // pc
$user_mjh = $Conf->checked_user_by_email("mjh@isi.edu"); // pc
$user_pdruschel = $Conf->checked_user_by_email("pdruschel@cs.rice.edu"); // pc
$user_nobody = new Contact;

// users are different
xassert($user_chair->contactId != $user_estrin->contactId);

// check permissions on paper
/** @param PaperInfo $paper1 */
function check_paper1($paper1) {
    global $user_chair, $user_estrin, $user_kohler, $user_marina, $user_van, $user_nobody;
    xassert_neqq($paper1, null);

    xassert($user_chair->can_view_paper($paper1));
    xassert($user_estrin->can_view_paper($paper1));
    xassert($user_marina->can_view_paper($paper1));
    xassert($user_van->can_view_paper($paper1));
    xassert(!$user_kohler->can_view_paper($paper1));
    xassert(!$user_nobody->can_view_paper($paper1));

    xassert($user_chair->allow_administer($paper1));
    xassert(!$user_estrin->allow_administer($paper1));
    xassert(!$user_marina->allow_administer($paper1));
    xassert(!$user_van->allow_administer($paper1));
    xassert(!$user_kohler->allow_administer($paper1));
    xassert(!$user_nobody->allow_administer($paper1));

    xassert($user_chair->can_administer($paper1));
    xassert(!$user_estrin->can_administer($paper1));
    xassert(!$user_marina->can_administer($paper1));
    xassert(!$user_van->can_administer($paper1));
    xassert(!$user_kohler->can_administer($paper1));
    xassert(!$user_nobody->can_administer($paper1));

    xassert($user_chair->can_view_tags($paper1));
    xassert(!$user_estrin->can_view_tags($paper1));
    xassert($user_marina->can_view_tags($paper1));
    xassert(!$user_van->can_view_tags($paper1));
    xassert(!$user_kohler->can_view_tags($paper1));
    xassert(!$user_nobody->can_view_tags($paper1));

    xassert($user_chair->can_view_tag($paper1, "foo"));
    xassert($user_chair->can_view_tag($paper1, "~foo"));
    xassert($user_chair->can_view_tag($paper1, $user_chair->contactId . "~foo"));
    xassert($user_chair->can_view_tag($paper1, "~~foo"));
    xassert($user_chair->can_view_tag($paper1, $user_estrin->contactId . "~foo"));
    xassert(!$user_estrin->can_view_tag($paper1, "foo"));
    xassert(!$user_estrin->can_view_tag($paper1, "~foo"));
    xassert(!$user_estrin->can_view_tag($paper1, $user_chair->contactId . "~foo"));
    xassert(!$user_estrin->can_view_tag($paper1, "~~foo"));
    xassert(!$user_estrin->can_view_tag($paper1, $user_estrin->contactId . "~foo"));
    xassert($user_marina->can_view_tag($paper1, "foo"));
    xassert($user_marina->can_view_tag($paper1, "~foo"));
    xassert(!$user_marina->can_view_tag($paper1, $user_chair->contactId . "~foo"));
    xassert(!$user_marina->can_view_tag($paper1, "~~foo"));
    xassert(!$user_marina->can_view_tag($paper1, $user_estrin->contactId . "~foo"));
    xassert($user_marina->can_view_tag($paper1, $user_marina->contactId . "~foo"));

    xassert($user_chair->can_update_paper($paper1));
    xassert($user_estrin->can_update_paper($paper1));
    xassert(!$user_marina->can_update_paper($paper1));
    xassert($user_van->can_update_paper($paper1));
    xassert(!$user_kohler->can_update_paper($paper1));
    xassert(!$user_nobody->can_update_paper($paper1));
}

$paper1 = $user_chair->checked_paper_by_id(1);
check_paper1($paper1);
check_paper1($user_estrin->checked_paper_by_id(1));

// grant user capability to read paper 1, check it doesn't allow PC view
$user_capability = new Contact;
xassert(!$user_capability->can_view_paper($paper1));
$user_capability->apply_capability_text(AuthorView_Capability::make($paper1));
xassert(!$user_capability->contactId);
xassert($user_capability->can_view_paper($paper1));
xassert(!$user_capability->allow_administer($paper1));
xassert(!$user_capability->can_administer($paper1));
xassert(!$user_capability->can_view_tags($paper1));
xassert(!$user_capability->can_update_paper($paper1));

// rejected papers cannot be updated
xassert($user_estrin->can_update_paper($paper1));
xassert_assign($user_chair, "paper,action,decision\n1,decision,no\n");
$paper1 = $user_chair->checked_paper_by_id(1);
xassert(!$user_estrin->can_update_paper($paper1));

// clear decision
xassert_eq($paper1->outcome, -1);
xassert_assign($user_chair, "paper,action,decision\n1,cleardecision,yes\n");
$paper1 = $user_chair->checked_paper_by_id(1);
xassert_eq($paper1->outcome, -1);
xassert_assign($user_chair, "paper,action,decision\n1,cleardecision,no\n");
$paper1 = $user_chair->checked_paper_by_id(1);
xassert_eq($paper1->outcome, 0);

// check `paperacc` invariant
xassert_eq($Conf->setting("paperacc", 0), 0);
xassert_assign($user_chair, "paper,action,decision\n1,decision,yes\n");
xassert_eq($Conf->setting("paperacc", 0), 1);
xassert_assign($user_chair, "paper,action\n1,withdraw\n");
xassert_eq($Conf->setting("paperacc", 0), 0);
xassert_assign($user_chair, "paper,action\n1,revive\n");
xassert_eq($Conf->setting("paperacc", 0), 1);
xassert_assign($user_chair, "paper,action,decision\n1,cleardecision,yes\n");
xassert_eq($Conf->setting("paperacc", 0), 0);

// change submission date
$Conf->save_setting("sub_update", $Now - 5);
$Conf->save_setting("sub_sub", $Now - 5);
xassert($user_chair->can_update_paper($paper1));
xassert(!$user_chair->call_with_overrides(Contact::OVERRIDE_CHECK_TIME, "can_update_paper", $paper1));
xassert(!$user_estrin->can_update_paper($paper1));
xassert(!$user_marina->can_update_paper($paper1));
xassert(!$user_van->can_update_paper($paper1));
xassert(!$user_kohler->can_update_paper($paper1));
xassert(!$user_nobody->can_update_paper($paper1));

// role assignment works
$paper18 = $user_mgbaker->checked_paper_by_id(18);
xassert($user_shenker->can_administer($paper18));
xassert(!$user_mgbaker->can_administer($paper1));
xassert(!$user_mgbaker->can_administer($paper18));

// author derivation works
xassert($user_mgbaker->act_author_view($paper18));

// simple search
$pl = new PaperList("empty", new PaperSearch($user_shenker, "au:berkeley"));
$j = $pl->text_json("id title");
xassert_eqq(join(";", array_keys($j)), "1;6;13;15;24");

// "and"
assert_search_papers($user_shenker, "au:berkeley fountain", "24");
assert_search_papers($user_shenker, "au:berkeley (fountain)", "24");
assert_search_papers($user_shenker, "au:berkeley (fountain", "24");
assert_search_papers($user_shenker, "au:berkeley fountain)", "24");

// sorting works
assert_search_papers($user_shenker, "au:berkeley sort:title", "24 15 13 1 6");

// more complex author searches
assert_search_papers($user_shenker, "au:estrin@usc.edu", "1");
assert_search_papers($user_shenker, "au:usc.edu", "1");
assert_search_papers($user_shenker, "au:stanford.edu", "3 18 19");
assert_search_papers($user_shenker, "au:*@*.stanford.edu", "3 18 19");
assert_search_papers($user_shenker, "au:n*@*u", "3 10");

// correct conflict information returned
$psearch = new PaperSearch($user_shenker, ["q" => "1 2 3 4 5 15-18", "reviewer" => $user_mgbaker]);
$pl = new PaperList("empty", $psearch);
$j = $pl->text_json("id conf");
xassert_eqq(join(";", array_keys($j)), "1;2;3;4;5;15;16;17;18");
xassert_eqq($j[3]->conf, "Y");
xassert_eqq($j[18]->conf, "Y");
foreach ([1, 2, 4, 5, 15, 16, 17] as $i)
    xassert_eqq($j[$i]->conf, "N");

$psearch = new PaperSearch($user_shenker, ["q" => "1 2 3 4 5 15-18", "reviewer" => $user_jon]);
$pl = new PaperList("empty", $psearch);
$j = $pl->text_json("id conf");
xassert_eqq(join(";", array_keys($j)), "1;2;3;4;5;15;16;17;18");
xassert_eqq($j[17]->conf, "Y");
foreach ([1, 2, 3, 4, 5, 15, 16, 18] as $i) {
    xassert_eqq($j[$i]->conf, "N");
}

assert_search_papers($user_chair, "re:estrin", "4 8 18");
assert_search_papers($user_shenker, "re:estrin", "4 8 18");

assert_search_papers($user_chair, "1-5 15-18", "1 2 3 4 5 15 16 17 18");
assert_search_papers($user_chair, "#1-5 15-#18", "1 2 3 4 5 15 16 17 18");
assert_search_papers($user_chair, "#1-#5 #15-18", "1 2 3 4 5 15 16 17 18");
assert_search_papers($user_chair, "5–1 15—18", "5 4 3 2 1 15 16 17 18");
assert_search_papers($user_chair, "5–1,#15—17,#20", "5 4 3 2 1 15 16 17 20");

// normals don't see conflicted reviews
assert_search_papers($user_mgbaker, "re:estrin", "4 8");

// make reviewer identity anonymous until review completion
$Conf->save_setting("rev_open", 1);
$Conf->save_setting("pc_seeblindrev", 1);
assert_search_papers($user_mgbaker, "re:varghese", "");

$revreq = array("overAllMerit" => 5, "reviewerQualification" => 4, "ready" => true);
save_review(1, $user_mgbaker, $revreq);
assert_search_papers($user_mgbaker, "re:varghese", "1");

// or lead assignment
assert_search_papers($user_marina, "re:varghese", "");
xassert_assign($Admin, "paper,lead\n1,marina\n", true);
assert_search_papers($user_marina, "re:varghese", "1");

// check comment identity
xassert($Conf->setting("au_seerev") == Conf::AUSEEREV_NO);
$comment1 = new CommentInfo(null, $paper1);
$c1ok = $comment1->save(array("text" => "test", "visibility" => "a", "blind" => false), $user_mgbaker);
xassert($c1ok);
xassert(!$user_van->can_view_comment($paper1, $comment1));
xassert(!$user_van->can_view_comment_identity($paper1, $comment1));
xassert(!$user_van->can_comment($paper1, null));
$Conf->save_setting("cmt_author", 1);
xassert(!$user_van->can_comment($paper1, null));
$Conf->save_setting("au_seerev", Conf::AUSEEREV_YES);
xassert($user_van->can_comment($paper1, null));
$Conf->save_setting("cmt_author", null);
xassert(!$user_van->can_comment($paper1, null));
xassert($user_van->can_view_comment($paper1, $comment1));
xassert(!$user_van->can_view_comment_identity($paper1, $comment1));
$Conf->save_setting("rev_blind", Conf::BLIND_OPTIONAL);
xassert($user_van->can_view_comment($paper1, $comment1));
xassert(!$user_van->can_view_comment_identity($paper1, $comment1));
$c1ok = $comment1->save(array("text" => "test", "visibility" => "a", "blind" => false), $user_mgbaker);
xassert($c1ok);
xassert($user_van->can_view_comment_identity($paper1, $comment1));
$Conf->save_setting("rev_blind", null);
xassert(!$user_van->can_view_comment_identity($paper1, $comment1));
$Conf->save_setting("au_seerev", Conf::AUSEEREV_NO);

// check comment/review visibility when reviews are incomplete
$Conf->save_setting("pc_seeallrev", Conf::PCSEEREV_UNLESSINCOMPLETE);
Contact::update_rights();
$review1 = fetch_review($paper1, $user_mgbaker);
xassert(!$user_wilma->has_review());
xassert(!$user_wilma->has_outstanding_review());
xassert($user_wilma->can_view_review($paper1, $review1));
xassert($user_mgbaker->has_review());
xassert($user_mgbaker->has_outstanding_review());
xassert($user_mgbaker->can_view_review($paper1, $review1));
xassert($user_mjh->has_review());
xassert($user_mjh->has_outstanding_review());
xassert(!$user_mjh->can_view_review($paper1, $review1));
xassert($user_varghese->has_review());
xassert($user_varghese->has_outstanding_review());
xassert(!$user_varghese->can_view_review($paper1, $review1));
xassert($user_marina->has_review());
xassert($user_marina->has_outstanding_review());
xassert($user_marina->can_view_review($paper1, $review1));
$review2 = save_review(1, $user_mjh, $revreq);
MailChecker::check_db("test01-save-review1B");
xassert($user_wilma->can_view_review($paper1, $review1));
xassert($user_wilma->can_view_review($paper1, $review2));
xassert($user_mgbaker->can_view_review($paper1, $review1));
xassert($user_mgbaker->can_view_review($paper1, $review2));
xassert($user_mjh->can_view_review($paper1, $review1));
xassert($user_mjh->can_view_review($paper1, $review2));
xassert(!$user_varghese->can_view_review($paper1, $review1));
xassert(!$user_varghese->can_view_review($paper1, $review2));
xassert($user_marina->can_view_review($paper1, $review1));
xassert($user_marina->can_view_review($paper1, $review2));

$Conf->save_setting("pc_seeallrev", Conf::PCSEEREV_UNLESSANYINCOMPLETE);
Contact::update_rights();
xassert($user_wilma->can_view_review($paper1, $review1));
xassert($user_wilma->can_view_review($paper1, $review2));
xassert($user_mgbaker->can_view_review($paper1, $review1));
xassert($user_mgbaker->can_view_review($paper1, $review2));
xassert($user_mjh->can_view_review($paper1, $review1));
xassert($user_mjh->can_view_review($paper1, $review2));
xassert(!$user_marina->can_view_review($paper1, $review1));
xassert(!$user_marina->can_view_review($paper1, $review2));

AssignmentSet::run($user_chair, "paper,action,email\n3,primary,ojuelegba@gmail.com\n");
xassert($user_wilma->has_outstanding_review());
xassert(!$user_wilma->can_view_review($paper1, $review1));
xassert(!$user_wilma->can_view_review($paper1, $review2));
$paper3 = $user_wilma->checked_paper_by_id(3);
save_review(3, $user_wilma, $revreq);
xassert(!$user_wilma->has_outstanding_review());
xassert($user_wilma->can_view_review($paper1, $review1));
xassert($user_wilma->can_view_review($paper1, $review2));

// set up some tags and tracks
AssignmentSet::run($user_chair, "paper,tag\n3 9 13 17,green\n", true);
$Conf->save_setting("tracks", 1, "{\"green\":{\"assrev\":\"-red\"}}");
$paper13 = $user_jon->checked_paper_by_id(13);
xassert(!$paper13->has_author($user_jon));
xassert(!$paper13->has_reviewer($user_jon));
xassert(!$Conf->check_tracks($paper13, $user_jon, Track::ASSREV));
xassert($user_jon->can_view_paper($paper13));
xassert(!$user_jon->can_accept_review_assignment_ignore_conflict($paper13));
xassert(!$user_jon->can_accept_review_assignment($paper13));

// check shepherd search visibility
$paper11 = $user_chair->checked_paper_by_id(11);
$paper12 = $user_chair->checked_paper_by_id(12);
$j = call_api("shepherd", $user_chair, ["shepherd" => $user_estrin->email], $paper11);
xassert_eqq($j->ok, true);
$j = call_api("shepherd", $user_chair, ["shepherd" => $user_estrin->email], $paper12);
xassert_eqq($j->ok, true);
assert_search_papers($user_chair, "shep:any", "11 12");
assert_search_papers($user_chair, "shep:estrin", "11 12");
assert_search_papers($user_shenker, "shep:any", "11 12");
assert_search_papers($user_shenker, "has:shepherd", "11 12");

// tag searches
assert_search_papers($user_chair, "#green", "3 9 13 17");
Dbl::qe("insert into PaperTag (paperId,tag,tagIndex) values (1,?,10), (1,?,5), (2,?,3)",
        $user_jon->contactId . "~vote", $user_marina->contactId . "~vote", $user_marina->contactId . "~vote");
assert_search_papers($user_jon, "#~vote", "1");
assert_search_papers($user_jon, "#~vote≥10", "1");
assert_search_papers($user_jon, "#~vote>10", "");
assert_search_papers($user_jon, "#~vote=10", "1");
assert_search_papers($user_jon, "#~vote<10", "");
assert_search_papers($user_jon, "#~v*", "1");
assert_search_papers($user_marina, "#~vote", "2 1");
assert_search_papers($user_marina, "#~vote≥5", "1");
assert_search_papers($user_marina, "#~vote>5", "");
assert_search_papers($user_marina, "#~vote=5", "1");
assert_search_papers($user_marina, "#~vote<5", "2");
assert_search_papers($user_chair, "#marina~vote", "2 1");
assert_search_papers($user_chair, "#red~vote", "1");

// assign some tags using AssignmentSet interface
$assignset = new AssignmentSet($Admin, true);
$assignset->parse("paper,action,tag,index
1-9,tag,g*#clear
2,tag,green,1\n");
assert_search_papers($user_chair, "#green", "3 9 13 17");
$assignset->execute();
assert_search_papers($user_chair, "#green", "13 17 2");
assert_search_papers($user_chair, "#green>0", "2");
assert_search_papers($user_chair, "#green=1", "2");
assert_search_papers($user_chair, "#green=0", "13 17");

$assignset = new AssignmentSet($Admin, true);
$assignset->parse("paper,action,tag,index
1,tag,~vote,clear
2,tag,marina~vote,clear\n");
xassert_eqq(join("\n", $assignset->message_texts()), "");
$assignset->execute();
assert_search_papers($user_chair, "#any~vote", "1");

// check AssignmentSet conflict checking
$assignset = new AssignmentSet($Admin, false);
$assignset->parse("paper,action,email\n1,pri,estrin@usc.edu\n");
xassert_eqq(join("\n", $assignset->message_texts()), "Deborah Estrin <estrin@usc.edu> has a conflict with #1.");
$assignset->execute();
assert_query("select email from PaperReview r join ContactInfo c on (c.contactId=r.contactId) where paperId=1 order by email", "mgbaker@cs.stanford.edu\nmjh@isi.edu\nvarghese@ccrc.wustl.edu");

// check AssignmentSet error messages and landmarks
$assignset = new AssignmentSet($Admin, false);
$assignset->parse("paper,action,email\n1,pri,estrin@usc.edu\n", "fart.txt");
xassert_eqq(join("\n", $assignset->message_texts(true)), "fart.txt:2: Deborah Estrin <estrin@usc.edu> has a conflict with #1.");
xassert(!$assignset->execute());

$assignset = new AssignmentSet($Admin, false);
$assignset->parse("paper,action,email,landmark\n1,pri,estrin@usc.edu,butt.txt:740\n", "fart.txt");
xassert_eqq(join("\n", $assignset->message_texts(true)), "butt.txt:740: Deborah Estrin <estrin@usc.edu> has a conflict with #1.");
xassert(!$assignset->execute());

$assignset = new AssignmentSet($Admin, false);
$assignset->parse("paper,action,email,landmark,message\n1,pri,estrin@usc.edu,butt.txt:740\n1,error,none,butt.txt/10,GODDAMNIT", "fart.txt");
xassert_eqq(join("\n", $assignset->message_texts(true)), "butt.txt/10: GODDAMNIT\nbutt.txt:740: Deborah Estrin <estrin@usc.edu> has a conflict with #1.");
xassert(!$assignset->execute());

assert_search_papers($user_chair, "#testo", "");
$assignset = new AssignmentSet($Admin, false);
$assignset->parse("paper,action,tag,message,landmark\n1,tag,testo,,butt.txt:740\n1,error,,GODDAMNIT,butt.txt/10", "fart.txt");
xassert_eqq(join("\n", $assignset->message_texts(true)), "butt.txt/10: GODDAMNIT");
xassert(!$assignset->execute());

assert_search_papers($user_chair, "#testo", "");
$assignset = new AssignmentSet($Admin, false);
$assignset->parse("paper,action,tag,message,landmark\n1,tag,testo,,butt.txt:740\n1,warning,,GODDAMNIT,butt.txt/10", "fart.txt");
xassert_eqq(join("\n", $assignset->message_texts(true)), "butt.txt/10: GODDAMNIT");
xassert($assignset->execute());

assert_search_papers($user_chair, "#testo", "1");
xassert_assign($Admin, "paper,tag\n1,testo#clear");

$assignset = new AssignmentSet($Admin, false);
$assignset->parse("paper,action,email,landmark,message\n,error,none,butt.txt/10,GODDAMNIT", "fart.txt");
xassert_eqq(join("\n", $assignset->message_texts(true)), "butt.txt/10: GODDAMNIT");
xassert(!$assignset->execute());

// more AssignmentSet conflict checking
assert_search_papers($user_chair, "#fart", "");
$assignset = new AssignmentSet($user_estrin, false);
$assignset->parse("paper,tag
1,fart
2,fart\n");
xassert_eqq(join("\n", $assignset->message_texts()), "You have a conflict with #1.");

xassert_assign($user_estrin, "paper,tag\n2,fart\n");
assert_search_papers($user_chair, "#fart", "2");

xassert_assign($Admin, "paper,tag\n1,#fart\n");
assert_search_papers($user_chair, "#fart", "1 2");
assert_search_papers($user_estrin, "#fart", "2");

// check twiddle tags
xassert_assign($Admin, "paper,tag\n1,~fart\n1,~~fart\n1,varghese~fart\n1,mjh~fart\n");
$paper1->load_tags();
xassert_eqq(join(" ", paper_tag_normalize($paper1)),
           "fart chair~fart mjh~fart varghese~fart jon~vote#10 marina~vote#5 ~~fart");
assert_search_papers($user_chair, "#~~*art", "1");

xassert_assign($Admin, "paper,tag\n1,all#none\n");
$paper1->load_tags();
xassert_eqq(join(" ", paper_tag_normalize($paper1)),
           "mjh~fart varghese~fart jon~vote#10 marina~vote#5");

xassert_assign($Admin, "paper,tag\n1,fart\n");
$paper1->load_tags();
xassert_eqq(join(" ", paper_tag_normalize($paper1)),
           "fart mjh~fart varghese~fart jon~vote#10 marina~vote#5");

xassert_assign($user_varghese, "paper,tag\n1,all#clear\n1,~green\n");
$paper1->load_tags();
xassert_eqq(join(" ", paper_tag_normalize($paper1)),
           "mjh~fart varghese~green jon~vote#10 marina~vote#5");

xassert_assign($Admin, "paper,tag\nall,fart#clear\n1,fart#4\n2,fart#5\n3,fart#6\n", true);
assert_search_papers($user_chair, "order:fart", "1 2 3");
xassert_eqq(search_text_col($user_chair, "order:fart", "tagval:fart"), "1 4\n2 5\n3 6\n");

xassert_assign($Admin, "action,paper,tag\nnexttag,6,fart\nnexttag,5,fart\nnexttag,4,fart\n", true);
assert_search_papers($user_chair, "order:fart", "1 2 3 6 5 4");

xassert_assign($Admin, "action,paper,tag\nseqnexttag,7,fart#3\nseqnexttag,8,fart\n", true);
assert_search_papers($user_chair, "order:fart", "7 8 1 2 3 6 5 4");

xassert_assign($Admin, "action,paper,tag\ncleartag,8,fArt\n", true);
assert_search_papers($user_chair, "order:fart", "7 1 2 3 6 5 4");

xassert_assign($Admin, "action,paper,tag\ntag,8,fArt#4\n", true);
assert_search_papers($user_chair, "order:fart", "7 8 1 2 3 6 5 4");

$paper8 = $user_chair->checked_paper_by_id(8);
xassert_eqq($paper8->tag_value("fart"), 4.0);
xassert(strpos($paper8->all_tags_text(), " fArt#") !== false);

// defined tags: chair
xassert_assign($user_varghese, "paper,tag\n1,chairtest\n");
assert_search_papers($user_varghese, "#chairtest", "1");
xassert_assign($user_varghese, "paper,tag\n1,chairtest#clear\n");
assert_search_papers($user_varghese, "#chairtest", "");

$Conf->save_setting("tag_chair", 1, trim($Conf->setting_data("tag_chair") . " chairtest"));
xassert_assign($Admin, "paper,tag\n1,chairtest\n", true);
assert_search_papers($user_chair, "#chairtest", "1");
assert_search_papers($user_varghese, "#chairtest", "1");
xassert_assign_fail($user_varghese, "paper,tag\n1,chairtest#clear\n");
assert_search_papers($user_varghese, "#chairtest", "1");

// pattern tags: chair
xassert_assign($user_varghese, "paper,tag\n1,chairtest1\n");
assert_search_papers($user_varghese, "#chairtest1", "1");
xassert_assign($user_varghese, "paper,tag\n1,chairtest1#clear\n");
assert_search_papers($user_varghese, "#chairtest1", "");

$Conf->save_setting("tag_chair", 1, trim($Conf->setting_data("tag_chair") . " chairtest*"));
xassert($Conf->tags()->has_pattern);
$ct = $Conf->tags()->check("chairtest0");
xassert(!!$ct);
xassert_assign($Admin, "paper,tag\n1,chairtest1\n", true);
assert_search_papers($user_chair, "#chairtest1", "1");
assert_search_papers($user_varghese, "#chairtest1", "1");
xassert_assign_fail($user_varghese, "paper,tag\n1,chairtest1#clear\n");
assert_search_papers($user_varghese, "#chairtest1", "1");

// pattern tag merging
$Conf->save_setting("tag_approval", 1, "chair*");
$ct = $Conf->tags()->check("chairtest0");
xassert($ct && $ct->readonly && $ct->approval);

// colon tag setting
xassert(!$Conf->setting("has_colontag"));
xassert_assign($Admin, "paper,tag\n1,:poop:\n", true);
xassert(!!$Conf->setting("has_colontag"));

// numeric order sort
assert_search_papers($user_chair, "13 10 8 9 12", "13 10 8 9 12");

// round searches
assert_search_papers($user_chair, "re:huitema", "8 10 13");
assert_search_papers($user_chair, "re:huitema round:R1", "13");
assert_search_papers($user_chair, "round:R1", "12 13 17");
assert_search_papers($user_chair, "round:R1 re:any", "12 13 17");
assert_search_papers($user_chair, "round:R1 re:>=0", "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30");

xassert_assign($Admin, "action,paper,user,round\nclearreview,all,huitema,R1\n", true);
assert_search_papers($user_chair, "re:huitema", "8 10");

xassert_assign($Admin, "action,paper,user,round\nprimary,13,huitema,R1\n", true);
assert_search_papers($user_chair, "round:R1 re:huitema", "13");

xassert_assign($Admin, "action,paper,user,round\nprimary,13,huitema,R2\n", true);
assert_search_papers($user_chair, "round:R1 re:huitema", "");
assert_search_papers($user_chair, "round:R2 re:huitema", "13");

xassert_assign($Admin, "action,paper,user,round\nprimary,13,huitema,:R1\n", true);
assert_search_papers($user_chair, "round:R1 re:huitema", "");
assert_search_papers($user_chair, "round:R2 re:huitema", "13");
assert_search_papers($user_chair, "round:unnamed re:huitema", "8 10");

xassert_assign($Admin, "action,paper,user,round\nprimary,13,huitema,unnamed\n", true);
assert_search_papers($user_chair, "round:R1 re:huitema", "");
assert_search_papers($user_chair, "round:R2 re:huitema", "");
assert_search_papers($user_chair, "round:unnamed re:huitema", "8 10 13");

xassert_assign($Admin, "action,paper,user,round\nprimary,13,huitema,:R1\n", true);
assert_search_papers($user_chair, "round:R1 re:huitema", "");
assert_search_papers($user_chair, "round:R2 re:huitema", "");
assert_search_papers($user_chair, "round:unnamed re:huitema", "8 10 13");

xassert_assign($Admin, "action,paper,user,round\nprimary,13,huitema,R1\n", true);
assert_search_papers($user_chair, "round:R1 re:huitema", "13");
assert_search_papers($user_chair, "round:R2 re:huitema", "");
assert_search_papers($user_chair, "round:unnamed re:huitema", "8 10");

// search combinations
assert_search_papers($user_chair, "re:huitema", "8 10 13");
assert_search_papers($user_chair, "8 10 13 re:huitema", "8 10 13");

// THEN searches
assert_search_papers($user_chair, "10-12 THEN re:huitema", "10 11 12 8 13");
assert_search_papers($user_chair, "10-12 HIGHLIGHT re:huitema", "10 11 12");
assert_search_papers($user_chair, "10-12 THEN re:huitema THEN 5-6", "10 11 12 8 13 5 6");
assert_search_papers($user_chair, "(10-12 THEN re:huitema) THEN 5-6", "10 11 12 8 13 5 6");

// NOT searches
assert_search_papers($user_chair, "#fart", "7 8 1 2 3 6 5 4");
assert_search_papers($user_chair, "tag:#fart", "1 2 3 4 5 6 7 8");
assert_search_papers($user_chair, "tag:fart", "1 2 3 4 5 6 7 8");
assert_search_papers($user_chair, "NOT #fart", "9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30");
assert_search_papers($user_chair, "-#fart", "9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30");

// option searches
assert_search_papers($user_chair, "has:calories", "1 2 3 4 5");
assert_search_papers($user_chair, "opt:calories", "1 2 3 4 5");
assert_search_papers($user_chair, "-opt:calories", "6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30");
assert_search_papers($user_chair, "calories:yes", "1 2 3 4 5");
assert_search_papers($user_chair, "calories:no", "6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30");
assert_search_papers($user_chair, "calories>200", "1 3 4");
assert_search_papers($user_chair, "calories:<1000", "2 5");
assert_search_papers($user_chair, "calories:1040", "3 4");
assert_search_papers($user_chair, "calories≥200", "1 2 3 4");

// option searches with edit condition
$Conf->save_setting("options", 1, '[{"id":1,"name":"Calories","abbr":"calories","type":"numeric","position":1,"display":"default"},{"id":2,"name":"Fattening","type":"numeric","position":2,"display":"default","exists_if":"calories>200"}]');
$Conf->invalidate_caches(["options" => true]);
$Conf->qe("insert into PaperOption (paperId,optionId,value) values (1,2,1),(2,2,1),(3,2,1),(4,2,1),(5,2,1)");
assert_search_papers($user_chair, "has:fattening", "1 3 4");

// Check all tags
assert_search_papers($user_chair, "#none", "9 10 11 12 14 15 16 18 19 20 21 22 23 24 25 26 27 28 29 30");
xassert_assign($Admin, "paper,tag\n9,~private\n10,~~chair\n");
assert_search_papers($user_chair, "#none", "11 12 14 15 16 18 19 20 21 22 23 24 25 26 27 28 29 30");
assert_search_papers($user_mgbaker, "#none", "3 9 10 11 12 14 15 16 18 19 20 21 22 23 24 25 26 27 28 29 30");

// comment searches
$paper2 = $user_chair->checked_paper_by_id(2);
xassert($user_mgbaker->can_comment($paper2, null));
xassert(!$user_mgbaker->can_comment($paper18, null));
xassert($user_marina->can_comment($paper1, null));
xassert($user_marina->can_comment($paper18, null));
assert_search_papers($user_chair, "cmt:any", "1");
assert_search_papers($user_chair, "has:comment", "1");
assert_search_papers($user_chair, "has:response", "");
assert_search_papers($user_chair, "has:author-comment", "1");
$comment2 = new CommentInfo(null, $paper18);
$c2ok = $comment2->save(array("text" => "test", "visibility" => "a", "blind" => false), $user_marina);
xassert($c2ok);
assert_search_papers($user_chair, "cmt:any", "1 18");
assert_search_papers($user_chair, "cmt:any>1", "");
$comment3 = new CommentInfo(null, $paper18);
$c3ok = $comment3->save(array("text" => "test", "visibility" => "a", "blind" => false, "tags" => "redcmt"), $user_marina);
xassert($c3ok);
assert_search_papers($user_chair, "cmt:any>1", "18");
assert_search_papers($user_chair, "cmt:jon", "");
assert_search_papers($user_chair, "cmt:marina", "18");
assert_search_papers($user_chair, "cmt:marina>1", "18");
assert_search_papers($user_chair, "cmt:#redcmt", "18");
$comment4 = new CommentInfo(null, $paper2);
$c2ok = $comment4->save(array("text" => "test", "visibility" => "p", "blind" => false), $user_mgbaker);
MailChecker::check_db("test01-comment2");
assert_search_papers($user_chair, "has:comment", "1 2 18");
assert_search_papers($user_chair, "has:response", "");
assert_search_papers($user_chair, "has:author-comment", "1 18");


/*$result = Dbl::qe("select paperId, tag, tagIndex from PaperTag order by paperId, tag");
$tags = array();
while ($result && ($row = $result->fetch_row()))
    $tags[] = "$row[0],$row[1],$row[2]\n";
echo join("", $tags);*/

// check review visibility for “not unless completed on same paper”
$Conf->save_setting("pc_seeallrev", Conf::PCSEEREV_IFCOMPLETE);
Contact::update_rights();
$review2a = fetch_review($paper2, $user_jon);
xassert(!$review2a->reviewSubmitted && !$review2a->reviewAuthorSeen);
xassert($review2a->reviewOrdinal == 0);
xassert($user_jon->can_view_review($paper2, $review2a));
xassert(!$user_pdruschel->can_view_review($paper2, $review2a));
xassert(!$user_mgbaker->can_view_review($paper2, $review2a));
$review2a = save_review(2, $user_jon, $revreq);
MailChecker::check_db("test01-review2A");
xassert($review2a->reviewSubmitted && !$review2a->reviewAuthorSeen);
xassert($review2a->reviewOrdinal == 1);
xassert($user_jon->can_view_review($paper2, $review2a));
xassert(!$user_pdruschel->can_view_review($paper2, $review2a));
xassert(!$user_mgbaker->can_view_review($paper2, $review2a));
$review2b = save_review(2, $user_pdruschel, $revreq);
MailChecker::check_db("test01-review2B");
xassert($user_jon->can_view_review($paper2, $review2a));
xassert($user_pdruschel->can_view_review($paper2, $review2a));
xassert(!$user_mgbaker->can_view_review($paper2, $review2a));
AssignmentSet::run($user_chair, "paper,action,email\n2,secondary,mgbaker@cs.stanford.edu\n");
$review2d = fetch_review($paper2, $user_mgbaker);
xassert(!$review2d->reviewSubmitted);
xassert($review2d->reviewNeedsSubmit == 1);
xassert(!$user_mgbaker->can_view_review($paper2, $review2a));
$user_external = Contact::create($Conf, null, ["email" => "external@_.com", "name" => "External Reviewer"]);
$user_mgbaker->assign_review(2, $user_external->contactId, REVIEW_EXTERNAL);
$review2d = fetch_review($paper2, $user_mgbaker);
xassert(!$review2d->reviewSubmitted);
xassert($review2d->reviewNeedsSubmit == -1);
xassert(!$user_mgbaker->can_view_review($paper2, $review2a));
$review2e = fetch_review($paper2, $user_external);
xassert(!$user_mgbaker->can_view_review($paper2, $review2e));
$review2e = save_review(2, $user_external, $revreq);
MailChecker::check_db("test01-review2C");
$review2d = fetch_review($paper2, $user_mgbaker);
xassert(!$review2d->reviewSubmitted);
xassert($review2d->reviewNeedsSubmit == 0);
xassert($user_mgbaker->can_view_review($paper2, $review2a));
xassert($user_mgbaker->can_view_review($paper2, $review2e));

// complex assignments
assert_search_papers($user_chair, "2 AND re:4", "2");
assert_search_papers($user_chair, "re:mgbaker", "1 2 13 17");
assert_search_papers($user_chair, "re:sec:mgbaker", "2");
assert_search_papers($user_chair, "sec:mgbaker", "2");
assert_search_papers($user_chair, "re:pri:mgbaker", "1 13 17");

$assignset = new AssignmentSet($user_chair, null);
$assignset->parse("action,paper,email,reviewtype\nreview,all,mgbaker@cs.stanford.edu,secondary:primary\n");
xassert_eqq(join("\n", $assignset->message_texts()), "");
xassert($assignset->execute());

xassert_assign($user_chair, "action,paper,email,reviewtype\nreview,all,mgbaker@cs.stanford.edu,secondary:primary\n");
assert_search_papers($user_chair, "re:sec:mgbaker", "");
assert_search_papers($user_chair, "re:pri:mgbaker", "1 2 13 17");
$review2d = fetch_review($paper2, $user_mgbaker);
xassert(!$review2d->reviewSubmitted);
xassert($review2d->reviewNeedsSubmit == 1);

xassert_assign($user_chair, "action,paper,email,reviewtype\nreview,2,mgbaker@cs.stanford.edu,primary:secondary\n");
assert_search_papers($user_chair, "re:sec:mgbaker", "2");
assert_search_papers($user_chair, "re:pri:mgbaker", "1 13 17");
$review2d = fetch_review($paper2, $user_mgbaker);
xassert(!$review2d->reviewSubmitted);
xassert($review2d->reviewNeedsSubmit == 0);

// uploading the current assignment makes no changes
function get_pcassignment_csv() {
    global $user_chair;
    list($header, $texts) = ListAction::pcassignments_csv_data($user_chair, range(1, 30));
    $csvg = new CsvGenerator;
    return $csvg->select($header)->append($texts)->unparse();
}
$old_pcassignments = get_pcassignment_csv();
xassert_assign($user_chair, $old_pcassignments);
xassert_eqq(get_pcassignment_csv(), $old_pcassignments);

// `any` assignments
assert_search_papers($user_chair, "re:R1", "12 13 17");
assert_search_papers($user_chair, "re:R2", "13 17");
assert_search_papers($user_chair, "re:R3", "12");
assert_search_papers($user_chair, "round:none", "1 2 3 4 5 6 7 8 9 10 11 14 15 16 18");
xassert_assign($user_chair, "action,paper,email,round\nreview,all,all,R1:none\n");
assert_search_papers($user_chair, "re:R1", "");
assert_search_papers($user_chair, "re:R2", "13 17");
assert_search_papers($user_chair, "re:R3", "12");
assert_search_papers($user_chair, "round:none", "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18");
xassert_assign($user_chair, "action,paper,email,round\nreview,1-5,all,none:R1");
assert_search_papers($user_chair, "re:R1", "1 2 3 4 5");
assert_search_papers($user_chair, "re:R2", "13 17");
assert_search_papers($user_chair, "re:R3", "12");
assert_search_papers($user_chair, "round:none", "6 7 8 9 10 11 12 13 14 15 16 17 18");

assert_search_papers($user_chair, "sec:any", "2");
assert_search_papers($user_chair, "has:sec", "2");
assert_search_papers($user_chair, "2 AND pri:mgbaker", "");
xassert_assign($user_chair, "action,paper,email,reviewtype\nreview,any,any,secondary:primary");
assert_search_papers($user_chair, "sec:any", "");
assert_search_papers($user_chair, "has:sec", "");
assert_search_papers($user_chair, "2 AND pri:mgbaker", "2");

assert_search_papers($user_chair, "pri:mgbaker", "1 2 13 17");
xassert_assign($user_chair, "action,paper,email,reviewtype\nreview,any,mgbaker,any");
assert_search_papers($user_chair, "pri:mgbaker", "1 2 13 17");
xassert_assign($user_chair, "action,paper,email,reviewtype\nreview,any,mgbaker,any:pcreview");
assert_search_papers($user_chair, "pri:mgbaker", "");
assert_search_papers($user_chair, "re:opt:mgbaker", "1 2 13 17");

xassert_assign($user_chair, "action,paper,email,reviewtype\nreview,any,mgbaker,any:external");
assert_search_papers($user_chair, "re:opt:mgbaker", "1 2 13 17");

xassert(!$Conf->user_by_email("newexternal@_.com"));
assert_search_papers($user_chair, "re:newexternal@_.com", "");
xassert_assign($user_chair, "action,paper,email\nreview,3,newexternal@_.com");
xassert($Conf->user_by_email("newexternal@_.com"));
assert_search_papers($user_chair, "re:newexternal@_.com", "3");

assert_search_papers($user_chair, "re:external@_.com", "2");
xassert_assign($user_chair, "action,paper,email\nreview,3,external@_.com");
assert_search_papers($user_chair, "re:external@_.com", "2 3");

// paper administrators
assert_search_papers($user_chair, "has:admin", "");
assert_search_papers($user_chair, "conflict:me", "");
assert_search_papers($user_chair, "admin:me", "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30");
assert_search_papers($user_marina, "admin:me", "");
xassert(!$user_marina->is_manager());

xassert_assign($user_chair, "action,paper,user\nadministrator,4,marina@poema.ru\n");
xassert($Conf->setting("papermanager") > 0);
assert_search_papers($user_chair, "has:admin", "4");
assert_search_papers($user_chair, "admin:me", "1 2 3 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30");
assert_search_papers($user_chair, "admin:marina", "4");
assert_search_papers($user_marina, "admin:me", "4");
xassert($user_marina->is_manager());

// conflict overrides
xassert_assign($Conf->root_user(), "action,paper,user,tag\nconflict,4 5,chair@_.com\ntag,4 5,,testtag");
$paper4 = $user_chair->checked_paper_by_id(4);
$paper5 = $user_chair->checked_paper_by_id(5);
assert(!$user_chair->can_administer($paper4));
assert(!$user_chair->allow_administer($paper4));
assert(!$user_chair->can_administer($paper5));
assert($user_chair->allow_administer($paper5));
xassert_eqq($paper4->viewable_tags($user_chair), "");
xassert_eqq($paper5->viewable_tags($user_chair), "");
$overrides = $user_chair->add_overrides(Contact::OVERRIDE_CONFLICT);
assert(!$user_chair->can_administer($paper4));
assert(!$user_chair->allow_administer($paper4));
assert($user_chair->can_administer($paper5));
assert($user_chair->allow_administer($paper5));
xassert_eqq($paper4->viewable_tags($user_chair), "");
xassert_match($paper5->viewable_tags($user_chair), '/\A fart#\d+ testtag#0\z/');
$user_chair->set_overrides($overrides);
xassert_assign($Conf->site_contact(), "action,paper,user\nclearconflict,4 5,chair@_.com");

// preference assignments
xassert_assign($user_chair, "paper,user,pref\n1,marina,10\n");
xassert_assign($user_chair, "paper,user,pref\n1,chair@_.com,10\n");
xassert_assign($user_chair, "paper,user,pref\n4,marina,10\n");
xassert_assign($user_chair, "paper,user,pref\n4,chair@_.com,10\n");

xassert_assign($user_marina, "paper,user,action\n4,chair@_.com,conflict\n");

xassert_assign($user_chair, "paper,user,pref\n1,marina,11\n");
xassert_assign($user_chair, "paper,user,pref\n1,chair@_.com,11\n");
xassert_assign_fail($user_chair, "paper,user,pref\n4,marina,11\n");
xassert_assign($user_chair, "paper,user,pref\n4,chair@_.com,11\n");

xassert_assign($user_marina, "paper,user,pref\n1,marina,12\n");
xassert_assign_fail($user_marina, "paper,user,pref\n1,chair@_.com,12\n");
xassert_assign($user_marina, "paper,user,pref\n4,marina,12\n");
xassert_assign($user_marina, "paper,user,pref\n4,chair@_.com,12\n");

xassert_assign($user_marina, "paper,user,action\n4,chair@_.com,noconflict\n");

$paper1->load_preferences();
xassert_eqq($paper1->preference($user_marina), [12, null]);
xassert_assign($user_marina, "paper,pref\n1,13\n");
$paper1->load_preferences();
xassert_eqq($paper1->preference($user_marina), [13, null]);

// remove paper administrators
xassert($user_marina->is_manager());
assert_search_papers($user_chair, "admin:marina", "4");
xassert_assign_fail($user_marina, "paper,action\n4,clearadministrator\n");
xassert($user_marina->is_manager());
assert_search_papers($user_chair, "admin:marina", "4");
xassert_assign($user_chair, "paper,action\n4,clearadministrator\n");
xassert(!$user_marina->is_manager());
assert_search_papers($user_chair, "admin:marina", "");

// conflicts and contacts
function sorted_conflicts(PaperInfo $prow, $contacts) {
    $c = $contacts ? $prow->contacts(true) : $prow->conflicts(true);
    $c = array_map(function ($c) { return $c->email; }, $c);
    sort($c);
    return join(" ", $c);
}

$paper3 = $user_chair->checked_paper_by_id(3);
xassert_eqq(sorted_conflicts($paper3, true), "sclin@leland.stanford.edu");
xassert_eqq(sorted_conflicts($paper3, false), "mgbaker@cs.stanford.edu sclin@leland.stanford.edu");

$user_sclin = $Conf->checked_user_by_email("sclin@leland.stanford.edu");
$Conf->save_setting("sub_update", $Now + 10);
$Conf->save_setting("sub_sub", $Now + 10);
xassert($user_sclin->can_update_paper($paper3));
xassert_assign($user_sclin, "paper,action,user\n3,conflict,rguerin@ibm.com\n");
$paper3 = $user_chair->checked_paper_by_id(3);
xassert_eqq(sorted_conflicts($paper3, false), "mgbaker@cs.stanford.edu rguerin@ibm.com sclin@leland.stanford.edu");

// test conflict types
$user_rguerin = $Conf->checked_user_by_email("rguerin@ibm.com");
xassert_eqq($paper3->conflict_type($user_rguerin), Conflict::GENERAL);
xassert_assign($user_sclin, "paper,action,user,conflict\n3,conflict,rguerin@ibm.com,pinned\n");
$paper3 = $user_chair->checked_paper_by_id(3);
xassert_eqq($paper3->conflict_type($user_rguerin), Conflict::GENERAL);
xassert_assign($user_chair, "paper,action,user,conflict\n3,conflict,rguerin@ibm.com,pinned\n");
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_rguerin), Conflict::set_pinned(Conflict::GENERAL, true));
xassert_assign($user_sclin, "paper,action,user,conflict type\n3,conflict,rguerin@ibm.com,pinned\n");
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_rguerin), Conflict::set_pinned(Conflict::GENERAL, true));
xassert_assign($user_chair, "paper,action,user,conflicttype\n3,conflict,rguerin@ibm.com,none\n");
xassert_assign($user_sclin, "paper,action,user,conflicttype\n3,conflict,rguerin@ibm.com,conflict\n");
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_rguerin), Conflict::GENERAL);

xassert_assign($user_sclin, "paper,action,user,conflict\n3,conflict,rguerin@ibm.com,collaborator\n");
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_rguerin), 2);
xassert_assign($user_sclin, "paper,action,user,conflict\n3,conflict,rguerin@ibm.com,advisor\n");
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_rguerin), 4);
xassert_assign($user_sclin, "paper,action,user,conflict\n3,conflict,rguerin@ibm.com,advisee\n");
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_rguerin), 4);
xassert_assign($user_sclin, "paper,action,user,conflict\n3,conflict,rguerin,collaborator:none\n");
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_rguerin), 4);
xassert_assign($user_sclin, "paper,action,user,conflict\n3,conflict,any,advisee:collaborator\n");
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_rguerin), 2);
xassert_assign($user_chair, "paper,action,user,conflict\n3,conflict,rguerin@ibm.com,pin unconflicted\n");
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_rguerin), 1);
xassert(!$paper3->has_conflict($user_rguerin));
xassert_assign($user_sclin, "paper,action,user,conflict\n3,conflict,rguerin@ibm.com,advisee\n");
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_rguerin), 1);
xassert_assign($user_chair, "paper,action,user,conflict\n3,conflict,rguerin@ibm.com,unpin\n");
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_rguerin), 0);
xassert_assign($user_sclin, "paper,action,user,conflict\n3,conflict,rguerin@ibm.com,advisee\n");
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_rguerin), 4);

$Conf->save_setting("sub_update", $Now - 5);
$Conf->save_setting("sub_sub", $Now - 5);
xassert_assign_fail($user_sclin, "paper,action,user\n3,clearconflict,rguerin@ibm.com\n");
$paper3 = $user_chair->checked_paper_by_id(3);
xassert_eqq(sorted_conflicts($paper3, false), "mgbaker@cs.stanford.edu rguerin@ibm.com sclin@leland.stanford.edu");

xassert(!$paper3->has_author($user_rguerin));
xassert($paper3->has_conflict($user_rguerin));
xassert_assign($user_sclin, "paper,action,user\n3,contact,rguerin@ibm.com");
$paper3 = $user_chair->checked_paper_by_id(3);
xassert($paper3->has_author($user_rguerin));
xassert($paper3->has_conflict($user_rguerin));
xassert_assign($user_sclin, "paper,action,user\n3,clearcontact,rguerin@ibm.com");
$paper3 = $user_chair->checked_paper_by_id(3);
xassert(!$paper3->has_author($user_rguerin));
xassert($paper3->has_conflict($user_rguerin));
xassert_assign($user_sclin, "paper,action,user\n3,contact,rguerin@ibm.com");
xassert_assign($user_chair, "paper,action,user\n3,clearconflict,rguerin@ibm.com");
$paper3 = $user_chair->checked_paper_by_id(3);
xassert($paper3->has_author($user_rguerin));
xassert($paper3->has_conflict($user_rguerin));
xassert_assign($user_sclin, "paper,action,user\n3,clearcontact,rguerin@ibm.com");
$paper3 = $user_chair->checked_paper_by_id(3);
xassert(!$paper3->has_author($user_rguerin));
xassert(!$paper3->has_conflict($user_rguerin));

xassert_assign($user_chair, "paper,action,user\n3,clearconflict,rguerin@ibm.com\n3,clearconflict,sclin@leland.stanford.edu\n3,clearcontact,mgbaker@cs.stanford.edu\n");
$paper3 = $user_chair->checked_paper_by_id(3);
xassert_eqq(sorted_conflicts($paper3, true), "sclin@leland.stanford.edu");
xassert_eqq(sorted_conflicts($paper3, false), "mgbaker@cs.stanford.edu sclin@leland.stanford.edu");

xassert_assign_fail($user_chair, "paper,action,user\n3,clearcontact,sclin@leland.stanford.edu\n");
xassert_assign($user_chair, "paper,action,user\n3,clearcontact,sclin@leland.stanford.edu\n3,contact,mgbaker@cs.stanford.edu\n");
// though no longer a contact, sclin is still a listed author, so
// has a conflict that way
$paper3 = $user_chair->checked_paper_by_id(3);
xassert_eqq($paper3->conflict_type($user_sclin), CONFLICT_AUTHOR);
xassert_eqq(sorted_conflicts($paper3, true), "mgbaker@cs.stanford.edu sclin@leland.stanford.edu");
xassert_eqq(sorted_conflicts($paper3, false), "mgbaker@cs.stanford.edu sclin@leland.stanford.edu");

// change author list => remove conflict
$ps = new PaperStatus($Conf);
xassert($ps->save_paper_json(json_decode('{"id":3,"authors":[{"name":"Nick McKeown", "email": "nickm@ee.stanford.edu", "affiliation": "Stanford University"}]}')));
$paper3->load_conflicts(false);
xassert_eqq($paper3->conflict_type($user_sclin), 0);
xassert_eqq(sorted_conflicts($paper3, true), "mgbaker@cs.stanford.edu");
xassert_eqq(sorted_conflicts($paper3, false), "mgbaker@cs.stanford.edu");

// tracks and view-paper permissions
AssignmentSet::run($user_chair, "paper,tag\nall,-green\n3 9 13 17,green\n", true);
$Conf->save_setting("tracks", 1, "{\"green\":{\"view\":\"-red\"},\"_\":{\"view\":\"+red\"}}");
$Conf->save_setting("pc_seeallrev", 1);
$Conf->save_setting("pc_seeblindrev", 0);
xassert($user_jon->has_tag("red"));
xassert(!$user_marina->has_tag("red"));

$paper13 = $user_jon->checked_paper_by_id(13);
xassert($paper13->has_tag("green"));
xassert(!$paper13->has_author($user_jon));
xassert(!$paper13->has_reviewer($user_jon));
xassert(!$paper13->has_author($user_marina));
xassert(!$paper13->has_reviewer($user_marina));

xassert(!$user_jon->can_view_paper($paper13));
xassert(!$user_jon->can_view_pdf($paper13));
xassert(!$user_jon->can_view_review($paper13, null));
xassert(!$user_jon->can_view_review_identity($paper13, null));
xassert($user_jon->can_accept_review_assignment_ignore_conflict($paper13));
xassert($user_jon->can_accept_review_assignment($paper13));
xassert(!$user_jon->can_review($paper13, null));
xassert($user_marina->can_view_paper($paper13));
xassert($user_marina->can_view_pdf($paper13));
xassert($user_marina->can_view_review($paper13, null));
xassert($user_marina->can_view_review_identity($paper13, null));
xassert($user_marina->can_accept_review_assignment_ignore_conflict($paper13));
xassert($user_marina->can_accept_review_assignment($paper13));
xassert($user_marina->can_review($paper13, null));

$paper14 = $user_jon->checked_paper_by_id(14);
xassert(!$paper14->has_tag("green"));
xassert(!$paper14->has_author($user_jon));
xassert(!$paper14->has_reviewer($user_jon));
xassert(!$paper14->has_author($user_marina));
xassert(!$paper14->has_reviewer($user_marina));

xassert($user_jon->can_view_paper($paper14));
xassert($user_jon->can_view_pdf($paper14));
xassert($user_jon->can_view_review($paper14, null));
xassert($user_jon->can_view_review_identity($paper14, null));
xassert($user_jon->can_accept_review_assignment_ignore_conflict($paper14));
xassert($user_jon->can_accept_review_assignment($paper14));
xassert($user_jon->can_review($paper14, null));
xassert(!$user_marina->can_view_paper($paper14));
xassert(!$user_marina->can_view_pdf($paper14));
xassert(!$user_marina->can_view_review($paper14, null));
xassert(!$user_marina->can_view_review_identity($paper14, null));
xassert($user_marina->can_accept_review_assignment_ignore_conflict($paper14));
xassert($user_marina->can_accept_review_assignment($paper14));
xassert(!$user_marina->can_review($paper14, null));

xassert_assign($user_chair, "paper,action,user\n13,primary,jon@cs.ucl.ac.uk\n");
xassert_assign($user_chair, "paper,action,user\n14,primary,jon@cs.ucl.ac.uk\n");
xassert_assign($user_chair, "paper,action,user\n13,primary,marina@poema.ru\n");
xassert_assign($user_chair, "paper,action,user\n14,primary,marina@poema.ru\n");
xassert_assign($user_chair, "paper,action,user\n13-14,clearreview,jon@cs.ucl.ac.uk\n13-14,clearreview,marina@poema.ru\n");

$Conf->save_setting("tracks", 1, "{\"green\":{\"view\":\"-red\",\"assrev\":\"-red\"},\"_\":{\"view\":\"+red\",\"assrev\":\"+red\"}}");

xassert(!$user_jon->can_view_paper($paper13));
xassert(!$user_jon->can_view_pdf($paper13));
xassert(!$user_jon->can_view_review($paper13, null));
xassert(!$user_jon->can_view_review_identity($paper13, null));
xassert(!$user_jon->can_accept_review_assignment_ignore_conflict($paper13));
xassert(!$user_jon->can_accept_review_assignment($paper13));
xassert(!$user_jon->can_review($paper13, null));
xassert($user_marina->can_view_paper($paper13));
xassert($user_marina->can_view_pdf($paper13));
xassert($user_marina->can_view_review($paper13, null));
xassert($user_marina->can_view_review_identity($paper13, null));
xassert($user_marina->can_accept_review_assignment_ignore_conflict($paper13));
xassert($user_marina->can_accept_review_assignment($paper13));
xassert($user_marina->can_review($paper13, null));

xassert($user_jon->can_view_paper($paper14));
xassert($user_jon->can_view_pdf($paper14));
xassert($user_jon->can_view_review($paper14, null));
xassert($user_jon->can_view_review_identity($paper14, null));
xassert($user_jon->can_accept_review_assignment_ignore_conflict($paper14));
xassert($user_jon->can_accept_review_assignment($paper14));
xassert($user_jon->can_review($paper14, null));
xassert(!$user_marina->can_view_paper($paper14));
xassert(!$user_marina->can_view_pdf($paper14));
xassert(!$user_marina->can_view_review($paper14, null));
xassert(!$user_marina->can_view_review_identity($paper14, null));
xassert(!$user_marina->can_accept_review_assignment_ignore_conflict($paper14));
xassert(!$user_marina->can_accept_review_assignment($paper14));
xassert(!$user_marina->can_review($paper14, null));

xassert_assign_fail($user_chair, "paper,action,user\n13,primary,jon@cs.ucl.ac.uk\n");
xassert_assign($user_chair, "paper,action,user\n14,primary,jon@cs.ucl.ac.uk\n");
xassert_assign($user_chair, "paper,action,user\n13,primary,marina@poema.ru\n");
xassert_assign_fail($user_chair, "paper,action,user\n14,primary,marina@poema.ru\n");
xassert_assign($user_chair, "paper,action,user\n13-14,clearreview,jon@cs.ucl.ac.uk\n13-14,clearreview,marina@poema.ru\n");

// combinations of tracks
$Conf->save_setting("tracks", 1, "{\"green\":{\"view\":\"-red\",\"assrev\":\"-red\"},\"red\":{\"view\":\"+red\"},\"blue\":{\"view\":\"+blue\"},\"_\":{\"view\":\"+red\",\"assrev\":\"+red\"}}");

// 1: none; 2: red; 3: green; 4: red green; 5: blue;
// 6: red blue; 7: green blue; 8: red green blue
xassert_assign($user_chair, "paper,tag\nall,-green\nall,-red\nall,-blue\n2 4 6 8,+red\n3 4 7 8,+green\n5 6 7 8,+blue\n");
xassert_assign($user_chair, "paper,action,user\nall,clearadministrator\nall,clearlead\n");
assert_search_papers($user_chair, "#red", "2 4 6 8");
assert_search_papers($user_chair, "#green", "3 4 7 8");
assert_search_papers($user_chair, "#blue", "5 6 7 8");

$user_floyd = $Conf->checked_user_by_email("floyd@ee.lbl.gov");
$user_pfrancis = $Conf->checked_user_by_email("pfrancis@ntt.jp");
xassert(!$user_marina->has_tag("red") && !$user_marina->has_tag("blue"));
xassert($user_estrin->has_tag("red") && !$user_estrin->has_tag("blue"));
xassert(!$user_pfrancis->has_tag("red") && $user_pfrancis->has_tag("blue"));
xassert($user_floyd->has_tag("red") && $user_floyd->has_tag("blue"));

for ($pid = 1; $pid <= 8; ++$pid) {
    $paper = $user_chair->checked_paper_by_id($pid);
    foreach ([$user_marina, $user_estrin, $user_pfrancis, $user_floyd] as $cidx => $user) {
        if ((!($cidx & 1) && (($pid - 1) & 2)) /* user not red && paper green */
            || (($cidx & 1) && ($pid == 1 || (($pid - 1) & 1))) /* user red && paper red or none */
            || (($cidx & 2) && (($pid - 1) & 4))) /* user blue && paper blue */
            xassert($user->can_view_paper($paper), "user {$user->email} can view paper $pid");
        else
            xassert(!$user->can_view_paper($paper), "user {$user->email} can't view paper $pid");
    }
}

// primary administrators
$Conf->save_setting("tracks", null);
for ($pid = 1; $pid <= 3; ++$pid) {
    $p = $user_chair->checked_paper_by_id($pid);
    xassert($user_chair->allow_administer($p));
    xassert(!$user_marina->allow_administer($p));
    xassert($user_chair->can_administer($p));
    xassert($user_chair->is_primary_administrator($p));
}
xassert_assign($user_chair, "paper,action,user\n2,administrator,marina@poema.ru");
for ($pid = 1; $pid <= 3; ++$pid) {
    $p = $user_chair->checked_paper_by_id($pid);
    xassert($user_chair->allow_administer($p));
    xassert_eqq($user_marina->allow_administer($p), $pid === 2);
    xassert($user_chair->can_administer($p));
    xassert_eqq($user_marina->can_administer($p), $pid === 2);
    xassert_eqq($user_chair->is_primary_administrator($p), $pid !== 2);
    xassert_eqq($user_marina->is_primary_administrator($p), $pid === 2);
}
$Conf->save_setting("tracks", 1, "{\"green\":{\"admin\":\"+red\"}}");
for ($pid = 1; $pid <= 3; ++$pid) {
    $p = $user_chair->checked_paper_by_id($pid);
    xassert($user_chair->allow_administer($p));
    xassert_eqq($user_marina->allow_administer($p), $pid === 2);
    xassert_eqq($user_estrin->allow_administer($p), $pid === 3);
    xassert($user_chair->can_administer($p));
    xassert_eqq($user_marina->can_administer($p), $pid === 2);
    xassert_eqq($user_estrin->can_administer($p), $pid === 3);
    xassert_eqq($user_chair->is_primary_administrator($p), $pid === 1);
    xassert_eqq($user_marina->is_primary_administrator($p), $pid === 2);
    xassert_eqq($user_estrin->is_primary_administrator($p), $pid === 3);
}
$Conf->save_setting("tracks", null);

// check content upload
$paper30 = $user_chair->checked_paper_by_id(30);
$old_hash = $paper30->document(DTYPE_SUBMISSION)->text_hash();
$ps = new PaperStatus($Conf);
$ps->save_paper_json(json_decode('{"id":30,"submission":{"content_file":"/etc/passwd","mimetype":"application/pdf"}}'));
xassert($ps->has_error_at("paper"));
$paper30 = $user_chair->checked_paper_by_id(30);
xassert_eqq($paper30->document(DTYPE_SUBMISSION)->text_hash(), $old_hash);
$ps->clear();
$ps->save_paper_json(json_decode('{"id":30,"submission":{"content_file":"./../../../../etc/passwd","mimetype":"application/pdf"}}'));
xassert($ps->has_error_at("paper"));
$paper30 = $user_chair->checked_paper_by_id(30);
xassert_eqq($paper30->document(DTYPE_SUBMISSION)->text_hash(), $old_hash);

// check accept invariant
assert_search_papers($user_chair, "dec:yes", "");
xassert(!$Conf->setting("paperacc"));
xassert_assign($user_chair, "paper,decision\n1,accept\n");
assert_search_papers($user_chair, "dec:yes", "1");
xassert($Conf->setting("paperacc"));

// check reviewAuthorSeen
$user_author2 = $Conf->checked_user_by_email("micke@cdt.luth.se");
$review2b = fetch_review($paper2, $user_pdruschel);
xassert(!$user_author2->can_view_review($paper2, $review2b));
xassert(!$review2b->reviewAuthorSeen);
$Conf->save_setting("au_seerev", Conf::AUSEEREV_YES);
xassert($user_author2->can_view_review($paper2, $review2b));

$rjson = $Conf->review_form()->unparse_review_json($user_chair, $paper2, $review2b);
ReviewForm::update_review_author_seen();
$review2b = fetch_review($paper2, $user_pdruschel);
xassert(!$review2b->reviewAuthorSeen);

$rjson = $Conf->review_form()->unparse_review_json($user_author2, $paper2, $review2b);
ReviewForm::update_review_author_seen();
$review2b = fetch_review($paper2, $user_pdruschel);
xassert(!!$review2b->reviewAuthorSeen);

// check review visibility
$Conf->save_setting("au_seerev", Conf::AUSEEREV_NO);
xassert(!$user_author2->can_view_review($paper2, $review2b));
$Conf->save_setting("au_seerev", Conf::AUSEEREV_TAGS);
$Conf->save_setting("tag_au_seerev", 1, "fart");
xassert($user_author2->can_view_review($paper2, $review2b));
$Conf->save_setting("tag_au_seerev", 1, "faart");
xassert(!$user_author2->can_view_review($paper2, $review2b));
$Conf->save_setting("resp_active", 1);
$Conf->save_setting("resp_open", 1);
$Conf->save_setting("resp_done", $Now + 100);
xassert($user_author2->can_view_review($paper2, $review2b));
$Conf->save_setting("au_seerev", Conf::AUSEEREV_NO);
xassert($user_author2->can_view_review($paper2, $review2b));
$Conf->save_setting("resp_active", null);
xassert(!$user_author2->can_view_review($paper2, $review2b));

// check token assignment
assert_search_papers($user_chair, "re:any 19", "");
xassert_assign($user_chair, "paper,action,user\n19,review,anonymous\n");
assert_search_papers($user_chair, "re:any 19", "19");
assert_search_papers($user_chair, "re:1 19", "19");

// check rev_tokens setting
$Conf->check_invariants();
xassert_assign($user_chair, "paper,action,user\n19,clearreview,anonymous\n");
assert_search_papers($user_chair, "re:any 19", "");
$Conf->check_invariants();
xassert_assign($user_chair, "paper,action,user\n19,review,anonymous\n");

xassert_assign($user_chair, "paper,action,user\n19,review,anonymous\n");
assert_search_papers($user_chair, "re:1 19", "19");
assert_search_papers($user_chair, "re:2 19", "");
xassert_assign($user_chair, "paper,action,user\n19,review,new-anonymous\n");
assert_search_papers($user_chair, "re:1 19", "");
assert_search_papers($user_chair, "re:2 19", "19");
xassert_assign($user_chair, "paper,action,user\n19,review,new-anonymous\n19,review,new-anonymous\n");
assert_search_papers($user_chair, "re:1 19", "");
assert_search_papers($user_chair, "re:4 19", "19");

// check that there actually are tokens
$paper19 = $user_chair->checked_paper_by_id(19);
xassert_eqq(count($paper19->reviews_by_id()), 4);
$revs = $paper19->reviews_by_id_order();
for ($i = 0; $i < 4; ++$i) {
    xassert($revs[$i]->reviewToken);
    for ($j = $i + 1; $j < 4; ++$j)
        xassert($revs[$i]->reviewToken != $revs[$j]->reviewToken);
}

// withdraw a paper
$paper16 = $user_chair->checked_paper_by_id(16);
xassert($paper16->timeSubmitted > 0);
xassert_eq($paper16->timeWithdrawn, 0);
xassert_eqq($paper16->withdrawReason, null);
xassert_assign($user_chair, "paper,action,reason\n16,withdraw,Paper is bad\n");
$paper16b = $user_chair->checked_paper_by_id(16);
xassert_eq($paper16b->timeSubmitted, -$paper16->timeSubmitted);
xassert($paper16b->timeWithdrawn > 0);
xassert_eqq($paper16b->withdrawReason, "Paper is bad");
xassert_eqq($paper16b->all_tags_text(), "");
xassert_assign($user_chair, "paper,action,reason\n16,revive\n");

// author can also withdraw
$user_mogul = $Conf->checked_user_by_email("mogul@wrl.dec.com");
$paper16 = $user_mogul->checked_paper_by_id(16);
xassert($paper16->timeSubmitted > 0);
xassert($paper16->timeWithdrawn <= 0);
xassert_assign($user_mogul, "paper,action,reason\n16,withdraw,Sucky\n");
$paper16 = $user_mogul->checked_paper_by_id(16);
xassert($paper16->timeSubmitted < 0);
xassert($paper16->timeWithdrawn > 0);
xassert_eqq($paper16->withdrawReason, "Sucky");
xassert_assign_fail($user_mogul, "paper,action,reason\n16,revive,Sucky\n");
$Conf->save_setting("sub_sub", $Now + 5);
xassert_assign($user_mogul, "paper,action,reason\n16,revive,Sucky\n");
$paper16 = $user_mogul->checked_paper_by_id(16);
xassert($paper16->timeSubmitted > 0);
xassert($paper16->timeWithdrawn <= 0);

// non-author cannot withdraw
xassert_assign_fail($user_estrin, "paper,action,reason\n16,withdraw,Fucker\n");

// check other withdraw possibilities: give a review
$user_chair->assign_review(16, $user_mgbaker->contactId, REVIEW_PC, []);
xassert_assign($user_mogul, "paper,action,reason\n16,withdraw,Sucky\n");
xassert_assign($user_mogul, "paper,action,reason\n16,revive,Sucky\n");
save_review(16, $user_mgbaker, ["ovemer" => 2, "revexp" => 1, "ready" => false]);
xassert_assign($user_mogul, "paper,action,reason\n16,withdraw,Sucky\n");
xassert_assign($user_mogul, "paper,action,reason\n16,revive,Sucky\n");
save_review(16, $user_mgbaker, ["ovemer" => 2, "revexp" => 1, "ready" => true]);
xassert_assign($user_mogul, "paper,action,reason\n16,withdraw,Sucky\n");
xassert_assign($user_mogul, "paper,action,reason\n16,revive,Sucky\n");
$Conf->qe("update PaperReview set reviewAuthorSeen=1 where paperId=? and contactId=?", 16, $user_mgbaker->contactId);
xassert_assign_fail($user_mogul, "paper,action,reason\n16,withdraw,Sucky\n");
$Conf->save_setting("sub_withdraw", 1);
xassert_assign($user_mogul, "paper,action,reason\n16,withdraw,Sucky\n");
xassert_assign($user_mogul, "paper,action,reason\n16,revive,Sucky\n");
$Conf->qe("update Paper set outcome=1 where paperId=?", 16);
xassert_assign_fail($user_mogul, "paper,action,reason\n16,withdraw,Sucky\n");
$Conf->qe("update Paper set outcome=0 where paperId=?", 16);
xassert_assign($user_mogul, "paper,action,reason\n16,withdraw,Sucky\n");
xassert_assign($user_mogul, "paper,action,reason\n16,revive,Sucky\n");

// more tags
$Conf->save_setting("tag_vote", 1, "vote#10 crap#3");
$Conf->save_setting("tag_approval", 1, "app#0");
xassert_assign($user_chair,
    "paper,tag\n16,+huitema~vote#5 +crowcroft~vote#1 +crowcroft~crap#2 +estrin~app +estrin~crap#1 +estrin~bar");
$paper16 = $user_chair->checked_paper_by_id(16);
xassert_eqq($paper16->tag_value("{$user_estrin->contactId}~crap"), 1.0);
xassert_eqq($paper16->tag_value("{$user_estrin->contactId}~app"), 0.0);
xassert_eqq($paper16->tag_value("vote"), 6.0);
xassert_eqq($paper16->tag_value("crap"), 3.0);
xassert_eqq($paper16->tag_value("app"), 1.0);
xassert_eqq($paper16->sorted_viewable_tags($user_chair), " app#1 crap#3 vote#6");
xassert_eqq($paper16->sorted_searchable_tags($user_chair), " 2~vote#5 4~app#0 4~bar#0 4~crap#1 8~crap#2 8~vote#1 app#1 crap#3 vote#6");
xassert(!$user_marina->allow_administer($paper16));
xassert_eqq($paper16->sorted_viewable_tags($user_marina), " app#1 crap#3 vote#6");
xassert_eqq($paper16->sorted_searchable_tags($user_marina), " 2~vote#5 4~app#0 4~crap#1 8~crap#2 8~vote#1 app#1 crap#3 vote#6");
$Conf->save_setting("tag_approval", null);
$paper16 = $user_chair->checked_paper_by_id(16);
xassert_eqq($paper16->sorted_viewable_tags($user_marina), " app#1 crap#3 vote#6");
xassert_eqq($paper16->sorted_searchable_tags($user_marina), " 2~vote#5 4~crap#1 8~crap#2 8~vote#1 app#1 crap#3 vote#6");
$Conf->save_setting("tag_approval", 1, "app#0");
xassert_assign($user_chair, "paper,action\n16,withdraw\n");
$paper16 = $user_chair->checked_paper_by_id(16);
xassert_eqq($paper16->all_tags_text(), " 4~bar#0");
xassert_eqq($paper16->sorted_searchable_tags($user_marina), "");
xassert_eqq($paper16->sorted_searchable_tags($user_estrin), " 4~bar#0");

$Conf->check_invariants();

// author view capabilities and multiple blank users
$blank1 = new Contact(null, $Conf);
$blank1->set_capability("@av19", true);
$blank2 = new Contact(null, $Conf);
$blank2->set_capability("@av16", true);
xassert($blank1->can_view_paper($paper19));
xassert(!$blank1->can_view_paper($paper16));
xassert(!$blank2->can_view_paper($paper19));
xassert($blank2->can_view_paper($paper16));
$blank2->set_capability("@av16", null);
xassert($blank1->can_view_paper($paper19));
xassert(!$blank1->can_view_paper($paper16));
xassert(!$blank2->can_view_paper($paper19));
xassert(!$blank2->can_view_paper($paper16));

// author view capabilities and "author" paper_set
$pset = $blank1->paper_set(["author" => true]);
xassert_array_eqq($pset->paper_ids(), [19]);
$pset = $user_mogul->paper_set(["author" => true]);
xassert_array_eqq($pset->paper_ids(), [16]);
$user_mogul->set_capability("@av12", true);
$pset = $user_mogul->paper_set(["author" => true]);
xassert_array_eqq($pset->paper_ids(), [12, 16]);

// search canonicalization
xassert_eqq(PaperSearch::canonical_query("(a b) OR (c d)", "", "", "", $Conf),
            "(a b) OR (c d)");
xassert_eqq(PaperSearch::canonical_query("", "a b (c d)", "", "", $Conf),
            "a OR b OR (c d)");
xassert_eqq(PaperSearch::canonical_query("e ", "a b (c d)", "", "", $Conf),
            "e AND (a OR b OR (c d))");
xassert_eqq(PaperSearch::canonical_query("", "a b", "c x m", "", $Conf),
            "(a OR b) AND NOT (c OR x OR m)");
xassert_eqq(PaperSearch::canonical_query("", "a b", "(c OR m) (x y)", "", $Conf),
            "(a OR b) AND NOT ((c OR m) OR (x y))");
xassert_eqq(PaperSearch::canonical_query("foo HIGHLIGHT:pink bar", "", "", "", $Conf),
            "foo HIGHLIGHT:pink bar");
xassert_eqq(PaperSearch::canonical_query("foo HIGHLIGHT:pink bar", "", "", "tag", $Conf),
            "#foo HIGHLIGHT:pink #bar");

// assignment synonyms
xassert_eqq($paper16->preference($user_varghese), [0, null]);
xassert_assign($user_varghese, "ID,Title,Preference\n16,Potential Benefits of Delta Encoding and Data Compression for HTTP,1X\n");
$paper16->load_preferences();
xassert_eqq($paper16->preference($user_varghese), [1, 1]);

xassert_eq($paper16->leadContactId, 0);
xassert_assign($user_chair, "paperID,lead\n16,varghese\n", true);
$paper16 = $user_chair->checked_paper_by_id(16);
xassert_eq($paper16->leadContactId, $user_varghese->contactId);

// search types
assert_search_papers($user_chair, "timers", "1 21");
assert_search_papers($user_chair, "ti:timers", "1");
assert_search_papers($user_chair, "routing", "2 3 4 11 19 21 27");
assert_search_papers($user_chair, "routing scalable", "4 19");
assert_search_papers($user_chair, "ti:routing ti:scalable", "4");
assert_search_papers($user_chair, "ti:(routing scalable)", "4");
assert_search_papers($user_chair, "ab:routing ab:scalable", "19");
assert_search_papers($user_chair, "ab:routing scalable", "4 19");
assert_search_papers($user_chair, "ab:(routing scalable)", "19");
assert_search_papers($user_chair, "many", "8 25 29"); // 16 withdrawn
assert_search_papers($user_chair, "many applications", "8 25");
assert_search_papers($user_chair, "\"many applications\"", "8");
assert_search_papers($user_chair, "“many applications”", "8");
assert_search_papers($user_chair, "“many applications“", "8");

// users
xassert(!maybe_user("sclinx@leland.stanford.edu"));
$u = Contact::create($Conf, null, ["email" => "sclinx@leland.stanford.edu", "name" => "Stephen Lon", "affiliation" => "Fart World"]);
xassert(!!$u);
xassert($u->contactId > 0);
xassert_eqq($u->email, "sclinx@leland.stanford.edu");
xassert_eqq($u->firstName, "Stephen");
xassert_eqq($u->lastName, "Lon");
xassert_eqq($u->affiliation, "Fart World");

xassert(!maybe_user("scliny@leland.stanford.edu"));
$u = Contact::create($Conf, null, ["email" => "scliny@leland.stanford.edu", "affiliation" => "Fart World"]);
xassert(!!$u);
xassert($u->contactId > 0);
xassert_eqq($u->email, "scliny@leland.stanford.edu");
xassert_eqq($u->firstName, "");
xassert_eqq($u->lastName, "");
xassert_eqq($u->affiliation, "Fart World");

xassert(!maybe_user("thalerd@eecs.umich.edu"));
$u = Contact::create($Conf, null, ["email" => "thalerd@eecs.umich.edu"]);
assert($u !== null);
xassert(!!$u);
xassert($u->contactId > 0);
xassert_eqq($u->email, "thalerd@eecs.umich.edu");
xassert_eqq($u->firstName, "David");
xassert_eqq($u->lastName, "Thaler");
xassert_eqq($u->affiliation, "University of Michigan");
xassert($Conf->checked_paper_by_id(27)->has_author($u));

xassert(!maybe_user("cengiz@isi.edu"));
$u = Contact::create($Conf, null, ["email" => "cengiz@isi.edu", "first" => "cengiz!", "last" => "ALAETTINOGLU", "affiliation" => "USC ISI"]);
xassert(!!$u);
xassert($u->contactId > 0);
xassert_eqq($u->email, "cengiz@isi.edu");
xassert_eqq($u->firstName, "cengiz!");
xassert_eqq($u->lastName, "ALAETTINOGLU");
xassert_eqq($u->affiliation, "USC ISI");
xassert($Conf->checked_paper_by_id(27)->has_author($u));

xassert(!maybe_user("anonymous10"));
$u = Contact::create($Conf, null, ["email" => "anonymous10"], Contact::SAVE_ANY_EMAIL);
xassert($u->contactId > 0);
xassert_eqq($Conf->fetch_value("select password from ContactInfo where email='anonymous10'"), " nologin");

// contact tags
xassert($user_chair->can_view_user_tags());
xassert($user_estrin->can_view_user_tags());
xassert(!$user_kohler->can_view_user_tags());
xassert(!$user_van->can_view_user_tags());
xassert(!$user_nobody->can_view_user_tags());

xassert_exit();
