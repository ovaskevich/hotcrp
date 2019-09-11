<?php
// api_mail.php -- HotCRP mail API calls
// Copyright (c) 2008-2019 Eddie Kohler; see LICENSE.

class Mail_API {
    static function mailtext(Contact $user, Qrequest $qreq, $prow) {
        if (!$user->isPC
            || ($prow && !$user->can_view_paper($prow)))
            return new JsonResult(403, "Permission error.");

        $recipient = [];
        foreach (["first" => "firstName", "last" => "lastName",
                  "affiliation" => "affiliation", "email" => "email"] as $r => $k) {
            if (isset($qreq[$k]))
                $recipient[$k] = $qreq[$k];
            else if (isset($qreq[$r]))
                $recipient[$k] = $qreq[$r];
        }
        $recipient = new Contact($recipient, $user->conf);

        $mailinfo = ["requester_contact" => $user, "sensitivity" => "display"];
        if (isset($qreq->reason))
            $mailinfo["reason"] = $qreq->reason;
        if (isset($qreq->r)
            && ctype_digit($qreq->r)
            && $prow
            && ($rrow = $prow->review_of_id($qreq->r))
            && $user->can_view_review($prow, $rrow))
            $mailinfo["rrow"] = $rrow;

        $mailer = new HotCRPMailer($user->conf, $recipient, $prow, $mailinfo);
        $j = ["ok" => true];
        if (isset($qreq->text) || isset($qreq->subject) || isset($qreq->body)) {
            foreach (["text", "subject", "body"] as $k)
                $j[$k] = $mailer->expand($qreq[$k], $k);
        } else if (isset($qreq->template)) {
            $mt = $user->conf->mail_template($qreq->template);
            if (!$mt
                || (!$user->privChair && !get($mt, "allow_pc")))
                return new JsonResult(404, "No such template.");
            $j["subject"] = $mailer->expand($mt->subject, "subject");
            $j["body"] = $mailer->expand($mt->body, "body");
        } else
            return new JsonResult(400, "Parameter error.");
        return $j;
    }
}
