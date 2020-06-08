<?php
// useractions.php -- HotCRP helpers for user actions
// Copyright (c) 2008-2020 Eddie Kohler; see LICENSE.

class UserActions {
    static function disable(Contact $user, $ids) {
        $enabled_cids = Dbl::fetch_first_columns($user->conf->dblink, "select contactId from ContactInfo where contactId?a and disabled=0 and contactId!=?", $ids, $user->contactId);
        if (!$enabled_cids) {
            return (object) ["ok" => true, "warnings" => ["Those accounts were already disabled."]];
        }
        $result = $user->conf->qe("update ContactInfo set disabled=1 where contactId?a and disabled=0", $enabled_cids);
        if (Dbl::is_error($result)) {
            return (object) ["error" => true];
        }
        $user->conf->save_logs(true);
        foreach ($enabled_cids as $cid) {
            $user->conf->log_for($user, $cid, "Account disabled");
        }
        $user->conf->save_logs(false);
        return (object) ["ok" => true];
    }

    static function enable(Contact $user, $ids) {
        // load emails of disabled users
        $disabled_ids = $activate_ids = [];
        $result = $user->conf->qe("select contactId, lastLogin from ContactInfo where contactId?a and disabled=1", $ids);
        while ($result && ($row = $result->fetch_row())) {
            $disabled_ids[] = (int) $row[0];
            if ($row[0] != $user->contactId && !$row[1])
                $activate_ids[$row[0]] = (int) $row[0];
        }
        Dbl::free($result);
        if (empty($disabled_ids)) {
            return (object) ["ok" => true, "warnings" => ["Those accounts were already enabled."]];
        }

        // enable them
        $user->conf->qe("update ContactInfo set disabled=0 where contactId?a", $disabled_ids);
        $user->conf->save_logs(true);
        foreach ($disabled_ids as $cid) {
            $user->conf->log_for($user, $cid, "Account enabled");
        }
        $user->conf->save_logs(false);

        // maybe send some enabling emails
        $result = $user->conf->qe("select * from ContactInfo where contactId?a and roles!=0", $activate_ids);
        while (($xuser = Contact::fetch($result, $user->conf))) {
            if ($xuser->isPC && !$xuser->activity_at) {
                $xuser->send_mail("@newaccount.pc");
            }
        }
        Dbl::free($result);
        return (object) ["ok" => true];
    }

    static function send_account_info(Contact $user, $ids) {
        $done = $disabled = [];
        $result = $user->conf->qe("select * from ContactInfo where contactId?a", $ids);
        while (($xuser = Contact::fetch($result, $user->conf))) {
            if (!$xuser->is_disabled()) {
                $xuser->send_mail("@accountinfo");
                $done[] = $xuser->email;
            } else {
                $disabled[] = $xuser->email;
            }
        }
        Dbl::free($result);

        $j = (object) ["ok" => true, "users" => $done];
        if ($disabled) {
            $j->warnings[] = $user->conf->_("Skipped disabled accounts %2\$s.", count($disabled), htmlspecialchars(commajoin($disabled)));
        }
        return $j;
    }
}
