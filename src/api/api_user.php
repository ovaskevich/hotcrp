<?php
// api_user.php -- HotCRP user-related API calls
// HotCRP is Copyright (c) 2008-2017 Eddie Kohler and Regents of the UC
// Distributed under an MIT-like license; see LICENSE

class User_API {
    static function whoami(Contact $user, Qrequest $qreq) {
        return ["ok" => true, "email" => $user->email];
    }

    static function clickthrough(Contact $user, Qrequest $qreq) {
        global $Now;
        if ($qreq->accept
            && $qreq->clickthrough_id
            && ($hash = Filer::sha1_hash_as_text($qreq->clickthrough_id))) {
            $user->merge_and_save_data(["clickthrough" => [$hash => $Now]]);
            return ["ok" => true];
        } else if ($qreq->clickthrough_accept) {
            return new JsonResult(400, "Parameter error.");
        } else {
            return ["ok" => false];
        }
    }
}
