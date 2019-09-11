<?php
// ldaplogin.php -- HotCRP helper function for LDAP login
// Copyright (c) 2009-2019 Eddie Kohler; see LICENSE.

function ldapLoginBindFailure(Qrequest $qreq, $ldapc) {
    global $Conf;

    // connection failed, report error
    $lerrno = ldap_errno($ldapc);
    $suffix = "";
    if ($lerrno != 49)
        $suffix = "<br /><span class='hint'>(LDAP error $lerrno: " . htmlspecialchars(ldap_err2str($lerrno)) . ")</span>";

    if ($lerrno < 5)
        return Conf::msg_error("LDAP protocol error.  Logins will fail until this error is fixed.$suffix");
    else if ((string) $qreq->password === "") {
        Ht::error_at("password");
        if ($lerrno == 53)
            $suffix = "";
        return Conf::msg_error("Enter your LDAP password.$suffix");
    } else {
        Ht::error_at("email");
        Ht::error_at("password");
        return Conf::msg_error("Those credentials are invalid.  Please use your LDAP username and password.$suffix");
    }
}

function ldapLoginAction(Qrequest $qreq) {
    global $Conf;

    if (!preg_match('/\A\s*(\S+)\s+(\d+\s+)?([^*]+)\*(.*?)\s*\z/s', $Conf->opt("ldapLogin"), $m))
        return Conf::msg_error("Internal error: <code>" . htmlspecialchars($Conf->opt("ldapLogin")) . "</code> syntax error; expected &ldquo;<code><i>LDAP-URL</i> <i>distinguished-name</i></code>&rdquo;, where <code><i>distinguished-name</i></code> contains a <code>*</code> character to be replaced by the user's email address.  Logins will fail until this error is fixed.");

    // connect to the LDAP server
    if ($m[2] == "")
        $ldapc = @ldap_connect($m[1]);
    else
        $ldapc = @ldap_connect($m[1], (int) $m[2]);
    if (!$ldapc)
        return Conf::msg_error("Internal error: ldap_connect.  Logins disabled until this error is fixed.");
    @ldap_set_option($ldapc, LDAP_OPT_PROTOCOL_VERSION, 3);

    $qemail = addcslashes((string) $qreq->email, ',=+<>#;\"');
    $dn = $m[3] . $qemail . $m[4];

    $success = @ldap_bind($ldapc, $dn, (string) $qreq->password);
    if (!$success && @ldap_errno($ldapc) == 2) {
        @ldap_set_option($ldapc, LDAP_OPT_PROTOCOL_VERSION, 2);
        $success = @ldap_bind($ldapc, $dn, (string) $qreq->password);
    }
    if (!$success)
        return ldapLoginBindFailure($qreq, $ldapc);

    // use LDAP information to prepopulate the database with names
    if (isset($Opt["ldap_addlFilterKey"])) {
        $sr = @ldap_search($ldapc, $dn, "(cn=*)",
                   array("sn", "givenname", "cn", "mail", "telephonenumber", $Opt["ldap_addlFilterKey"]));
    } else {
	// did not indent line below to not throw off merge
    $sr = @ldap_search($ldapc, $dn, "(cn=*)",
                       array("sn", "givenname", "cn", "mail", "telephonenumber"));
    }
    if ($sr) {
        $e = @ldap_get_entries($ldapc, $sr);
        $e = ($e["count"] == 1 ? $e[0] : array());
        if (isset($e["cn"]) && $e["cn"]["count"] == 1)
            list($qreq->firstName, $qreq->lastName) = Text::split_name($e["cn"][0]);
        if (isset($e["sn"]) && $e["sn"]["count"] == 1)
            $qreq->lastName = $e["sn"][0];
        if (isset($e["givenname"]) && $e["givenname"]["count"] == 1)
            $qreq->firstName = $e["givenname"][0];
        if (isset($e["mail"]) && $e["mail"]["count"] == 1)
            $qreq->preferredEmail = $e["mail"][0];
        if (isset($e["telephonenumber"]) && $e["telephonenumber"]["count"] == 1)
            $qreq->phone = $e["telephonenumber"][0];
    }

    // additional filter key set?
    if (isset($Opt["ldap_addlFilterKey"])) {
        // only pass, if key exists in LDAP query, has one value, and the value matches 
        //if (!(isset($e[$Opt["ldap_addlFilterKey"]]))) {
        //  return $Conf->errorMsg(" Filter key : '".$Opt["ldap_addlFilterKey"]."' not found in ldap search. " . var_dump(array_keys($e)));
        //}     
        //if (!($e[$Opt["ldap_addlFilterKey"]]["count"] == 1)) {
        //  return $Conf->errorMsg("Found wrong number of entries for key: " . $e[$Opt["ldap_addlFilterKey"]]["count"]);
        //}     
        if (!((isset($e[$Opt["ldap_addlFilterKey"]])) 
                && ($e[$Opt["ldap_addlFilterKey"]]["count"] == 1) 
                && ($e[$Opt["ldap_addlFilterKey"]][0] == $Opt["ldap_addlFilterValue"]))) {
            return $Conf->errorMsg($Opt["ldap_addlFilterErrMsg"]);
        } 
    }
        
    // set default affiliation
    if (isset($Opt["ldap_def_affiliation"])) {
        $_REQUEST["affiliation"] = $Opt["ldap_def_affiliation"];
    }
    // stick in no collaborators by default (avoids setting popping up all the time)
    if (isset($Opt["ldap_def_collab"])) {
        $_REQUEST["collaborators"] = $Opt["ldap_def_collab"];
    }
    
    ldap_close($ldapc);
    return true;
}
