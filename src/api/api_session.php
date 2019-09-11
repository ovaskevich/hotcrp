<?php
// api_session.php -- HotCRP session API calls
// Copyright (c) 2008-2019 Eddie Kohler; see LICENSE.

class Session_API {
    static function setsession(Contact $user, $qreq) {
        ensure_session(0);

        if (is_string($qreq)) {
            $v = $qreq;
        } else {
            $v = (string) $qreq->v;
        }

        $error = false;
        preg_match_all('/(?:\A|\s)(foldpaper|foldpscollab|foldhomeactivity|(?:pl|pf|ul)display|(?:|ul)scoresort)(|\.[^=]*)(=\S*|)(?=\s|\z)/', $v, $ms, PREG_SET_ORDER);
        foreach ($ms as $m) {
            $unfold = intval(substr($m[3], 1) ? : "0") === 0;
            if ($m[1] === "foldpaper" && $m[2] !== "") {
                $x = $user->session($m[1], []);
                if (is_string($x))
                    $x = explode(" ", $x);
                $x = array_diff($x, [substr($m[2], 1)]);
                if ($unfold)
                    $x[] = substr($m[2], 1);
                $v = join(" ", $x);
                if ($v === "")
                    $user->save_session($m[1], null);
                else if (substr_count($v, " ") === count($x) - 1)
                    $user->save_session($m[1], $v);
                else
                    $user->save_session($m[1], $x);
                // XXX backwards compat
                $user->save_session("foldpapera", null);
                $user->save_session("foldpaperb", null);
                $user->save_session("foldpaperp", null);
                $user->save_session("foldpapert", null);
            } else if ($m[1] === "scoresort" && $m[2] === "" && $m[3] !== "") {
                $want = substr($m[3], 1);
                $default = ListSorter::default_score_sort($user, true);
                $user->save_session($m[1], $want === $default ? null : $want);
            } else if ($m[1] === "ulscoresort" && $m[2] === "" && $m[3] !== "") {
                $want = substr($m[3], 1);
                if (in_array($want, ["A", "V", "D"], true)) {
                    $user->save_session($m[1], $want === "A" ? null : $want);
                }
            } else if (($m[1] === "pldisplay" || $m[1] === "pfdisplay")
                       && $m[2] !== "") {
                PaperList::change_display($user, substr($m[1], 0, 2), substr($m[2], 1), $unfold);
            } else if ($m[1] === "uldisplay"
                       && preg_match('/\A\.[-a-zA-Z0-9_:]+\z/', $m[2])) {
                $x = $user->session($m[1]);
                if ($x === null || strpos($x, " ") === false)
                    $x = " tags overAllMerit ";
                $v = substr($m[2], 1);
                $x = str_replace(" $v ", " ", $x) . ($unfold ? "$v " : "");
                if ($x === " tags overAllMerit " || $x === " overAllMerit tags ")
                    $x = null;
                $user->save_session($m[1], $x);
            } else if (substr($m[1], 0, 4) === "fold" && $m[2] === "") {
                $user->save_session($m[1], $unfold ? 0 : null);
            } else {
                $error = true;
            }
        }

        return ["ok" => !$error, "postvalue" => post_value()];
    }
}
