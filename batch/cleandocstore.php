<?php
// cleandocstore.php -- HotCRP maintenance script
// Copyright (c) 2006-2020 Eddie Kohler; see LICENSE.

$ConfSitePATH = preg_replace(',/batch/[^/]+,', '', __FILE__);
require_once("$ConfSitePATH/lib/getopt.php");

$arg = getopt_rest($argv, "hn:c:Vm:du:q", ["help", "name:", "count:", "verbose", "match:",
    "dry-run", "max-usage:", "quiet", "silent", "keep-temp", "docstore"]);
foreach (["c" => "count", "V" => "verbose", "m" => "match", "d" => "dry-run",
          "u" => "max-usage", "q" => "quiet"] as $s => $l) {
    if (isset($arg[$s]) && !isset($arg[$l]))
        $arg[$l] = $arg[$s];
}
if (isset($arg["silent"])) {
    $arg["quiet"] = false;
}
if (isset($arg["h"]) || isset($arg["help"])) {
    fwrite(STDOUT, "Usage: php batch/cleandocstore.php [-c COUNT] [-V] [-m MATCH] [-d|--dry-run]
             [-u USAGELIMIT] [--keep-temp] [--docstore] [DOCSTORES...]\n");
    exit(0);
}
if (isset($arg["count"]) && !ctype_digit($arg["count"])) {
    fwrite(STDERR, "batch/cleandocstore.php: `-c` expects integer\n");
    exit(1);
}

require_once("$ConfSitePATH/src/init.php");

class Batch_CleanDocstore {
    /** @var list<?DocumentFileTree> */
    public $ftrees = [];

    function fparts_random_match() {
        global $Now;
        $fmatches = [];
        for ($i = 0; $i !== count($this->ftrees); ++$i) {
            if (!($ftree = $this->ftrees[$i])) {
                continue;
            }
            $n = 0;
            for ($j = 0;
                 $n < 5 && $j < ($n ? 10 : 10000) && !$ftree->is_empty();
                 ++$j) {
                $fm = $ftree->random_match();
                if ($fm->is_complete()
                    && (($fm->treeid & 1) === 0
                        || max($fm->atime(), $fm->mtime()) < $Now - 86400)) {
                    ++$n;
                    $fmatches[] = $fm;
                } else {
                    $ftree->hide($fm);
                }
            }
            if ($n === 0) {
                $this->ftrees[$i] = null;
            }
        }
        usort($fmatches, function ($a, $b) {
            global $Now;
            // week-old temporary files should be removed first
            $at = $a->atime();
            if (($a->treeid & 1) && $at < $Now - 604800) {
                $at = 1;
            }
            $bt = $b->atime();
            if (($b->treeid & 1) && $bt < $Now - 604800) {
                $bt = 1;
            }
            if ($at !== false && $bt !== false) {
                return $at < $bt ? -1 : ($at == $bt ? 0 : 1);
            } else {
                return $at ? -1 : ($bt ? 1 : 0);
            }
        });
        if (empty($fmatches)) {
            return null;
        } else {
            $fm = $fmatches[0];
            $this->ftrees[$fm->treeid]->hide($fm);
            return $fm;
        }
    }

    /** @param DocumentFileTreeMatch $fm
     * @param bool $dry_run */
    private function check_match(Conf $conf, $fm, $dry_run) {
        $doc = new DocumentInfo([
            "sha1" => $fm->algohash,
            "mimetype" => Mimetype::type($fm->extension)
        ], $conf);
        $hashalg = $doc->hash_algorithm();
        if ($hashalg === false) {
            fwrite(STDERR, "{$fm->fname}: unknown hash\n");
            return false;
        }
        if (!$dry_run) {
            $chash = hash_file($hashalg, $fm->fname, true);
            if ($chash === false) {
                fwrite(STDERR, "{$fm->fname}: is unreadable\n");
                return false;
            } else if ($chash !== $doc->binary_hash_data()) {
                fwrite(STDERR, "{$fm->fname}: incorrect hash\n");
                fwrite(STDERR, "  data hash is " . $doc->hash_algorithm_prefix() . bin2hex($chash) . "\n");
                return false;
            }
        }
        if ($doc->check_s3()) {
            return true;
        } else {
            fwrite(STDERR, "{$fm->fname}: not on S3\n");
            return false;
        }
    }

    function run(Conf $conf, $arg) {
        // argument parsing
        $confdp = $conf->docstore();
        if (isset($arg["docstore"])) {
            echo $confdp ? $confdp . "\n" : "";
            return 0;
        } else if (!$confdp) {
            fwrite(STDERR, "batch/cleandocstore.php: Conference doesn't use docstore\n");
            return 1;
        }

        preg_match('{\A((?:/[^/%]*(?=/|\z))+)}', $confdp, $m);
        $usage_directory = $m[1];

        $count = isset($arg["count"]) ? intval($arg["count"]) : 10;
        $verbose = isset($arg["verbose"]);
        $dry_run = isset($arg["dry-run"]);
        $keep_temp = isset($arg["keep-temp"]);
        $usage_threshold = null;
        $hash_matcher = new DocumentHashMatcher(get($arg, "match"));

        if (isset($arg["max-usage"])) {
            if (!is_numeric($arg["max-usage"])
                || (float) $arg["max-usage"] < 0
                || (float) $arg["max-usage"] > 1) {
                fwrite(STDERR, "batch/cleandocstore.php: `-u` expects fraction between 0 and 1\n");
                return 1;
            }
            $ts = disk_total_space($usage_directory);
            $fs = disk_free_space($usage_directory);
            if ($ts === false || $fs === false) {
                fwrite(STDERR, "$usage_directory: cannot evaluate free space\n");
                return 1;
            }
            $want_fs = $ts * (1 - (float) $arg["max-usage"]);
            $usage_threshold = $want_fs - $fs;
            if (!isset($arg["count"])) {
                $count = 5000;
            }
        }

        foreach (array_merge([$confdp], get($arg, "_", [])) as $i => $dp) {
            if (!str_starts_with($dp, "/") || strpos($dp, "%") === false) {
                fwrite(STDERR, "batch/cleandocstore.php: Bad docstore pattern.\n");
                return 1;
            }
            $this->ftrees[] = new DocumentFileTree($dp, $hash_matcher, count($this->ftrees));
            if (!$keep_temp) {
                $this->ftrees[] = new DocumentFileTree(Filer::docstore_fixed_prefix($dp) . "tmp/%w", $hash_matcher, count($this->ftrees));
            } else {
                $this->ftrees[] = null;
            }
        }

        // actual run
        $ndone = $nsuccess = $bytesremoved = 0;
        while ($count > 0
               && ($usage_threshold === null || $bytesremoved < $usage_threshold)
               && ($fm = $this->fparts_random_match())) {
            if (($fm->treeid & 1) !== 0
                || $this->check_match($conf, $fm, $dry_run)) {
                $size = filesize($fm->fname);
                if ($dry_run || unlink($fm->fname)) {
                    if ($verbose) {
                        fwrite(STDOUT, "{$fm->fname}: " . ($dry_run ? "would remove\n" : "removed\n"));
                    }
                    ++$nsuccess;
                    $bytesremoved += $size;
                } else {
                    fwrite(STDERR, "{$fm->fname}: cannot remove\n");
                }
            }
            --$count;
            ++$ndone;
        }

        if ($verbose && $usage_threshold !== null && $bytesremoved >= $usage_threshold) {
            fwrite(STDOUT, $usage_directory . ": free space above threshold\n");
        }
        if (!isset($arg["quiet"])) {
            fwrite(STDOUT, $usage_directory . ": " . ($dry_run ? "would remove " : "removed ") . plural($nsuccess, "file") . ", " . plural($bytesremoved, "byte") . "\n");
        }
        if ($nsuccess == 0) {
            fwrite(STDERR, "Can't find anything to delete.\n");
        }
        return $nsuccess && $nsuccess == $ndone ? 0 : 1;
    }
}

exit((new Batch_CleanDocstore)->run($Conf, $arg));
