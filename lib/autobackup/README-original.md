daily-backup-snapshot-script
============================

The original (old) script is also on my web site: http://rhobbs.co.uk/beh

This "makeSnapshots.sh" script enables you to go back in time to find an old or recent version of an file or directory that was deleted or modified at some point by providing you with daily, weekly, monthly and yearly snapshots.

This script is designed to run once per day, it can write snapshots to a separate directory (local or NFS) or via the rsync protocol (only if you also have the remote partition mounted over NFS locally as well, for the "rm" and "mv" commands to run) and for the first time it runs it initially makes an entire copy of your original data which it then makes a copy of and updates daily.

Version 1.9 - "Another "makeSnapshot" process is currently running" comment only being echo'd once so it doesn't get repeated constantly.

Version 1.8 - "echo" commands put in so there's blank lines in between certain outputs.

Version 1.7 - Variables and if statements added so these things can be chosen: processIsRunning file directory, protocol: rsync or just directory, rsync hostname, username & passwordfile for rsync protocol and checksum yes or no.

Version 1.6 - Modified "overlap time" so it just uses the same "duration" function and modified "duration" function, so it doesn't say "0 hours, 0 minutes, 12 seconds" - it now removes the zeros and says "12 seconds".

Version 1.5 - Added "-n" to some of the "echo" commands, so the "done" appears on the same line.

Version 1.4 - moved "customizable variables" back to the top & echo'ing the duration of each rm, mv, copy and the whole rsync process with start_time & end_time variables.

Version 1.3 - echo comments modified, start date added to beginning, added overlap time being echo'd and comments being echo'd describing snapshots being deleted, moved and created.

Version 1.2 - "processIsRunning" file created when running and while loop created so script doesn't overlap.

Version 1.1 - rsync protocol added.

Version 1.0 - Original.

