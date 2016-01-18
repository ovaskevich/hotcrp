Auto-backup for HotCRP
======================

Getting auto-backup working for HotCRP is pretty easy.

First, edit `autobackup.sh`. The default settings should for the most part
suffice, but you may want to edit `backupCommand` as well as the `snapdir` and
`maxXXX` values.

Once that's set up, run `cron -e` to edit the user's crontab. Add the following:

    0 5 * * * /var/www/html/hotcrp/lib/autobackup/autobackup.sh

This will fire the auto-backup script at 5 a.m. every day.


Known issues
------------
* When using auto-backup for the first time, two identical daily backups are created.
