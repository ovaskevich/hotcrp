#!/bin/bash

# Daily, Weekly, Monthly & Yearly Snapshots
# Version 1.9 - "Another "makeSnapshot" process is currently running" comment only being echo'd once so it doesn't get repeated constantly.
# Version 1.8 - "echo" commands put in so there's blank lines in between certain outputs.
# Version 1.7 - Variables and if statements added so these things can be chosen: processIsRunning file directory, protocol: rsync or just directory, rsync hostname, username & passwordfile for rsync protocol and checksum yes or no.
# Version 1.6 - Modified "overlap time" so it just uses the same "duration" function and modified "duration" function, so it doesn't say "0 hours, 0 minutes, 12 seconds" - it now removes the zeros and says "12 seconds".
# Version 1.5 - Added "-n" to some of the "echo" commands, so the "done" appears on the same line.
# Version 1.4 - moved "customizable variables" back to the top & echo'ing the duration of each rm, mv, copy and the whole rsync process with start_time & end_time variables.
# Version 1.3 - echo comments modified, start date added to beginning, added overlap time being echo'd and comments being echo'd describing snapshots being deleted, moved and created.
# Version 1.2 - "processIsRunning" file created when running and while loop created so script doesn't overlap.
# Version 1.1 - rsync protocol added.
# Version 1.0 - Original.
# Written by Richard Hobbs (fishsponge)
# http://www.rhobbs.co.uk/

#set -ex

################################
# CUSTOMIZABLE VARIABLES BELOW #
################################

# The directory in which snapshots are stored
# NOTE: This will contain 1 complete copy of
# the original data at *least*.
eval snapdir="~/dbBackup"
snapdir="$(readlink -f $snapdir)"
#rsyncsnapdir="snapshots"

# rsync protocol OR directory -> directory OR command
#protocol="rsync"
#protocol="directory"
protocol="command"

# command configuration - use %SNAPSHOT% to substitute snapshot ID
backupFileTmpl="db_backup_%SNAPSHOT%.tar.gz"
backupCommand="/var/www/html/hotcrp/lib/backupdb.sh -n Spring15 -z $snapdir/$backupFileTmpl"

# rsync login details
#rsynchostname="nas"
#rsyncusername="username"
#rsyncpasswordfile="/root/password"

# rsync checksums? "yes" or "no"
#checksums="no"

# directory for "makeSnapshotProcessIsRunning" file
pirfiledir="$snapdir"

# Source directories to put into the snapshots
# NOTE: Do *NOT* include the snapshot directory.
#dirs[0]='/root/'
#dirs[1]='/etc/'
#dirs[2]='/home/'

# NOTE: If you reduce the maximum number of snapshots
# you may have to delete the higher numbered snapshots
# yourself.

# Maximum number of daily snapshots
maxdaily=7

# Maximum number of weekly snapshots
maxweekly=5

# Maximum number of monthly snapshots
maxmonthly=6

# Maximum number of yearly snapshots
maxyearly=5

# Day of week to run weekly, monthly & yearly snapshots
# 1=Mon, 2=Tue, 3=Wed, 4=Thu, 5=Fri, 6=Sat, 7=Sun
# NOTE: All weekly, monthly & yearly snapshots
# will be based on the day before.
daytorun=2




################################
# DO NOT EDIT BELOW THIS LINE  #
################################

echo -n "Start: "; date
echo

duration ()
{
    local hours=`echo $(( (($end_time - $start_time) / 60) / 60 ))`
    local minutes=`echo $(( (($end_time - $start_time) / 60) - ($hours * 60) ))`
    local seconds=`echo $(( ($end_time - $start_time) - ($minutes * 60) - ($hours * 60 * 60) ))`
    if [ $hours != 0 ]
    then
        echo "$hours hours, $minutes minutes, $seconds seconds"
    else
        if [ $minutes != 0 ]
        then
            echo "$minutes minutes, $seconds seconds"
        else
            echo "$seconds seconds"
        fi
    fi
}

getFile() {
    echo "$snapdir/$(sed "s/%SNAPSHOT%/$1/" <<< $backupFileTmpl)"
}

getCommand() {
    echo "$(sed "s/%SNAPSHOT%/$1/" <<< $backupCommand)"
}

if [ $protocol != "command" ]; then
    backupFileTmpl="%SNAPSHOT%"
fi

start_time=`date +%s`
while [ 1 ]
do
    if [ -f "${pirfiledir}/makeSnapshotProcessIsRunning" ]
    then
        if [ "${pirStatementEchod}" != "yes" ]
        then
            echo "Another \"makeSnapshot\" process is currently running (`date`) so waiting for it to finish..."; sleep 257
            $pirStatementEchod="yes"
        fi
        sleep 257
    else
        echo "makeSnapshot has finished (or is not running), so starting the process..."; break
    fi
done
end_time=`date +%s`
echo "Overlap took `duration`."
echo

echo -n "Snapshot creation starts: "; date
echo

touch ${pirfiledir}/makeSnapshotProcessIsRunning

if [ ! -d ${snapdir} ]; then echo -e "${snapdir} doesn't exist.\nPlease check \"snapdir=\" in the script or run \"mkdir ${snapdir}\" in the correct location." >&2; exit 1; fi

if [ `date +%u` == "${daytorun}" ]; then doweekly="yes"; fi
if [ `date +%u` == "${daytorun}" ]; then if [ `date +%d` -le "7" ]; then domonthly="yes"; fi; fi
if [ `date +%u` == "${daytorun}" ]; then if [ `date +%j` -le "7" ]; then doyearly="yes"; fi; fi

if [ "$protocol" != "command" ]; then
    if [ ! -d $(getFile daily.0) ]; then
      echo "\"${snapdir}/daily.0/\" directory doesn't exist, so creating it now.";
      echo;
      mkdir ${snapdir}/daily.0 || exit 1;
    fi
else
    if [ ! -f $(getFile daily.0) ]; then
      echo "\"$(getFile daily.0)\" file doesn't exist, so creating it now.";
      echo;
      touch $(getFile daily.0) || exit 1;
    fi
fi

# DAILY

minus1=`expr ${maxdaily} - 1`
if [ -e $(getFile daily.${minus1}) ]; then
  echo -n "Removing \"daily.${minus1}\"...";
  start_time=`date +%s`;
  rm -rf $(getFile "daily.${minus1}");
  end_time=`date +%s`;
  echo " done (`duration`).";
  echo;
fi
for ((ss=${minus1}; ss >= 2; ss--)); do
  ssminus1=`expr ${ss} - 1`
  if [ -e $(getFile "daily.${ssminus1}") ]; then
    echo -n "Moving \"daily.${ssminus1}\" to \"daily.${ss}\"...";
    start_time=`date +%s`;
    mv $(getFile "daily.${ssminus1}") $(getFile "daily.${ss}");
    end_time=`date +%s`;
    echo " done (`duration`).";
  fi
done
echo
if [ -e $(getFile "daily.0") ]; then
  echo -n "Synchronizing \"daily.0\" with \"daily.1\"...";
  start_time=`date +%s`;
  cp -al $(getFile "daily.0") $(getFile "daily.1");
  end_time=`date +%s`;
  echo " done (`duration`).";
  echo;
fi

# WEEKLY

if [ "${doweekly}" == "yes" ]
then

  minus1=`expr ${maxweekly} - 1`
  if [ -e $(getFile "weekly.${minus1}") ]; then
    echo -n "Removing \"weekly.${minus1}\"...";
    start_time=`date +%s`;
    rm -rf $(getFile "weekly.${minus1}");
    end_time=`date +%s`;
    echo " done (`duration`).";
    echo;
  fi
  for ((ss=${minus1}; ss >= 1; ss--))
  do
    ssminus1=`expr ${ss} - 1`
    if [ -e $(getFile "weekly.${ssminus1}") ]; then
      echo -n "Moving \"weekly.${ssminus1}\" to \"weekly.${ss}\"...";
      start_time=`date +%s`;
      mv $(getFile "weekly.${ssminus1}") $(getFile "weekly.${ss}");
      end_time=`date +%s`;
      echo " done (`duration`).";
    fi
  done
  echo
  if [ -e $(getFile "daily.0") ]; then
    echo -n "Synchronizing \"daily.0\" with \"weekly.0\"...";
    start_time=`date +%s`;
    cp -al $(getFile "daily.0") $(getFile "weekly.0");
    end_time=`date +%s`;
    echo " done (`duration`).";
    echo;
  fi

fi

# MONTHLY

if [ "${domonthly}" == "yes" ]
then

  minus1=`expr ${maxmonthly} - 1`
  if [ -e $(getFile "monthly.${minus1}") ]; then
    echo -n "Removing \"monthly.${minus1}\"...";
    start_time=`date +%s`;
    rm -rf $(getFile "monthly.${minus1}");
    end_time=`date +%s`;
    echo " done (`duration`).";
    echo;
  fi
  for ((ss=${minus1}; ss >= 1; ss--))
  do
    ssminus1=`expr ${ss} - 1`
    if [ -e $(getFile "monthly.${ssminus1}") ]; then echo -n "Moving \"monthly.${ssminus1}\" to \"monthly.${ss}\"..."; start_time=`date +%s`; mv $(getFile "monthly.${ssminus1}") $(getFile "monthly.${ss}"); end_time=`date +%s`; echo " done (`duration`)."; fi
  done
  echo
  if [ -e $(getFile "daily.0") ]; then echo -n "Synchronizing \"daily.0\" with \"monthly.0\"..."; start_time=`date +%s`; cp -al $(getFile "daily.0") $(getFile "monthly.0"); end_time=`date +%s`; echo " done (`duration`)."; echo; fi

fi

# YEARLY

if [ "${doyearly}" == "yes" ]
then

  minus1=`expr ${maxyearly} - 1`
  if [ -e $(getFile "yearly.${minus1}") ]; then
    echo -n "Removing \"yearly.${minus1}\"...";
    start_time=`date +%s`;
    rm -rf $(getFile "yearly.${minus1}");
    end_time=`date +%s`;
    echo " done (`duration`).";
    echo;
  fi
  for ((ss=${minus1}; ss >= 1; ss--))
  do
    ssminus1=`expr ${ss} - 1`
    if [ -e $(getFile "yearly.${ssminus1}") ];
      then echo -n "Moving \"yearly.${ssminus1}\" to \"yearly.${ss}\"...";
      start_time=`date +%s`;
      mv $(getFile "yearly.${ssminus1}") $(getFile "yearly.${ss}");
      end_time=`date +%s`;
      echo " done (`duration`).";
    fi
  done
  echo
  if [ -e $(getFile "daily.0") ]; then
    echo -n "Synchronizing \"daily.0\" with \"yearly.0\"...";
    start_time=`date +%s`;
    cp -al $(getFile "daily.0") $(getFile "yearly.0");
    end_time=`date +%s`;
    echo " done (`duration`).";
    echo;
  fi

fi

# LIVE DATA

echo "Starting $protocol process to \"daily.0\"..."
echo
start_time=`date +%s`
if [ ${protocol} = "command" ]; then
  command="$(getCommand daily.0)"
  echo "Running command \"$command\""
  eval "$command"
else
  for dir in "${dirs[@]}"
  do
    echo "Syncing \"${dir}\"..."
    if [ ${protocol} = "rsync" ]
    then
      if [ ${checksums} = "yes" ]
      then
        rsync -avSc --delete --password-file=${rsyncpasswordfile} ${dir}/ ${rsyncusername}@${rsynchostname}::${rsyncsnapdir}/daily.0/${dir}/
      else
        rsync -avS --delete --password-file=${rsyncpasswordfile} ${dir}/ ${rsyncusername}@${rsynchostname}::${rsyncsnapdir}/daily.0/${dir}/
      fi
    else
      if [ ${protocol} = "directory" ]
      then
        if [ ${checksums} = "yes" ]
        then
          rsync -avSc --delete ${dir}/ ${snapdir}/daily.0/${dir}/
        else
          rsync -avS --delete ${dir}/ ${snapdir}/daily.0/${dir}/
        fi
      else
        echo "No protocol specified, so dropping rsync protocol and using directory..."
        if [ ${checksums} = "yes" ]
        then
          rsync -avSc --delete ${dir}/ ${snapdir}/daily.0/${dir}/
        else
          rsync -avS --delete ${dir}/ ${snapdir}/daily.0/${dir}/
        fi
      fi
    fi
    echo
  done
fi
end_time=`date +%s`
echo "Entire $protocol process done (`duration`)."
 echo
  
touch "$(getFile daily.0)"

rm ${pirfiledir}/makeSnapshotProcessIsRunning

echo -n "End: "; date

