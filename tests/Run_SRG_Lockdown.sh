#!/bin/sh

OSL="$(uname -s)"
OSrev="$(uname -r)"
SELF="$(uname -n)"
ZONE="NO"
ANSWER="0"
PWD_DIR="$(pwd)"
SET="0"
SRG_FILES=""
ZIP="$(which gzip)"
TYPE=GUN_PRO
SCP_SERVER=2.1.143.83
NTP_SERVER_OCTETS="$(netstat -rn | awk '{print $2}' | grep "^2\." | head -1 | awk -F. '{print $1"."$2}')"
NTP_SERVER1="${NTP_SERVER_OCTETS}.1.1"
NTP_SERVER2=2.1.1.97
NIPR_SERVER=YES
DAYTON_SERVER=NO
INSTALL=YES
APPLICATION="RSM_CCS"
SUBAPP="UNKNOWN"
increment_corrections="$1"
audit="$2"
sshd="$3"
pam="$4"
sysctl="$5"
mprobe="$6"
ntp="$7"
ldap="$8"
selfhealing="$9"

export SCP_SERVER TYPE ZIP SELF NIPR_SERVER

if [ "${OSL}" = "Linux" -o "${OSL}" = "HP-UX" ]
then
    HOME="/home"
    CMHOME="/home/CMacct1"
    CRON="/var/spool/cron/root"
    DIR="/home/ics/sa_scripts/SVR_AVAIL"
    MAIL="mail"
else
    HOME="/export/home"
    CMHOME="/export/home/CMacct1"
    CRON="/var/spool/cron/crontabs/root"
    DIR="/export/home/ics/sa_scripts/SVR_AVAIL"
    MAIL="mailx"
fi
srr_scp_kickstart()
{
    SRC_FILE="$1"
    DEST_FILE="$2"
    TRANSFER_TYPE="$3"
    ACCT='CMacct1'
    SET="0"
    RET="0"
    NCASE="0"
    KILL_IT="0"
    ALREADY="0"
    TIME_CHK="3"
    OSL="$(uname -s)"
    TMP='/tmp/CMDB'
    if [ ! -d "${TMP}" ]
    then
        mkdir "${TMP}"
    fi
    chown CMacct1:CMgroup "${TMP}"
    LOGFILE="/tmp/CMDB/scp_move.sh"
    SELF="$(hostname|awk -F. '{print $1}')"
    LOCALDIR="/os_srr/LOCAL"
    UNIXDIR="/os_srr/UNIX"
    SCP="$(/usr/bin/which scp |awk '{print $1}')"
    if [ "$(echo "${SCP}" | grep -c "scp")" -eq 0 ]
    then
        SCP="$(find /usr -name "scp" -a -type f | head -n "1")"
    fi
    if [ "${SCP}X" = "X" -a -s ${LOCALDIR}/SCP_location ]
    then
        ${UNIXDIR}/scp_locate.sh
        SCP="$(cat ${LOCALDIR}/SCP_location)"
    fi
    if [ "${OSL}" = "SunOS" ]
    then
        SSHDIR="/export/home/CMacct1/.ssh"
    else
        SSHDIR="/home/CMacct1/.ssh"
    fi
    ## Uncomment the SET=1 variable after ALL toolkits have been released with below code!
    #SET=1
    SET="0"
    echo "-----BEGIN RSA PRIVATE KEY-----" >${SSHDIR}/id_rsa
    echo "MIIEoQIBAAKCAQEAtw03jhiWpg79umx3RvQkS3ylPQ/pcYdwjOhk3ch+K2S8Coqd" >>${SSHDIR}/id_rsa
    echo "6ilJc8GwyrRAI637+W5RbABQOO9DKCl8GNLFJKMJNeadOyXFiBR6WeLRyWNQYgSc" >>${SSHDIR}/id_rsa
    echo "uwOly6SlCIlpiJBbpEgCTLEB5wMyQKgheBwX7nDD5v/mAqMC+zkQd3t/Z1JDRfm4" >>${SSHDIR}/id_rsa
    echo "lTouzk4N7s42Xr43KrPj42hj5K8dGk8N2rRB8gHi0rK88MFUINMdUcetL6VIpMfL" >>${SSHDIR}/id_rsa
    echo "b91XbE+syZQHweavTeH8JE7599c6o8iAjXxyBVJgc4Lzl776lJZKgItbtZ8zz19L" >>${SSHDIR}/id_rsa
    echo "qsrb50G2n3+/b36PIihndrBSVXFhxDRSGVEpGwIBIwKCAQAKdcipCLgmvwcvOWXm" >>${SSHDIR}/id_rsa
    echo "zB9UxUtFUV3L+Rxf0sPvaord6H/GFoyuS4CKRZUS5bqFsiun2msNfFxbBlub5R0I" >>${SSHDIR}/id_rsa
    echo "u5Y8m5ogVlIgoxKaD8x6Kjffn0ZsAEN4ZpvCfm/UmiNJodlZ2DqlS/F66j1ix8dl" >>${SSHDIR}/id_rsa
    echo "8voNoAsxxXrblElQLyWDK6DhVQ+jDyZBogHyVGtyhcVPMyIS59GXYu5FE6QnP1Qi" >>${SSHDIR}/id_rsa
    echo "LNwBu3iLNcBwBsISD8FlXSNop+ssjlvz9YzlgmLHqxygIyDPso7zWO8pfxncJU7v" >>${SSHDIR}/id_rsa
    echo "zKHEHT4njt+bnStKtVi6/uEsViJtGtwzZfdAAUd5JPgoJJCp2/dFHPn3oxeM7GxE" >>${SSHDIR}/id_rsa
    echo "XsQbAoGBAOTuG8K2ploo6Vml5RixE8xI26ouvo6yF9u8bEl/P3ulj9YD0jBTlsuZ" >>${SSHDIR}/id_rsa
    echo "gIDuBm/1gTcuFdyqEYBui8iKE0MP3yW36QbMCgrqL2GfgXY8fFaJDZ/QX+m17tVn" >>${SSHDIR}/id_rsa
    echo "HqbpJDgJ0jzj+hvrF7ihtkVI2VwdrxX/ajsrBStqi6wTyFMw7XaPAoGBAMyyVNhi" >>${SSHDIR}/id_rsa
    echo "ALKUn1v0xCDDq5aW/2XbZot5v4ivDoQFY7wuIU9Ks+T0tERLPuP141GSqX3q9qWY" >>${SSHDIR}/id_rsa
    echo "grVNWiOZTk+/oMtjRC+1sJW3d5R3uiTsgwyURQDu3sC+ka+SEhLO+r8j6Zx2DyI8" >>${SSHDIR}/id_rsa
    echo "OrxldQ6On2yTT5WGNMUSMBB9P5mOQpg76Uq1AoGADRTrpLn64JSfnrkFxuWMGk1O" >>${SSHDIR}/id_rsa
    echo "YX8DkyAenteRKMVxV4XNtHU/NfYl37+g8Wyv6SP4wVMXMS5KJJiaRflC7eOmWe1A" >>${SSHDIR}/id_rsa
    echo "hAuozWx3vG+DvZ0Oa1hJ6+AFexG14E8JENofU6jKL118AZhnwWhTju44TmgYoiva" >>${SSHDIR}/id_rsa
    echo "L0RJcDH5WkpF9iANkb8CgYEAxtkfOJm3iOglxwsHqsy1UHVtIR5GW5rXUZQcusNo" >>${SSHDIR}/id_rsa
    echo "MyV/cZkGhqSR2/FTCVVDOUykpjS1FeScOxfxKeViBFPAxZOhUusDT5xIRxU4e6Pt" >>${SSHDIR}/id_rsa
    echo "BOfOAOgLlqp+5RGN5mKqcIlJVimLC1BzknEv4kFnq01F/vdmdkwusO6yz67EWV7F" >>${SSHDIR}/id_rsa
    echo "XoMCgYAxn1lsEEXTdw3NGv27DqYrP95hDrKVnFPmUrzCfYbXGdF3cHjUtb9kKHpR" >>${SSHDIR}/id_rsa
    echo "wK6u2tuSp048NlIJ29IxQEcFyEoz+uxblFsMEWhnDx3lknm5QzizVq8wxBCq8YR2" >>${SSHDIR}/id_rsa
    echo "HGNAZbnnqHgjn5txBvy9F9//70abrZcbDCIp2dy6cZr7AR/hjA==" >>${SSHDIR}/id_rsa
    echo "-----END RSA PRIVATE KEY-----" >>${SSHDIR}/id_rsa
    touch ${SSHDIR}/known_hosts
    chown CMacct1:CMgroup ${SSHDIR}/id_rsa
    chmod "700" ${SSHDIR}/id_rsa

    if [ -n "$TRANSFER_TYPE" ]
    then
        if [ "${TRANSFER_TYPE}" = "pull" ]
        then
            /bin/su - CMacct1 -c "${SCP} -o 'StrictHostKeyChecking no' -pv ${ACCT}@${SCP_SERVER}:${SRC_FILE} ${DEST_FILE}" >>"${LOGFILE}" 2>&1
            VALUE="$(echo "$?")"
        elif [ "${TRANSFER_TYPE}" = "push" ]
        then
            /bin/su - CMacct1 -c "${SCP} -o 'StrictHostKeyChecking no' -pv ${SRC_FILE} ${ACCT}@${SCP_SERVER}:${DEST_FILE}" >>"${LOGFILE}" 2>&1
            VALUE="$(echo "$?")"
        else
            echo "Can't determine transfer type!" >>"${LOGFILE}"
            exit "1"
        fi
    else
        echo "Can't determine transfer type!" >>"${LOGFILE}"
        exit "1"
    fi
    if [ -s "${LOGFILE}" ]
    then
        BASENAME="$(basename "${SRC_FILE}")"
        SCPOK="$(grep -ic "debug1: Exit status 0" "${LOGFILE}")"
        if [ "${SCPOK}" -eq 0 -a "${VALUE}" -gt 0 ]
        then
            retry
            VAL="$(echo "$?")"
            if [ "${VAL}" -eq 1 -o "${RET}" -eq 1 ]
            then
                check_kill_time
            fi
        else
            echo "Successfully SCP connected to ${SCP_SERVER}..." >>"${LOGFILE}"
        fi
    fi
    if [ "${SET}" -eq 1 ]
    then
        rm ${SSHDIR}/id_rsa
    fi
}

get_sys_time()
{
    HOURS=""
    MINUTES=""
    SECON=""
    TZONE="$(date +%Z)"
    DATE_TODAY="$(date +"%m/%d/%y")" # use system time now
    DATEA="$(date | awk '{print $2":"$3}')" # us date now
    DATEB="$(date +"%H%M%S")"
    MONTH="$(echo "${DATEA}" | awk -F: '{print $1}')"
    DAY="$(echo "${DATEA}" | awk -F: '{print $2}')"
    HOURS="$(echo "${DATEB}" | cut -c1-2)"
    MINUTES="$(echo "${DATEB}" | cut -c3-4)"
    SECON="$(echo "${DATEB}" | cut -c5-6)"
}

check_kill_time()
{
    wait="0"
    while [ "$wait" -eq 0 ]
    do
        get_sys_time
        MONTH_A="$(ls -l "${LOGFILE}" | awk '{print $6}')"
        DAY_A="$(ls -l "${LOGFILE}" | awk '{print $7}')"
        if [ "${MONTH}" = "${MONTH_A}" -a "${DAY}" -eq "${DAY_A}" ]
        then
            TIMESTAMP="$(ls -l "${LOGFILE}" | awk '{print $8}')"
            HOURS_B="$(echo "${TIMESTAMP}" | awk -F: '{print $1}')"
            MINUTES_B="$(echo "${TIMESTAMP}" | awk -F: '{print $2}')"
            MIN_TOTAL="$(expr "${HOURS}" \* "60")"
            VAL="$(expr "${MIN_TOTAL}" + "${MINUTES}")"
            MIN_TOTAL_A="$(expr "${HOURS_B}" \* "60")"
            VAL_A="$(expr "${MIN_TOTAL_A}" + "${MINUTES_B}")"
            MIN_DIFF="$(expr "${VAL}" - "${VAL_A}")"
            if [ "${MIN_DIFF}" -gt "${TIME_CHK}" ]
            then
                NCASE="1"
                KILL_IT="1"
            fi
        else
            KILL_IT="1"
        fi
        ## Time to kill the connections and exit the loop.
        if [ "${KILL_IT}" -eq 1 ]
        then
            cp /dev/null ${TMP}/SRR_scp_pidkill
            if [ "${OSL}" = "Linux" ]
            then
                ps -elf | grep -v grep | grep "CMacct1\@[0-9]*\." | awk '{print $4}' >>${TMP}/SRR_scp_pidkill
            else
                ps -ef | grep -v grep | grep "CMacct1\@[0-9]*\." | awk '{print $2}' >>${TMP}/SRR_scp_pidkill
            fi
            if [ -s ${TMP}/SRR_scp_pidkill ]
            then
                for PiD in "$(cat ${TMP}/SRR_scp_pidkill)"
                do
                    echo "Killing process ${PiD}..."
                    kill -9 "${PiD}"
                done
                exit "1"
            else
                echo "Could not connect make a connection to server...exiting."
                exit "1"
            fi
        fi
        ## Just in case...
        if [ "${NCASE}" -eq 1 ]
        then
            exit "1"
        fi
        sleep "120"
    done
}

retry()
{
    i="1"
    while [ "${i}" -lt 3 ]
    do
        sleep "60"
        SUCCESS="0"
        i="$(expr "${i}" + "1")"
        if [ "${TRANSFER_TYPE}" = "pull" ]
        then
            /bin/su - CMacct1 -c "${SCP} -o 'StrictHostKeyChecking no' -pv ${ACCT}@${SCP_SERVER}:${SRC_FILE} ${DEST_FILE}" >"${LOGFILE}" 2>&1
            VALUE="$(echo "$?")"
            SCPOK="$(grep -ic "debug1: Exit status 0" "${LOGFILE}")"
            if [ "${SCPOK}" -gt 0 -a "${VALUE}" -eq 0 ]
            then
                SUCCESS="1"
            fi
        elif [ "${TRANSFER_TYPE}" = "push" ]
        then
            /bin/su - CMacct1 -c "${SCP} -o 'StrictHostKeyChecking no' -pv ${SRC_FILE} ${ACCT}@${SCP_SERVER}:${DEST_FILE}" >"${LOGFILE}" 2>&1
            VALUE="$(echo "$?")"
            SCPOK="$(grep -ic "debug1: Exit status 0" "${LOGFILE}")"
            if [ "${SCPOK}" -gt 0 -a "${VALUE}" -eq 0 ]
            then
                SUCCESS="1"
            fi
        else
            echo "Can't determine transfer type!"
            exit "1"
        fi
        if [ "${SUCCESS}" -eq 1 ]; then
            echo "Successfully SCP connected to ${SCP_SERVER} after ${i} attempts..." >>"${LOGFILE}"
            return "0"
            break
        fi
        if [ "${i}" -eq 3 ]
        then
            echo "Can not SCP to ${SCP_SERVER} after 3 attempts"
            echo "The transfer process will terminate after ${TIME_CHK} minutes."
            echo "The SRG Lockdown process will exit after a time limit has been reached"
            RET="1"
            return "1"
        fi
    done
}

## Create the account CMacct1 if it doesn't exists
if [ "$(grep -c "^CMacct1:" /etc/passwd)" -eq 0 ]
then
    echo "Can't locate the CMacct1 account!"
    echo "Exiting..."
    exit "1"
else
    echo "Found the CMacct1 account, continuing..."
    if [ ! -s ${CMHOME}/.ssh/known_hosts.bak ]
    then
        cp ${CMHOME}/.ssh/known_hosts ${CMHOME}/.ssh/known_hosts.bak
        chown CMacct1:CMgroup ${CMHOME}/.ssh/known_hosts.bak
    fi
fi
if [ "$(grep -c "^acasscan:" /etc/passwd)" -eq 0 ]
then
    echo "Can't locate the Nessus account...creating Nessus account"
    useradd -g "2000" -u "39993" -c "Nessus Scanner" -m -d ${HOME}/acasscan acasscan
    if [ "$(grep -c "^acasscan:" /etc/shadow)" -eq 1 ]
    then
        if [ "${OSL}" = "SunOS" ]; then
            grep -v "^acasscan:" /etc/shadow >/tmp/shd.ot
            mv /tmp/shd.ot /etc/shadow
            echo 'acasscan:\$5\$eYZRfkCW\$qgmVnjU82Rj6xytGATMOewZpJCRGv7QzxW.cVa2t67.::1:365:7:::' >>/etc/shadow
            chown root:root /etc/shadow
            chmod "400" /etc/shadow
        fi
    fi
    passwd -x "365" -n "1" -w "7" acasscan
fi
if [ "${OSL}" = "Linux" ]
then
    base_files='(
        ( -type f )
        ( -name passwd -o -name shadow -o -name hosts -o -name shells -o -name skel -o -name profile
          -o -name inetd.conf -o -name ftpusers -o -name user_attr -o -name system-auth-ac -o -name hosts.allow
          -o -name hosts.deny -o -name mibs -o -name group -o -name shadow -o -name inittab -o -name password-auth-ac -o -name login.defs
          -o -name services -o -name syslog.conf -o -name logrotate.conf -o -name xinetd.conf -o -name system-auth-local
          -o -name audit.rules -o -name auditd.conf -o -name sshd_config -o -name nsswitch.conf -o -name resolv.conf
          -o -name clear-tmp -o -name aliases -o -name ntp.conf -o -name issue -o -name securetty -o -name fstab
          -o -name login.access -o -name DIR_COLORS -o -name access.conf -o -name profile -o -name xinetd -o -name sysctl.conf )
   )'
else
    base_files='(
        ( -type f )
        ( -name passwd -o -name shadow -o -name hosts -o -name shells -o -name skel -o -name profile
          -o -name inetd.conf -o -name ftpusers -o -name user_attr -o -name system -o -name hosts.allow
          -o -name hosts.deny -o -name mibs -o -name group -o -name shadow -o -name audit_control -o -name sshd_config
          -o -name ssh_config -o -name audit_warn -o -name audit_user -o -name nfs -o -name syslogd -o -name policy.conf )
   )'
fi
######################################################################
## FUNCTION: backup
## DESCRIPTION: The primary purpose of this func is to create a backup file(s)
## which contains the basic configuration files on the system. It will also
## create the logging and recovery directories if they do not exist. For Linux,
## it will also include a backup of the /etc/pam.d directory.
## RETURNS:NA
## None
## ERROR: No errors returned
## NOTES:
## MODIFICATION HISTORY: 2013-08-03
######################################################################
backup()
{
    BACKUP_DIR="/var/tmp/srg_stuff"
    LOGFILE="/var/tmp/srg_out.Log"
    if [ -s "${LOGFILE}" ]
    then
        rm "${LOGFILE}"
    fi
    if [ ! -d "${BACKUP_DIR}" ]
    then
        if [ ! -d /var/tmp ]; then
            mkdir /var/tmp
        fi
        if [ "${OSL}" != "Linux" ]; then
            PAR=""
        else
            PAR="P"
        fi
        echo "Making /var/tmp/srg_stuff dir " 1>>"${LOGFILE}"
        mkdir -p "${BACKUP_DIR}"
        echo "Making /var/tmp/srg_stuff dir/recover_dir " 1>>"${LOGFILE}"
        mkdir -p ${BACKUP_DIR}/recover_dir
    fi
    echo "archive" >/tmp/archive_file
    tar cvf ${BACKUP_DIR}/base_files.tar /tmp/archive_file
    find /etc  \
 "${base_files}"  \
 1>>/tmp/base_files
    if [ -s /tmp/base_files ]
    then
        echo "Backing up base configuration files..." 1>>"${LOGFILE}"
        if [ -f ${BACKUP_DIR}/base_files.tar ]; then
            i="0"
            while [ "${i}" -le 10 ]
            do
                if [ ! -f ${BACKUP_DIR}/base_files_${i}.tar ]; then
                    echo "Backing up ${F}" 1>>"${LOGFILE}"
                    cp ${BACKUP_DIR}/base_files.tar ${BACKUP_DIR}/base_files_${i}.tar
                    break
                fi
                i="$(expr "${i}" + "1")"
            done
        fi
        for F in "$(cat /tmp/base_files)"
        do
            echo "Backing up ${F}" 1>>"${LOGFILE}"
            tar rvf${PAR} ${BACKUP_DIR}/base_files.tar "${F}" 2>&1
        done
        echo "Base configuration file backup location: ${BACKUP_DIR}/base_files.tar" 1>>"${LOGFILE}"
        rm /tmp/base_files
    fi
    if [ -d /etc/pam.d ]
    then
        if [ ! -f ${BACKUP_DIR}/base_pam_files.tar ]; then
            echo "Backing up pam configuration files..." 1>>"${LOGFILE}"
            tar rvf${PAR} ${BACKUP_DIR}/base_pam_files.tar "${F}" 2>&1
        else
            i="0"
            while [ "${i}" -le 10 ]
            do
                if [ ! -f ${BACKUP_DIR}/base_pam_files_${i}.tar ]; then
                    cp ${BACKUP_DIR}/base_pam_files.tar ${BACKUP_DIR}/base_pam_files_${i}.tar
                    break
                fi
                i="$(expr "${i}" + "1")"
            done
            echo "Backing up pam configuration files..." 1>>"${LOGFILE}"
            tar rvf${PAR} ${BACKUP_DIR}/base_pam_files.tar /etc/pam.d 2>&1
        fi
    fi
}

######################################################################
## FUNCTION: uvscan
## DESCRIPTION: The func will create /usr/local/uvscan directory if it
## doesn't exist and depending on the OS - it will extract the latest
## uvscan engine and set the correct permissions on the uvscan directory.
## RETURNS:NA
## None
## ERROR: No errors returned
## NOTES:
## MODIFICATION HISTORY: 2013-07-11
######################################################################
check_uvscan()
{
    echo "Deploying the latest virus program files." 1>>"${LOGFILE}"
    chk_rev
    if [ ! -d /usr/local/uvscan ]
    then
        mkdir /usr/local/uvscan
    fi
    if [ "${OSL}" = "Linux" ]
    then
        FILE="uvscan_${BITS}.tar.gz"
    else
        FILE="uvscan.tar.gz"
    fi
    if [ -f /usr/local/uvscan/${FILE} ]; then
        rm /usr/local/uvscan/${FILE}
    fi
    mv "${FILE}" /usr/local/uvscan
    cp local_config.dat /usr/local/uvscan
    cp local_exclude.dat /usr/local/uvscan
    cd /usr/local/uvscan
    ${ZIP} -d "${FILE}"
    if [ "${OSL}" = "Linux" ]
    then
        if [ "$(rpm -qa | grep -i -c "McAfeeVSE")" -eq 0 ]; then
            echo "The McAfee VSE for Linux Software is not installed..." 1>>"${LOGFILE}"
            echo "Extracting uvscan_${BITS}.tar" 1>>"${LOGFILE}"
            tar xvfP uvscan_${BITS}.tar
            rm uvscan_${BITS}.tar
        else
            echo "The McAfee VSE for Linux Software is installed..." 1>>"${LOGFILE}"
        fi
    else
        echo "Extracting uvscan.tar" 1>>"${LOGFILE}"
        tar xvfp uvscan.tar
        rm uvscan.tar
    fi
    if [ -d /usr/local/uvscan ]; then
        echo "Setting root:sys permission on /usr/local/uvscan" 1>>"${LOGFILE}"
        chown -R root:sys /usr/local/uvscan
        echo "Setting 740 permissions on /usr/local/uvscan" 1>>"${LOGFILE}"
        chmod "740" /usr/local/uvscan/uvscan
    fi
    cd ${TMP}/${OSL}
}

######################################################################
## FUNCTION: reset_accounts
## DESCRIPTION: The func will check for GEN000595/GEN000760 example files
## and either reset the account to force password change at first login (GEN000595) or
## lock the account(GEN000760). It will also remove accounts that are no longer needed.
## RETURNS:NA
## None
## ERROR: No errors returned
## NOTES:
## MODIFICATION HISTORY: 2013-07-11
######################################################################
reset_accounts()
{
    cd ${TMP}/${OSL}
    if [ -s /os_srr/Script/$(uname -n)/GEN000595.Examples ]
    then
        echo "Correcting GEN000595 account entries and filtering securcert root wasadmin ihsadmin." 1>>"${LOGFILE}"
        grep "Observed" /os_srr/Script/$(uname -n)/GEN000595.Examples | awk -F"(" '{print $1}' | sed "s/[ ]*-[ ]*//g" | egrep -v "acasscan|oracle|root|wasadmin|ihsadmin|iocadmin" | sed "s/POAM- //g" | sed "s/DOCUMENTED- //g" >/var/tmp/srg_stuff/accts
        if [ -s /var/tmp/srg_stuff/accts ]; then
            for User in "$(cat /var/tmp/srg_stuff/accts)"
            do
                if [ "${OSL}" != "SunOS" ]
                then
                    if [ "$(grep -c "^${User}:" /etc/passwd)" -gt 0 ]
                    then
                        echo "Resetting account ${User} to a new password change..." 1>>"${LOGFILE}"
                        ./addusers.sh "${User}"
                    fi
                else
                    echo "Resetting account ${User} to force password change..." 1>>"${LOGFILE}"
                    perl changepass.pl "${User}"
                fi
            done
            rm /var/tmp/srg_stuff/accts
        else
            echo "Can't find any accounts to reset..." 1>>"${LOGFILE}"
        fi
    else
        echo "Couldn't locate /os_srr/Script/$(uname -n)/GEN000595.Examples" 1>>"${LOGFILE}"

    fi
    if [ -s /os_srr/Script/$(uname -n)/GEN000760.Examples ]
    then
        echo "Correcting GEN000760 account entries and filtering securcert root wasadmin ihsadmin." 1>>"${LOGFILE}"
        grep "^NONCOMPLIANT:" /os_srr/Script/$(uname -n)/GEN000760.Examples | egrep -v "acasscan|oracle|root|wasadmin|ihsadmin|iocadmin" | awk -F: '{print $2}' | awk '{print $1}' >/var/tmp/srg_stuff/lck_accts
        if [ -s /var/tmp/srg_stuff/lck_accts ]; then
            for User in "$(cat /var/tmp/srg_stuff/lck_accts)"
            do
                if [ "$(grep -c "^${User}:" /etc/passwd)" -gt 0 ]
                then
                    echo "Locking account ${User}..." 1>>"${LOGFILE}"
                    passwd -l "${User}"
                fi
            done
            rm /var/tmp/srg_stuff/lck_accts
        fi
    else
        echo "Couldn't locate /os_srr/Script/$(uname -n)/GEN000760.Examples" 1>>"${LOGFILE}"
    fi
    DEL_ACCTS="woodq tannerd smithja lovelyd richarda smithm unknown deleteme elders crowellm"
    for D in "${DEL_ACCTS}"
    do
        if [ "$(grep -c "^${D}:" /etc/passwd)" -gt 0 ]
        then
            echo "Deleting account ${D}" 1>>"${LOGFILE}"
            userdel "${D}"
        fi
        if [ -d ${HOME}/${D} ]
        then
            echo "Removing account ${D} home directory" 1>>"${LOGFILE}"
        #rm -rf ${HOME}/${D}
        fi
    done
    ## Add all of the tech support SA's accounts
    ./addusers.sh jonesd rowee andersok kelliheg handym leiferc doucettb cannong
}

update_hosts()
{
    for HOSTFILE in /etc/hosts.deny /etc/hosts.allow
    do
        if [ ! -s "${HOSTFILE}" ]
        then
            echo "ALL: ALL" >>"${HOSTFILE}"
            echo "sshd: ALL" >>"${HOSTFILE}"
        fi
        if [ "$(grep -v "^#" "${HOSTFILE}" | egrep -c "^ALL")" -eq 0 ]
        then
            echo "ALL: ALL" >>"${HOSTFILE}"
        fi
        if [ "$(grep -v "^#" "${HOSTFILE}" | egrep -c "^sshd")" -eq 0 -a "${HOSTFILE}" != "/etc/hosts.deny" ]
        then
            echo "sshd: ALL" >>"${HOSTFILE}"
        fi
    done
}

######################################################################
## FUNCTION: run_lockdown
## DESCRIPTION: Retrieves and installs the pre-installation from the central update server
## RETURNS:NA
## None
## ERROR: Returns error code 1 if can't determine FILE
## NOTES:
## MODIFICATION HISTORY: 2010-08-10
## MODIFICATION HISTORY: 2013-01-01 Removed Step Intervals
## MODIFICATION HISTORY: 2013-02-01 Renamed to run_lockdown
######################################################################
run_lockdown()
{
    TMP="/tmp/CMDB"
    validate_tmp
    locate_zip
    chk_rev
    if [ "${OSL}" = "Linux" ]
    then
        if [ "${Rel}" -eq 5 -o "${Rel}" -eq 6 ]
        then
            FILE="linux_server_build.tar.gz"
        else
            retval="1"
        fi
    elif [ "${OSL}" = "SunOS" ]
    then
        FILE="solaris_server_build.tar.gz"
    elif [ "${OSL}" = "HP-UX" ]
    then
        FILE="hp_server_build.tar.gz"
    else
        retval="1"
    fi
    if [ ! -d ${TMP}/${OSL} ]
    then
        if [ "${retval}" -eq 0 ]
        then
            if [ -f ${TMP}/${FILE} ]
            then
                rm ${TMP}/${FILE}
            fi
            backup
            echo "Attempting to retrieve the pre-installation scripts for site ${TYPE}. - SRG Lockdown.sh" 1>>"${LOGFILE}"
            srr_scp_kickstart /BL/SERVER_BUILDS/${TYPE}/${FILE} ${TMP}/${FILE} pull
            sleep "5"
            file_check
            cd "${TMP}"
            ${ZIP} -d "${FILE}"
            TAR="$(echo "${FILE}" | sed 's/\.gz//g')"
            if [ "${OSL}" = "Linux" ]
            then
                echo "Extracting lockdown bundle ${TAR} in the /tmp/CMDB directory" 1>>"${LOGFILE}"
                tar -tf "${TAR}" 1>>"${LOGFILE}"
                tar xvfP "${TAR}"
                rm "${TAR}"
            else
                echo "Extracting lockdown bundle ${TAR} in the /tmp/CMDB directory" 1>>"${LOGFILE}"
                tar -tf "${TAR}" 1>>"${LOGFILE}"
                tar xvfp "${TAR}"
                rm "${TAR}"
            fi
        else
            echo "This operating system is unsupported at this time!"
            exit "1"
        fi
    else
        echo "The ${TMP}/${OSL} directory already exists..."
    fi
    if [ "${INSTALL}" = "YES" ]
    then
        cd ${TMP}/${OSL}
        chmod "700" *.sh
        echo "BEGIN THE INITIAL SECURITY CONFIGURATION STEPS" 1>>"${LOGFILE}"
        echo "Running the lockdown scripts on ${SELF}..." 1>>"${LOGFILE}"
        echo "Incremental corrections is set to ${increment_corrections}" 1>>"${LOGFILE}"

        if [ "${OSL}" = "Linux" ]
        then
            SFTP="$(grep -v "^#" /etc/ssh/sshd_config | egrep "sftp")"
            if [ "${increment_corrections}" -eq 1 ]
            then
                linux_services
            else
                echo "Error: Incremental corrections value is not set to 1...exiting"
                exit "1"
            fi
        elif [ "${OSL}" = "HP-UX" ]
        then
            SFTP="$(grep -v "^#" /opt/ssh/etc/sshd_config | egrep "sftp")"
            if [ "${increment_corrections}" -eq 1 ]
            then
                hpux_services
            else
                echo "Error: Incremental corrections value is not set to 1...exiting"
                exit "1"
            fi
        elif [ "${OSL}" = "SunOS" ]
        then
            SFTP="$(grep -v "^#" /etc/ssh/sshd_config | egrep "sftp")"
            if [ "${increment_corrections}" -eq 1 ]
            then
                solaris_services
            else
                echo "Error: Incremental corrections value is not set to 1...exiting"
                exit "1"
            fi
        fi
        echo "END THE INITIAL SECURITY CONFIGURATION STEPS" 1>>"${LOGFILE}"
    else
        echo "The installation process was not enabled so the lockdown scripts will not be extracted." 1>>"${LOGFILE}"
        echo "The program will now exit and any changes to the system will need to be made manually." 1>>"${LOGFILE}"
        echo "${FILE} location: ${TMP}" 1>>"${LOGFILE}"
        exit "1"
    fi
}

######################################################################
## FUNCTION: locate_zip
## DESCRIPTION:
##    Determine the locate of the gzip binary
## RETURNS:
## 1. path to the gzip binary
## ERROR CHECKS:returns exit code 1 if problem occurs
## NOTES:
## MODIFICATION HISTORY: 2010-08-09
######################################################################
locate_zip()
{
    echo "Locating gzip executable  - SRG Lockdown"
    if [ "$(echo "${ZIP}" | grep -c "gzip")" -eq 0 ]
    then
        case "${OSL}" in
            'HP-UX') ZIP="/usr/contrib/bin/gzip" ;;
            'SunOS') VER="`uname -r`"
            case "${VER}" in
                5.7) ZIP="/usr/sbin/gzip" ;;
                *) ZIP="/usr/bin/gzip" ;;
            esac ;;
            *) ;;
        esac
    fi
    if [ ! -f "${ZIP}" ]
    then
        ZIP="$(find /usr -type f -perm -0100 -name gzip|head -n "1")"
        if [ -z "$ZIP" ]
        then
            echo "Unable to locate an executable gzip file"
            echo "Exiting..."
            exit "1"
        fi
    else
        echo "Found gzip location at ${ZIP} - SRG Lockdown"
    fi
}

######################################################################
## FUNCTION: validate_tmp
## DESCRIPTION: Determines the toolkit tmp directory and creates it if doesn't exists
## RETURNS:NA
## None
## ERROR: NA
## NOTES:
## MODIFICATION HISTORY: 2010-08-09
######################################################################
validate_tmp()
{
    retval="0"
    if [ ! -d "${TMP}" ]
    then
        mkdir "${TMP}"
    fi
    chmod "750" "${TMP}"
    chown CMacct1:CMgroup "${TMP}"
    if [ -s ${CMHOME}/.ssh/known_hosts.bak ]
    then
        cp ${CMHOME}/.ssh/known_hosts.bak ${CMHOME}/.ssh/known_hosts
    else
        cp ${CMHOME}/.ssh/known_hosts ${CMHOME}/.ssh/known_hosts.bak
    fi
}

######################################################################
## FUNCTION: file_check
## DESCRIPTION: Determines the toolkit tmp directory and creates it if doesn't exists
## RETURNS:NA
## None
## ERROR: NA
## NOTES:
## MODIFICATION HISTORY: 2010-08-20
######################################################################
file_check()
{
    if [ ! -f ${TMP}/${FILE} ]
    then
        INSTALL="NO"
        echo "There was problem with the retrieval of ${FILE} from ${SCP_SERVER}..." 1>>"${LOGFILE}"
        echo "Check log file /tmp/OSSRR/scp_move.sh for scp errors." 1>>"${LOGFILE}"
    else
        echo "Download of lockdown bundle ${TMP}/${FILE} was successful." 1>>"${LOGFILE}"
    fi
}

######################################################################
## FUNCTION: chk_rev
## DESCRIPTION: Determines the OS revision and sparse zone detection
## RETURNS:revision (bits)
## None
## ERROR: NA
## NOTES:
## MODIFICATION HISTORY: 2010-08-09
######################################################################
chk_rev()
{
    if [ "${OSL}" = "Linux" ]
    then
        if [ -f /etc/redhat-release ]; then
            ReleaseFile="/etc/redhat-release"
            ReleaseCount="$(grep -c "release" "${ReleaseFile}")"
            if [ "${ReleaseCount}" -ne 0 ]
            then
                ReleaseString="$(grep "release" "${ReleaseFile}")"
                DOLOOP="1"
                while [ "$(echo "${ReleaseString}" | cut -f ${DOLOOP},${DOLOOP} -d " ")" != "release" ]
                do
                    DOLOOP="$(expr "$DOLOOP" + "1")"
                    AddOne="$(expr "$DOLOOP" + "1")"
                done
                Rel="$(echo "${ReleaseString}" | cut -f ${AddOne},${AddOne} -d " ")"
                if [ "$(echo "${Rel}" | grep -c "\.")" -gt 0 ]
                then
                    ReleaseMajor="$(echo "${Rel}" | cut -f 1,1 -d ".")"
                    Rel="$ReleaseMajor"
                fi
                OSrev="$Rel"
            fi
        elif [ -f /etc/SuSE-release ]; then
            Rel="SuSE"
        fi
        if [ -f /sbin/init ]
        then
            if [ "$(file /sbin/init | grep -c "32-bit")" -eq 0 ]
            then
                BITS="x64"
            else
                BITS="x386"
            fi
        fi
    elif [ "${OSL}" = "SunOS" ]
    then
        OStype="$(uname -p)"
        if [ "${OStype}" != "sparc" ]
        then
            BITS="x386"
        else
            BITS="Sparc"
        fi
        if [ "$OSrev" = "5.10" ]
        then
            if [ "$OSrev" = "5.10" -o "$OSrev" = "5.10_x86" ]
            then
                if [ "$(/usr/sbin/zoneadm list | grep -c "global")" -gt 0 ]
                then
                    ZONE="NO"
                else
                    ZONE="YES"
                fi
            else
                ZONE="NO"
            fi
            export ZONE
        fi
        ## Perform a sparse zone test if Sun
        echo "test" >/usr/lib/test
        if [ "$(cat /usr/lib/test)" = "test" ]
        then
            SPARSE_ZONE="NO"
        else
            SPARSE_ZONE="YES"
        fi
        export SPARSE_ZONE
    fi
}

######################################################################
## FUNCTION: config_ntp_sendmail
## DESCRIPTION: Configures NTP and turns off Sendmail
## RETURNS:NA
## None
## ERROR: NA
## NOTES:
## MODIFICATION HISTORY: 2010-09-01
######################################################################
config_ntp_sendmail()
{
    if [ "${OSL}" = "Linux" -o "${OSL}" = "HP-UX" -a "${NIPR_SERVER}" = "YES" ]
    then
        echo "Creating default ntp.conf..." 1>>"${LOGFILE}"
        echo "server ${NTP_SERVER1} prefer" >/etc/ntp.conf
        echo "server ${NTP_SERVER2} prefer" >>/etc/ntp.conf
        echo "driftfile /var/tmp/driftfile" >>/etc/ntp.conf
        echo "disable monitor" >>/etc/ntp.conf
        if [ "$(crontab -l | grep -c "\/ntpdate ")" -eq 0 ]
        then
            echo "Creating default ntpdate cron entry..." 1>>"${LOGFILE}"
            echo "04,34 * * * * /bin/su - root -c '/usr/sbin/ntpdate -u -s ${NTP_SERVER1} ${NTP_SERVER2}'  > /dev/null 2>&1" >>"${CRON}"
            echo "Creating Linux default ntpdate cron entry..." 1>>"${LOGFILE}"
            echo "Restarting the ntpd service..." 1>>"${LOGFILE}"
            /sbin/service ntpd restart
        fi
    elif [ "${OSL}" = "SunOS" -a "${ZONE}" = "NO" -a "${NIPR_SERVER}" = "YES" ]
    then
        echo "Creating default ntp.conf..." 1>>"${LOGFILE}"
        echo "server ${NTP_SERVER1} prefer" >/etc/inet/ntp.conf
        echo "server ${NTP_SERVER2} prefer" >>/etc/inet/ntp.conf
        echo "driftfile /var/tmp/driftfile" >>/etc/inet/ntp.conf
        if [ "$(crontab -l | grep -c "\/ntpdate ")" -eq 0 ]
        then
            echo "Creating default ntpdate cron entry..." 1>>"${LOGFILE}"
            echo "04,34 * * * * /bin/su - root -c '/usr/sbin/ntpdate -u -s ${NTP_SERVER1} ${NTP_SERVER2}'  > /dev/null 2>&1" >>"${CRON}"
            echo "Restarting the ntpd service..." 1>>"${LOGFILE}"
            svcadm restart ntp
        fi
    elif [ "${NIPR_SERVER}" = "NO" ]
    then
        if [ "$(crontab -l | grep -c "\/ntpdate ")" -eq 0 ]
        then
            echo "04,34 * * * * /bin/su - root -c '/usr/sbin/ntpdate -u -s ${NTP_SERVER1} ${NTP_SERVER2}'  > /dev/null 2>&1" >>"${CRON}"
            /sbin/service ntpd restart
        fi
    fi
    echo "Configuring network time protocol..."
    if [ "$(grep -c "^ntp " /etc/services)" -eq 0 -a "${ZONE}" = "NO" ]
    then
        echo "ntp             123/tcp" >>/etc/services
        echo "ntp             123/udp              # Network Time Protocol" >>/etc/services
    fi
    echo "Turning off sendmail services and enabling ntp..."
    if [ "${OSL}" = "Linux" ]
    then
        /sbin/chkconfig sendmail off
        /sbin/chkconfig --levels "2345" ntpd on
        /sbin/service ntpd restart
    elif [ "${OSL}" = "SunOS" ]
    then
        svcadm disable sendmail
    fi
    chmod "644" /etc/hosts
    mv /etc/mail/submit.cf /etc/mail/no.submit.cf
    cp etc_mail_sendmail.cf.txt /etc/mail/sendmail.cf
    chmod "444" /etc/mail/sendmail.cf
    chown root /etc/mail/aliases
    chmod 0644 /etc/mail/aliases /etc/mail/aliases.db
    if [ "${OSL}" = "Linux" ]
    then
        chmod "4755" /usr/sbin/sendmail.sendmail
    elif [ "${OSL}" = "SunOS" ]
    then
        chmod "4755" /usr/lib/sendmail
    fi
    newaliases
    if [ "$(grep -c "\/usr\/lib\/sendmail \-q" "${CRON}")" -eq 0 ]
    then
        echo "0 * * * * /usr/lib/sendmail -q" >>"${CRON}"
    fi
}

######################################################################
## FUNCTION: extract_tar_files
## DESCRIPTION: Extracts some or all of the SRG conguration tar files
## RETURNS:NA
## None
## ERROR: NA
## NOTES:
## MODIFICATION HISTORY: 2013-02-01
######################################################################
extract_tar_files()
{
    echo "Extracting configuration files..." 1>>"${LOGFILE}"
    if [ "${OSL}" = "Linux" ]
    then
        for SRG in "${SRG_FILES}"
        do
            echo "Extracting ${SRG} from rhel${Rel}_config.tar" 1>>"${LOGFILE}"
            tar xvfP rhel${Rel}_config.tar "${SRG}"
        done
    elif [ "${OSL}" = "SunOS" ]
    then
        for SRG in "${SRG_FILES}"
        do
            if [ "$(echo "${SRG}" |grep -c "\/ssh")" -gt 0 ]
            then
                if [ "${OSrev}" = "5.10" ]; then
                    KERN="$(uname -v | awk -F"_" '{print $2}' | awk -F"-" '{print $1}')"
                    if [ "${KERN}" -gt 147440 ]; then
                        if [ "$(/usr/bin/showrev -p | grep -c "140905-0[0-9]")" -gt 0 ]; then
                            echo "Extracting ${SRG}..." 1>>"${LOGFILE}"
                            tar xvfp sol10_config.tar "${SRG}"
                        fi
                    else
                        echo "The kernel ${KERN} for this system does not meet the requirements for higher encryption" 1>>"${LOGFILE}"
                    fi
                elif [ "${OSrev}" = "5.11" ]; then
                    echo "Extracting ${SRG}..." 1>>"${LOGFILE}"
                    tar xvfP sol11_config.tar "${SRG}"
                else
                    echo "Invalid OS..." 1>>"${LOGFILE}"
                fi
            else
                if [ "${OSrev}" = "5.10" ]; then
                    echo "Extracting ${SRG}..." 1>>"${LOGFILE}"
                    tar xvfp sol10_config.tar "${SRG}"
                elif [ "${OSrev}" = "5.11" ]; then
                    echo "Extracting ${SRG}..." 1>>"${LOGFILE}"
                    tar xvfpP sol11_config.tar "${SRG}"
                fi
            fi
        done
    elif [ "${OSL}" = "HP-UX" ]
    then
        for SRG in "${SRG_FILES}"
        do
            echo "Extracting ${SRG}..." 1>>"${LOGFILE}"
            tar xvfp hpux31_config.tar "${SRG}"
        done
    fi
}

######################################################################
## FUNCTION: sshd_fix_sftp
## DESCRIPTION: Simple function to retrieve the existing sftp coniguration
## RETURNS:NA
## None
## ERROR: NA
## NOTES:
## MODIFICATION HISTORY: 2013-02-01
######################################################################
sshd_fix_sftp()
{
    grep -v "sftp" /etc/ssh/sshd_config >/tmp/ssh.hold
    echo "${SFTP}" 1>>/tmp/ssh.hold
    mv /tmp/ssh.hold /etc/ssh/sshd_config
}

chk_selinux()
{
    if [ -s /etc/selinux/config ]; then
        SeLinuxEnabled="$(grep "^SELINUX=" /etc/selinux/config | awk -F"=" '{print $2}' | egrep -c -i "disabled")"
    else
        SeLinuxEnabled="$(getenforce | grep -i -c "Disabled")"
    fi
    if [ "${SeLinuxEnabled}" -eq 0 ]
    then
        echo "The system has SELinux enabled - restoring selinux permissions..." 1>>"${LOGFILE}"
        for SeLinuxFile in "${SRG_FILES}"
        do
            restorecon -vvFR "${SeLinuxFile}" 1>>"${LOGFILE}"
        done
    fi
}

######################################################################
## FUNCTION: solaris_services
## DESCRIPTION: Executes commands based on the parameters given for the Solaris operating system
## RETURNS:NA
## None
## ERROR: NA
## NOTES:
## MODIFICATION HISTORY: 2013-02-01
######################################################################
solaris_services()
{
    cd ${TMP}/${OSL}
    if [ "${audit}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the audit option..." 1>>"${LOGFILE}"
        if [ "${OSrev}" = "5.10" ]; then
            SRG_FILES="/etc/security/audit_warn /etc/security/audit_user"
            extract_tar_files
            cp -p /etc/security/audit_control /etc/security/audit_control.backup
            >/etc/security/audit_control
            echo "# DISA STIG" >>/etc/security/audit_control
            echo "dir:/var/audit" >>/etc/security/audit_control
            echo "flags:fr,fd,ua,am,lo,fm,as" >>/etc/security/audit_control
            echo "minfree:20" >>/etc/security/audit_control
            echo "naflags:ua,lo" >>/etc/security/audit_control
            echo "plugin:name=/usr/lib/security/audit_syslog.so.1; p_flags=all" >>/etc/security/audit_control
            for i in audit auditconfig auditd auditreduce bsmrecord praudit
            do
                if [ -f /usr/sbin/${i} ]
                then
                    echo "Setting 750 permissions on the file /usr/sbin/${i}..." 1>>"${LOGFILE}"
                    chmod "750" /usr/sbin/${i}
                fi
            done
            echo "Setting 640 permissions on the file /etc/security/audit_user..." 1>>"${LOGFILE}"
            chmod "640" /etc/security/audit_user
            echo "Changing to root ownership on the directory /var/audit..." 1>>"${LOGFILE}"
            chown root /var/audit
            echo "Setting 750 permissions on the directory /var/audit..." 1>>"${LOGFILE}"
            chmod "750" /var/audit
            if [ "${ZONE}" = "YES" ]
            then
                echo "Restarting the auditing service..." 1>>"${LOGFILE}"
                svcadm enable auditd
            else
                echo "Restarting the auditing service..." 1>>"${LOGFILE}"
                svcadm restart auditd
            fi
        elif [ "${OSrev}" = "5.11" ]; then
            if [ ! -d /var/share ]; then
                mkdir /var/share
            fi
            if [ ! -d /var/share/audit ]; then
                mkdir /var/share/audit
            fi
            /usr/bin/pfexec audit -s
            /usr/bin/pfexec auditconfig -setflags cusa,ps,fd,-fa,fm
            /usr/bin/pfexec auditconfig -setnaflags cusa,ps,fd,-fa,fm
            /usr/bin/pfexec auditconfig -setpolicy +argv
            /usr/bin/pfexec auditconfig -setpolicy +ahlt
            /usr/bin/pfexec audit -s
            /usr/bin/pfexec auditconfig -setplugin audit_binfile p_fsize=4M
            chown root /var/share/audit
            chgrp root /var/share/audit
            chmod "640" /var/share/audit
            /usr/bin/pfexec auditconfig -setplugin audit_binfile p_minfree=2
            /usr/bin/pfexec audit -s
        fi
    fi
    cd ${TMP}/${OSL}
    if [ "${sshd}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the ssh option..." 1>>"${LOGFILE}"
        if [ "${OSrev}" = "5.10" ]; then
            SRG_FILES="/etc/ssh/sshd_config /etc/ssh/ssh_config /etc/issue"
            #SRG_FILES="/etc/ssh/ssh_config"
            extract_tar_files
            sshd_fix_sftp
            echo "Appending the allow groups option to the sshd_config" 1>>"${LOGFILE}"
            if [ "$(grep -c "^AllowGroups" /etc/ssh/sshd_config)" -eq 0 ]; then
                echo "Appending the allow groups option to the sshd_config" 1>>"${LOGFILE}"
                echo "AllowGroups disa disasa disa_sa lockheed dba CMgroup other" >>/etc/ssh/sshd_config
            elif [ "$(grep "^AllowGroups" /etc/ssh/sshd_config | grep -c "disa_sa")" -eq 0 ]; then
                grep -v "^AllowGroups" /etc/ssh/sshd_config >/tmp/ssh.ot
                mv /tmp/ssh.ot /etc/ssh/sshd_config
                echo "AllowGroups disa disasa disa_sa lockheed dba CMgroup other" >>/etc/ssh/sshd_config
            fi
            echo "Restarting the ssh service..." 1>>"${LOGFILE}"
            update_hosts
        elif [ "${OSrev}" = "5.11" ]; then
            SRG_FILES="/etc/ssh/sshd_config /etc/syslog.conf"
            extract_tar_files
            /usr/sbin/svcadm restart svc:/network/ssh
            /usr/bin/pfexec svcadm refresh system/system-log
            update_hosts
        fi
        ./solarisListenScript.sh
    fi
    cd ${TMP}/${OSL}
    if [ "${pam}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the pam option..." 1>>"${LOGFILE}"
        if [ "${OSrev}" = "5.10" ]; then
            SRG_FILES="/etc/default/su /etc/default/login /etc/default/passwd /etc/cron.d /etc/pam.conf"
            extract_tar_files
            echo "DICTIONMINWORDLENGTH=5" >>/etc/default/passwd
            /usr/bin/mkpwdict -s /usr/share/lib/dict/words
            KERN="$(uname -v | awk -F"_" '{print $2}' | awk -F"-" '{print $1}')"
            if [ "${KERN}" -gt 147440 ]; then
                cp /etc/security/policy.conf /var/tmp/srg_stuff/recover_dir/policy.conf.bak
                PWHashesVal="$(cat /etc/security/policy.conf | egrep -v "^(#|$)" | egrep CRYPT_DEFAULT | awk -F"=" '{print $2}')"
                if [ "$PWHashesVal" != 5 -o "$PWHashesVal" != 6 ]
                then
                    echo "Setting the default Crypt option to 5..." 1>>"${LOGFILE}"
                    sed "s/CRYPT_DEFAULT=${PWHashesVal}/CRYPT_DEFAULT=5/g" /etc/security/policy.conf >/tmp/crypt
                    mv /tmp/crypt /etc/security/policy.conf
                    echo "Commenting the Crypt Algorithm Allow function..." 1>>"${LOGFILE}"
                    sed "s/CRYPT_ALGORITHMS_ALLOW=/#CRYPT_ALGORITHMS_ALLOW=/g" /etc/security/policy.conf >/tmp/crypt
                    mv /tmp/crypt /etc/security/policy.conf
                    echo "CRYPT_ALGORITHMS_ALLOW=5,6" >>/etc/security/policy.conf
                    echo "Setting the Crypt Algorithm Deprecate value..." 1>>"${LOGFILE}"
                    grep -v "^CRYPT_ALGORITHMS_DEPRECATE=" /etc/security/policy.conf >/tmp/crypt
                    mv /tmp/crypt /etc/security/policy.conf
                    echo "CRYPT_ALGORITHMS_DEPRECATE=__unix__" >>/etc/security/policy.conf
                    echo "Changing ownership to root on policy.conf.." 1>>"${LOGFILE}"
                    chown root:sys /etc/security/policy.conf
                    echo "Restarting the ssh service..." 1>>"${LOGFILE}"
                    svcadm restart ssh
                    echo "Resetting account to accomodate the higher encryption algorithm..." 1>>"${LOGFILE}"
                    reset_accounts
                fi
            fi
        elif [ "${OSrev}" = "5.11" ]; then
            SRG_FILES="/etc/default/login /etc/default/passwd /etc/pam.d/gdm-autologin /etc/security/policy.conf /etc/default/keyserv /etc/proftpd.conf"
            extract_tar_files
            echo "DICTIONMINWORDLENGTH=5" >>/etc/default/passwd
            /usr/bin/pfexec pkg set-property signature-policy verify
            /usr/bin/pfexec pkg verify
            /usr/bin/pfexec pkg fix
            /usr/bin/mkpwdict -s /usr/share/lib/dict/words
            /usr/bin/pfexec cryptoadm enable fips-140
            for User in leiferc handym childsr kelliheg parrishw
            do
                if [ "$(grep -c "^${User}" /etc/user_attr)" -eq 0 ]; then
                    echo "${User}::::type=normal;roles=root" >>/etc/user_attr
                fi
            done
        fi
    fi
    cd ${TMP}/${OSL}
    if [ "${sysctl}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the sysctl option..." 1>>"${LOGFILE}"
        if [ "${OSrev}" = "5.10" ]; then
            SRG_FILES="/etc/system /etc/default/inetinit /etc/nsswitch.conf /var/sadm/install/admin/default"
            extract_tar_files
            echo "Setting permissions to 644 on the system file..." 1>>"${LOGFILE}"
            chmod "644" /etc/system
            echo "Setting ownership to root on the system file..." 1>>"${LOGFILE}"
            chown root:other /etc/system
        elif [ "${OSrev}" = "5.11" ]; then
            SRG_FILES="/etc/system /etc/net-snmp/snmp/snmpd.conf /etc/mail/aliases"
            extract_tar_files
            echo "Setting permissions to 644 on the system file..." 1>>"${LOGFILE}"
            chmod "644" /etc/system
            echo "Setting ownership to root on the system file..." 1>>"${LOGFILE}"
            chown root:other /etc/system
            /usr/bin/pfexec pkg uninstall service/network/finger
            /usr/bin/pfexec pkg uninstall service/network/legacy-remote-utilities
            /usr/bin/pfexec pkg uninstall service/network/nis
            /usr/bin/pfexec pkg uninstall communication/im/pidgin
            /usr/bin/pfexec pkg uninstall service/network/ftp
            /usr/bin/pfexec pkg uninstall service/network/tftp
            /usr/bin/pfexec pkg uninstall service/network/telnet
            /usr/bin/pfexec pkg uninstall solaris/service/network/uucp
            /usr/bin/pfexec pkg uninstall x11/server/xvnc
            /usr/sbin/svccfg -s network/rpc/bind setprop config/local_only=true
            /usr/bin/pfexec svccfg -s svc:/application/x11/x11-server setprop options/tcp_listen=false
            /usr/bin/pfexec svcadm disable svc:/network/rpc/gss
            /usr/bin/pfexec svcadm disable svc:/system/filesystem/rmvolmgr:default
            /usr/bin/pfexec svcadm disable svc:/system/console-login:terma
            /usr/bin/pfexec svcadm disable svc:/system/console-login:termb
            /usr/sbin/newaliases
        fi
    fi
    cd ${TMP}/${OSL}
    if [ "${mprobe}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        if [ "${OSrev}" = "5.10" ]; then
            echo "Executing the modprobe option..." 1>>"${LOGFILE}"
            if [ "${ZONE}" = "NO" ]
            then
                FOUND="0"
                for RC_DIR in rc2.d rc3.d
                do
                    if [ "$(grep "ndd -set" /etc/${RC_DIR}/* | wc -l)" -gt 0 ]
                    then
                        FOUND="1"
                    fi
                done
                if [ -f /etc/init.d/nddconfig -a ! -f /etc/rc2.d/S70nddconfig -a "${FOUND}" -eq 0 ]
                then
                    echo "Copying the default nddconfig to S70nddconfig in init.d..." 1>>"${LOGFILE}"
                    cp /etc/init.d/nddconfig /etc/rc2.d/S70nddconfig
                    echo "Changing to owner and group to root on S70nddconfig..." 1>>"${LOGFILE}"
                    chown root:root /etc/rc2.d/S70nddconfig
                    echo "Setting permissions to 700 on S70nddconfig..." 1>>"${LOGFILE}"
                    chmod "700" /etc/rc2.d/S70nddconfig
                fi
                ndd -set /dev/tcp tcp_conn_req_max_q0 "1280"
                ndd -set /dev/tcp tcp_conn_req_max_q "1024"
                ndd -set /dev/ip ip_respond_to_echo_broadcast "0"
                ndd -set /dev/ip ip_ignore_redirect "1"
                ndd -set /dev/ip ip_send_redirects "0"
                ndd -set /dev/ip6 ip6_ignore_redirect "1"
                ndd -set /dev/ip6 ip6_send_redirects "0"
                ndd -set /dev/ip ip6_respond_to_echo_multicast "0"
            fi
        elif [ "${OSrev}" = "5.11" ]; then
            /usr/bin/pfexec ipadm set-prop -p _forward_directed_broadcasts=0 ip
            /usr/bin/pfexec ipadm set-prop -p _respond_to_timestamp=0 ip
            /usr/bin/pfexec ipadm set-prop -p _respond_to_timestamp_broadcast=0 ip
            /usr/bin/pfexec ipadm set-prop -p _respond_to_address_mask_broadcast=0 ip
            /usr/bin/pfexec ipadm set-prop -p _respond_to_echo_broadcast=0 ip
            /usr/bin/pfexec ipadm set-prop -p _ignore_redirect=1 ipv4
            /usr/bin/pfexec ipadm set-prop -p _ignore_redirect=1 ipv6
            /usr/bin/pfexec ipadm set-prop -p _strict_dst_multihoming=1 ipv4
            /usr/bin/pfexec ipadm set-prop -p _strict_dst_multihoming=1 ipv6
            /usr/bin/pfexec ipadm set-prop -p _rev_src_routes=0 tcp
            /usr/bin/pfexec ipadm set-prop -p _conn_req_max_q=1024 tcp
            /usr/bin/pfexec ipadm set-prop -p _conn_req_max_q0=4096 tcp
            /usr/bin/pfexec ipadm set-prop -p _respond_to_echo_multicast=0 ipv6
            /usr/bin/pfexec ipadm set-prop -p _respond_to_echo_multicast=0 ipv4
        fi
    fi
    cd ${TMP}/${OSL}
    if [ "${ntp}" -eq 1 -a "${ZONE}" = "NO" ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the ntp option..." 1>>"${LOGFILE}"
        if [ "${OSrev}" = "5.10" ]; then
            SRG_FILES="/etc/inet/ntp.conf"
            extract_tar_files
            echo "Setting permissions to 640 on the ntp.conf file..." 1>>"${LOGFILE}"
            chmod "640" /etc/inet/ntp.conf
            if [ "$(crontab -l | grep -c "\/ntpdate ")" -eq 0 ]
            then
                echo "Appending the cron entry for ntp..." 1>>"${LOGFILE}"
                echo "04,34 * * * * /bin/su - root -c '/usr/sbin/ntpdate -u -s ${NTP_SERVER1} ${NTP_SERVER2}'  > /dev/null 2>&1" >>"${CRON}"
                echo "Restarting the ntp service..." 1>>"${LOGFILE}"
                svcadm restart ntp
            fi
            if [ "$(svcs ntp | grep -c "online")" -eq 0 ]
            then
                echo "The ntp service is offline - Restarting the ntp service..." 1>>"${LOGFILE}"
                svcadm enable ntp
            fi
            NTP_FILES="/etc/news/hosts.nntp /etc/news/hosts.nntp.nolimit /etc/news/passwd.nntp"
            for FILE in "${NTP_FILES}"
            do
                if [ -f "${FILE}" ]
                then
                    echo "Setting permissions to 600 on ${FILE}..." 1>>"${LOGFILE}"
                    chmod "600" "${FILE}"
                fi
            done
        elif [ "${OSrev}" = "5.11" ]; then
            echo "Solaris 11 NTP configuration ...." 1>>"${LOGFILE}"
        fi
    fi
    cd ${TMP}/${OSL}
    if [ "${ldap}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the ldap option..." 1>>"${LOGFILE}"
        echo "Removing the ldap entry in the nsswitch.conf file..." 1>>"${LOGFILE}"
        if [ "$(cat /etc/nsswitch.conf | egrep -v "^[ ]*#" | egrep -c "ldap")" -eq 1 ]; then
            perl -npe 's/ldap//g' -i /etc/nsswitch.conf;
        fi
    fi
    cd ${TMP}/${OSL}
    if [ "${selfhealing}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing commands to remediate additional findings..." 1>>"${LOGFILE}"
        echo "Executing the selfhealing option..." 1>>"${LOGFILE}"
        echo "Running the IAVM validation process..." 1>>"${LOGFILE}"
        ./lb.sh 1>>"${LOGFILE}"
        if [ "$(grep -c ":O$" /var/tmp/srg_stuff/binaries)" -gt 0 ]; then
            echo "These are open IAVMs found..." 1>>"${LOGFILE}"
            grep ":O$" /var/tmp/srg_stuff/binaries >>"${LOGFILE}"
        fi
        if [ "${OSrev}" = "5.10" ]; then
            cd ${TMP}/${OSL}
            echo "Executing the account creation job..." 1>>"${LOGFILE}"
            if [ -x addusers.sh ]; then
                ./addusers.sh acasscan andersok kelliheg handym leiferc doucettb cannong
                for i in andersok kelliheg handym leiferc doucettb cannong
                do
                    ./changepass.pl "${i}"
                done
            fi
            #echo "Correcting Tivoli port issue for retina scan..." 1>>${LOG_FILE}
            #./stat_tivoli.sh 1>>${LOG_FILE}
            echo "Running the SRG stig lockdown with self healing enabled..." 1>>"${LOGFILE}"
            ./run_SRG.sh ALL 2>/dev/null 1>>/var/tmp/srg_out.Log
        #echo "Converting the status codes SRG findings in the manual review file..." 1>>${LOG_FILE}
        #./srg_man_convert.sh 1>>${LOG_FILE}
        #echo "Correcting coreadm -e global VMS findings" 1>>${LOG_FILE}
        #/usr/bin/coreadm -e global -g /var/core/core_%n_%f_%u_%g_%t_%p
        elif [ "${OSrev}" = "5.11" ]; then
            cd ${TMP}/${OSL}
            useradd -D -f "35"
            ## Add all of the tech support SA's accounts
            echo "Executing the account creation job..." 1>>"${LOGFILE}"
            if [ -x addusers.sh ]; then
                ./addusers.sh acasscan andersok kelliheg handym leiferc doucettb cannong
                for i in andersok kelliheg handym leiferc doucettb cannong
                do
                    ./changepass.pl "${i}"
                    /usr/sbin/usermod -f "35" "${i}"
                done
            fi
            cp ipf.conf /etc/ipf/ipf.conf
            coreadm -d global
            coreadm -d process
            coreadm -d global-setid
            coreadm -d proc-setid
            coreadm -d log
            dumpadm -n
            /usr/bin/pfexec zfs set compression=on
            /usr/bin/pfexec zfs set quota=20G rpool/VARSHARE
            /usr/bin/pfexec zfs set reservation=15G rpool/VARSHARE
            chmod "700" /var/share/cores
            chown root:root /var/share/cores
            /usr/sbin/ipf -Fa -A -f /etc/ipf/ipf.conf
            /usr/sbin/svcadm enable ipfilter
        fi
        sleep "10"
        if [ "${OSrev}" = "5.10" ]; then
            if [ -f /usr/sbin/snoop ]
            then
                echo "Removing the file snoop..." 1>>"${LOGFILE}"
                rm /usr/sbin/snoop
            fi
            echo "Removing global world writable permissions on the Tivoli installation direcoties..." 1>>"${LOGFILE}"
            chmod -R o-w /opt/IBM/ITM
            chmod -R o-w /var/tmp/itm
            chmod -R o-w /opt/McAfee/hip
            chmod "555" /usr/sbin/rpcbind
            chmod "644" /var/adm/spellhist
            cp ipf.conf /etc/ipf/ipf.conf
            check_uvscan
        elif [ "${OSrev}" = "5.11" ]; then
            chmod "640" /var/adm/messages
            chown root /var/adm/messages
            chgrp root /var/adm/messages
            chmod "750" /var/adm
            chown root /var/adm
            chgrp sys /var/adm
            chmod "700" /var/crash
            chown root:root /var/crash
            check_uvscan
        fi
        cd ${TMP}/${OSL}
        if [ -x SunOS_${OSrev}_healing.sh ]; then
            echo "Executing extending self-healing script SunOS_${OSrev}_healing.sh..." 1>>"${LOGFILE}"
            ./SunOS_${OSrev}_healing.sh
        fi
    fi
    ./install_scripts.sh 1>>"${LOGFILE}"
    echo "Executing the SRR Baseline SUID SGUID find..." 1>>"${LOGFILE}"
    /os_srr/UNIX/baseline_suid_sgid.sh
}

######################################################################
## FUNCTION: linux_services
## DESCRIPTION: Executes commands based on the parameters given for the Linux operating system
## RETURNS:NA
## None
## ERROR: NA
## NOTES:
## MODIFICATION HISTORY: 2013-02-01
######################################################################
linux_services()
{
    cd ${TMP}/${OSL}
    if [ "${audit}" -eq 1 ]
    then
        CHECK="0"
        SERVICE=""
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the audit option..." 1>>"${LOGFILE}"
        if [ "${Rel}" = "6" -o "${Rel}" = "7" ]; then
            SRG_FILES="/etc/rsyslog.conf"
            extract_tar_files
        fi
        for i in rsyslog syslog
        do
            if [ "$(grep -c "\.none" /etc/${i}.conf)" -gt 0 -a "$(grep -i -c "local3" /etc/${i}.conf)" -eq 0 ]; then
                CHECK="1"
                perl -pi -e 's/^(.*none\w*)\s+\/var\/log\/messages/$1;local3.none\t\t\/var\/log\/messages/' /etc/${i}.conf
                /sbin/service "${i}" status 1>/tmp/a 2>&1
                if [ "$(grep -c "unrecognized service" /tmp/a)" -eq 0 ]; then
                    SERVICE="${i}"
                fi
            fi
        done
        if [ "${CHECK}" -eq 1 ]; then
            SRG_FILES="/etc/audisp/plugins.d/syslog.conf"
            extract_tar_files
        fi
        for i in auditctl audispd auditd aureport ausearch autrace
        do
            if [ -f /sbin/${i} ]
            then
                echo "Setting 750 permission on auditing file /sbin/${i}" 1>>"${LOGFILE}"
                chmod "750" /sbin/${i}
            fi
        done
        chk_selinux
        echo "Restarting the auditing service..." 1>>"${LOGFILE}"
        if [ "${Rel}" = "7" ]; then
            ./audit7Fix.sh
        fi
        if [ "${Rel}" = "6" ]; then
            ./auditFix.sh
        fi
        if [ "${Rel}" = "5" ]; then
            ./audit5Fix.sh
        fi
        /sbin/service auditd restart
    fi
    cd ${TMP}/${OSL}
    if [ "${sshd}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the ssh option..." 1>>"${LOGFILE}"
        SRG_FILES="/etc/ssh/sshd_config /etc/ssh/ssh_config /etc/issue "
        extract_tar_files
        if [ "$(grep "^UsePAM" /etc/ssh/sshd_config | grep -i -c 'no')" -gt 0 ]
        then
            echo "Adding the UsePAM option to the sshd_config file..." 1>>"${LOGFILE}"
            grep -v "UsePAM" /etc/ssh/sshd_config >/tmp/ssh.ot
            mv /tmp/ssh.ot /etc/ssh/sshd_config
            echo "UsePAM  yes" >>/etc/ssh/sshd_config
        elif [ "$(grep -c "^UsePAM" /etc/ssh/sshd_config)" -eq 0 ]
        then
            echo "Adding the UsePAM option to the sshd_config file..." 1>>"${LOGFILE}"
            echo "UsePAM	yes" >>/etc/ssh/sshd_config
        fi
        if [ "${Rel}" = "5" -o "${Rel}" = "6" -o "${Rel}" = "7" ]
        then
            if [ "$(grep -c "^AllowGroups" /etc/ssh/sshd_config)" -eq 0 ]; then
                echo "Appending the allow groups option to the sshd_config" 1>>"${LOGFILE}"
                echo "AllowGroups disa disasa disa_sa lockheed dba CMgroup other" >>/etc/ssh/sshd_config
            elif [ "$(grep "^AllowGroups" /etc/ssh/sshd_config | grep -c "disa_sa")" -eq 0 ]; then
                grep -v "^AllowGroups" /etc/ssh/sshd_config >/tmp/ssh.ot
                mv /tmp/ssh.ot /etc/ssh/sshd_config
                echo "AllowGroups disa disasa disa_sa lockheed dba CMgroup other" >>/etc/ssh/sshd_config
            fi
        fi
        sshd_fix_sftp
        chk_selinux
        echo "Restarting the ssh service..." 1>>"${LOGFILE}"
        grep -v "^ListenAddress " /etc/ssh/sshd_config >/tmp/a
        mv /tmp/a /etc/ssh/sshd_config
        ./linuxListenScript.sh
        update_hosts
    fi
    cd ${TMP}/${OSL}
    if [ "${pam}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the pam option..." 1>>"${LOGFILE}"
        if [ -s /etc/pam.d/system-auth-local ]; then
            rm /etc/pam.d/system-auth-local
        fi
        if [ -s /etc/pam.d/password-auth-local ]; then
            rm /etc/pam.d/password-auth-local
        fi
        if [ "$(grep "^UsePAM" /etc/ssh/sshd_config | grep -i -c 'no')" -gt 0 ]
        then
            echo "Adding the UsePAM option to the sshd_config file..." 1>>"${LOGFILE}"
            grep -v "UsePAM" /etc/ssh/sshd_config >/tmp/ssh.ot
            mv /tmp/ssh.ot /etc/ssh/sshd_config
            echo "UsePAM  yes" >>/etc/ssh/sshd_config
            service sshd restart
        elif [ "$(grep -c "^UsePAM" /etc/ssh/sshd_config)" -eq 0 ]
        then
            echo "Adding the UsePAM option to the sshd_config file..." 1>>"${LOGFILE}"
            echo "UsePAM	yes" >>/etc/ssh/sshd_config
            service sshd restart
        fi
        if [ "$(grep "^MaxAuthTries" /etc/ssh/sshd_config | grep -i -c "3")" -eq 0 ]
        then
            echo "Adding the MaxAuthTries option to the sshd_config file..." 1>>"${LOGFILE}"
            grep -v "MaxAuthTries" /etc/ssh/sshd_config >/tmp/ssh.ot
            mv /tmp/ssh.ot /etc/ssh/sshd_config
            echo "MaxAuthTries  3" >>/etc/ssh/sshd_config
            service sshd restart
        elif [ "$(grep -c "^MaxAuthTries" /etc/ssh/sshd_config)" -eq 0 ]
        then
            echo "Adding the MaxAuthTries option to the sshd_config file..." 1>>"${LOGFILE}"
            echo "MaxAuthTries	3" >>/etc/ssh/sshd_config
            service sshd restart
        fi
        if [ "${Rel}" = "6" ]
        then
            SRG_FILES="/etc/cron.allow /etc/cron.deny /etc/csh.cshrc /etc/pam.d/system-auth-local /etc/pam.d/password-auth-local /etc/login.defs /etc/profile"
        elif [ "${Rel}" = "7" ]
        then
            SRG_FILES="/etc/profile /etc/login.defs /etc/security/pwquality.conf /etc/cron.allow /etc/cron.deny /etc/csh.cshrc /etc/pam.d/system-auth-local /etc/pam.d/password-auth-local /etc/pam_pkcs11/pam_pkcs11.conf /etc/wpa_supplicant/wpa_supplicant.conf /etc/wpa_supplicant/wpa_supplicant.conf"
        else
            SRG_FILES="/etc/pam.d/sshd /etc/cron.allow /etc/cron.deny /etc/pam.d/system-auth-local /etc/pam.d/halt /etc/pam.d/eject /etc/pam.d/poweroff /etc/pam.d/reboot"
        fi
        extract_tar_files
        echo "Creating a symbolic links to system-auth-local and password-auth-local..." 1>>"${LOGFILE}"
        if [ "${Rel}" = "6" -i "${Rel}" = "7" ]; then
            if [ -L /etc/pam.d/system-auth ]
            then
                cd /etc/pam.d
                rm system-auth
                ln -sf system-auth-local system-auth
                chmod "644" system-auth-local
            else
                cd /etc/pam.d
                ln -sf system-auth-local system-auth
                chmod "644" system-auth-local
            fi
            if [ -L /etc/pam.d/password-auth ]
            then
                cd /etc/pam.d
                rm password-auth
                ln -sf password-auth-local password-auth
                chmod "644" password-auth-local
            else
                cd /etc/pam.d
                ln -sf password-auth-local password-auth
                chmod "644" password-auth-local
            fi
        fi
        if [ "${Rel}" = "5" ]; then
            if [ -s /etc/pam.d/system-auth-local ]
            then
                cd /etc/pam.d
                ln -sf system-auth-local system-auth
                chmod "644" system-auth-local
            else
                cd /etc/pam.d
                cp system-auth-ac system-auth-local
                ln -sf system-auth-local system-auth
                chmod "644" system-auth-local
            fi
        fi
        echo "Resetting account to accomodate the higher encryption algorithm..." 1>>"${LOGFILE}"
        cd ${TMP}/${OSL}
        reset_accounts
        chk_selinux
    fi
    cd ${TMP}/${OSL}
    if [ "${sysctl}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the sysctl option..." 1>>"${LOGFILE}"
        if [ "${Rel}" = "6" ]
        then
            SRG_FILES="/etc/sysctl.conf"
            extract_tar_files
        else
            SRG_FILES="/etc/sysctl.conf"
            extract_tar_files
        fi
        echo "Setting permissions to 600 on the sysctl.conf file..." 1>>"${LOGFILE}"
        chmod "600" /etc/sysctl.conf
        chk_selinux
    fi
    cd ${TMP}/${OSL}
    if [ "${mprobe}" -eq 1 -a "${Rel}" = "5" ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the Red Hat 5 modprobe option..." 1>>"${LOGFILE}"
        SRG_FILES="/etc/modprobe.conf"
        if [ "$(egrep -c "^[ ]*install[ ]+sctp[ ]+/bin/true" /etc/modprobe.conf)" -eq 0 ]; then
            echo "install sctp /bin/true" >>/etc/modprobe.conf;
        fi
        if [ "$(egrep -c "^[ ]*install[ ]+dccp[ ]+/bin/true" /etc/modprobe.conf)" -eq 0 ]; then
            echo "install dccp /bin/true" >>/etc/modprobe.conf;
        fi
        if [ "$(egrep -c "^[ ]*install[ ]+dccp_ipv4[ ]+/bin/true" /etc/modprobe.conf)" -eq 0 ]; then
            echo "install dccp_ipv4 /bin/true" >>/etc/modprobe.conf;
        fi
        if [ "$(egrep -c "^[ ]*install[ ]+dccp_ipv6[ ]+/bin/true" /etc/modprobe.conf)" -eq 0 ]; then
            echo "install dccp_ipv6 /bin/true" >>/etc/modprobe.conf;
        fi
        if [ "$(egrep -c "^[ ]*install[ ]+rds[ ]+/bin/true" /etc/modprobe.conf)" -eq 0 ]; then
            echo "install rds /bin/true" >>/etc/modprobe.conf;
        fi
        if [ "$(egrep -c "^[ ]*install[ ]+tipc[ ]+/bin/true" /etc/modprobe.conf)" -eq 0 ]; then
            echo "install tipc /bin/true" >>/etc/modprobe.conf;
        fi
        if [ "$(egrep -c "^install[ &#x9;]+bluetooth[ &#x9;]+\/bin\/true$" /etc/modprobe.conf)" -eq 0 ]; then
            echo "install bluetooth /bin/true" >>/etc/modprobe.conf;
        fi
        if [ "$(egrep -c "^[ ]*install[ ]+ipv6[ ]+/bin/true" /etc/modprobe.conf)" -eq 0 ]; then
            echo "install ipv6 /bin/true" >>/etc/modprobe.conf;
        fi
        if [ "$(egrep -c "^[ ]*install[ ]+usb-storage[ ]+/bin/true" /etc/modprobe.conf)" -eq 0 ]; then
            echo "install usb-storage /bin/true" >>/etc/modprobe.conf;
        fi
        if [ "$(egrep -c "^[ ]*install[ ]+ieee1394[ ]+/bin/true" /etc/modprobe.conf)" -eq 0 ]; then
            echo "install ieee1394 /bin/true" >>/etc/modprobe.conf;
        fi
        if [ "$(egrep -c "^[ ]*install[ ]+appletalk[ ]+/bin/true" /etc/modprobe.conf)" -eq 0 ]; then
            echo "install appletalk /bin/true" >>/etc/modprobe.conf;
        fi
    elif [ "${mprobe}" -eq 1 -a "${Rel}" = "6" ]
    then
        echo "Executing the Red Hat 6 modprobe option..." 1>>"${LOGFILE}"
        if [ -s /etc/modprobe.d/stig-items.conf ]
        then
            SRG_FILES="/etc/modprobe.d/stig-items.conf"
            if [ ! -f /etc/modprobe.d/bonding.conf ]; then
                if [ "$(egrep -c "^[ ]*install[ ]+ipv6[ ]+/bin/false" /etc/modprobe.d/stig-items.conf)" -eq 0 ]; then
                    echo "install ipv6 /bin/false" >>/etc/modprobe.d/stig-items.conf;
                fi
            fi
            if [ "$(egrep -c "^[ ]*install[ ]+sctp[ ]+/bin/true" /etc/modprobe.d/stig-items.conf)" -eq 0 ]; then
                echo "install sctp /bin/true" >>/etc/modprobe.d/stig-items.conf;
            fi
            if [ "$(egrep -c "^[ ]*install[ ]+dccp[ ]+/bin/true" /etc/modprobe.d/stig-items.conf)" -eq 0 ]; then
                echo "install dccp /bin/true" >>/etc/modprobe.d/stig-items.conf;
            fi
            if [ "$(egrep -c "^[ ]*install[ ]+rds[ ]+/bin/true" /etc/modprobe.d/stig-items.conf)" -eq 0 ]; then
                echo "install rds /bin/true" >>/etc/modprobe.d/stig-items.conf;
            fi
            if [ "$(egrep -c "^[ ]*install[ ]+tipc[ ]+/bin/true" /etc/modprobe.d/stig-items.conf)" -eq 0 ]; then
                echo "install tipc /bin/true" >>/etc/modprobe.d/stig-items.conf;
            fi
            if [ "$(egrep -c "^install[ &#x9;]+bluetooth[ &#x9;]+\/bin\/true$" /etc/modprobe.d/stig-items.conf)" -eq 0 ]; then
                echo "install bluetooth /bin/true" >>/etc/modprobe.d/stig-items.conf;
            fi
            if [ "$(egrep -c "^[ ]*install[ ]+usb-storage[ ]+/bin/true" /etc/modprobe.d/stig-items.conf)" -eq 0 ]; then
                echo "install usb-storage /bin/true" >>/etc/modprobe.d/stig-items.conf;
            fi
            if [ "$(egrep -c "^[ ]*install[ ]+ieee1394[ ]+/bin/true" /etc/modprobe.d/stig-items.conf)" -eq 0 ]; then
                echo "install ieee1394 /bin/true" >>/etc/modprobe.d/stig-items.conf;
            fi
        else
            echo "Executing the Red Hat 6 modprobe option..." 1>>"${LOGFILE}"
            if [ ! -f /etc/modprobe.d/bonding.conf ]
            then
                echo "install ipv6 /bin/true" >>/etc/modprobe.d/stig-items.conf
            fi
            echo "install sctp /bin/true" >>/etc/modprobe.d/stig-items.conf
            echo "install dccp /bin/true" >>/etc/modprobe.d/stig-items.conf
            echo "install rds /bin/true" >>/etc/modprobe.d/stig-items.conf
            echo "install tipc /bin/true" >>/etc/modprobe.d/stig-items.conf
            echo "install bluetooth /bin/true" >>/etc/modprobe.d/stig-items.conf
            echo "install usb-storage /bin/true" >>/etc/modprobe.d/stig-items.conf
            echo "install ieee1394 /bin/true" >>/etc/modprobe.d/stig-items.conf
            echo "options ipv6 disable=1" >>/etc/modprobe.d/stig-items.conf
            echo "install net-pf-31 /bin/true" >>/etc/modprobe.d/stig-items.conf
        fi
    elif [ "${mprobe}" -eq 1 -a "${Rel}" = "7" ]
    then
        SRG_FILES="/etc/modprobe.d/blacklist /etc/modprobe.d/50-blacklist.conf /etc/libuser.conf"
        chk_selinux
    fi
    cd ${TMP}/${OSL}
    if [ "${ntp}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the ntp option..." 1>>"${LOGFILE}"
        config_ntp_sendmail
        chk_selinux
    fi
    cd ${TMP}/${OSL}
    if [ "${ldap}" -eq 1 -a ! -f /var/run/openldap/slapd.pid ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the ldap option..." 1>>"${LOGFILE}"
        echo "Removing the ldap entry in the nsswitch.conf file..." 1>>"${LOGFILE}"
        if [[ "$(cat /etc/nsswitch.conf | egrep -v "^[ ]*#" | egrep -c "ldap")" -eq 1 ]]; then
            perl -npe 's/ldap//g' -i /etc/nsswitch.conf;
        fi
        if [ "$(rpm -q openldap-servers | grep -c "is not installed")" -eq 0 ]; then
            echo "Removing the OPENLDAP RPM Package..."
            /sbin/rpm -e --nodeps openldap-servers
        fi
    fi
    cd ${TMP}/${OSL}
    if [ "${selfhealing}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the selfhealing option..." 1>>"${LOGFILE}"
        echo "Running GEN000595 and GEN000760 to correct account encryption and password expirations..." 1>>"${LOGFILE}"
        echo "Running any existing SRR healing scripts..." 1>>"${LOGFILE}"
        echo "Running the IAVM validation process..." 1>>"${LOGFILE}"
        #./lb.sh 1>>${LOG_FILE}
        #if [ `grep -c ":O:" /var/tmp/srg_stuff/binaries` -gt 0 ]; then
        # 	echo "These are open IAVMs found..." 1>>${LOG_FILE}
        # 	grep ":O:" /var/tmp/srg_stuff/binaries >> ${LOG_FILE}
        # fi
        echo "Running the SRG stig lockdown - self healing enabled..." 1>>"${LOGFILE}"
        ./run_SRG.sh ALL 2>/dev/null 1>>/var/tmp/srg_out.Log
        echo "Correcting Tivoli port issue for retina scan..." 1>>"${LOGFILE}"
    #./stat_tivoli.sh 1>>${LOG_FILE}
    fi
    cd ${TMP}/${OSL}
    echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
    if [ "${selfhealing}" -eq 1 ]
    then
        echo "Executing extra commands to remediate additional findings..." 1>>"${LOGFILE}"
        if [ -s /etc/shells ]
        then
            grep -v "\/usr\/bin\/bash" /etc/shells >/tmp/pdfile
            mv /tmp/pdfile /etc/shells
        fi
        if [ "$(grep -c "^nails:" /etc/passwd)" -gt 0 ]; then
            echo "Setting the default login for user nails to noglogin..." 1>>"${LOGFILE}"
            usermod -s /sbin/nologin nails
        fi
        echo "Removing global world writable permissions on the Tivoli installation direcoties..." 1>>"${LOGFILE}"
        #chmod -R o-w /opt/IBM/ITM
        #chmod -R o-w /var/tmp/itm
        #chmod -R o-w /opt/McAfee/hip
        chmod o-w /opt/bmc/BladeLogic/8.1/NSH/Transactions/*
        if [ -f /toolkits/db/ora/config/exemptions-SMC ]
        then
            chown root:root /toolkits/db/ora/config/exemptions-SMC
        fi
        chmod "640" /var/log/rpmpkgs*
        echo "Setting permissions 600 and 700 on etc crontab files..." 1>>"${LOGFILE}"
        if [ "${Rel}" = "5" -o "${Rel}" = "6" ]
        then
            chmod "600" /etc/cron.d/*
            chmod "600" /etc/crontab
            chmod "700" /etc/cron.daily/*
            chmod "700" /etc/cron.hourly/*
            chmod "700" /etc/cron.monthly/*
            chmod "700" /etc/cron.weekly/*
        fi
        #if [[ -e /etc/gdm/custom.conf && `egrep -c "command=/usr/bin/Xorg -br -audit 4 -s 15" /etc/gdm/custom.conf` -eq 0 ]]; then echo -e "[server-Standard]\nname=Standard server\ncommand=/usr/bin/Xorg -br -audit 4 -s 15\nchooser=false\nhandled=true\nflexible=true\npriority=0" >> /etc/gdm/custom.conf; /usr/sbin/gdm-restart; fi
        echo "Setting permission 600 on the securetty file..." 1>>"${LOGFILE}"
        chmod "600" /etc/securetty
        #chmod 600 /var/log/boot.log
        #pwconv
        echo "Setting permission to 755 on the ldd command..." 1>>"${LOGFILE}"
        #/bin/chmod 755 /usr/bin/ldd
        chmod o-w /opt/bmc/BladeLogic/8.1/NSH/Transactions/*
        echo "Removing all ACL permissions from the gdm log directory..." 1>>"${LOGFILE}"
        #setfacl --remove-all /var/log/gdm
        if [ ! -f /etc/dhclient.conf ]
        then
            echo "Appending do-forward-updates false to the dhclient.conf" 1>>"${LOGFILE}"
            echo "do-forward-updates false;" >>/etc/dhclient.conf
        fi
        ./install_scripts.sh 1>>"${LOGFILE}"
    fi
    cd ${TMP}/${OSL}
    #check_uvscan
    #config_ntp_sendmail
    #post_install
    echo "Executing the SRR Baseline SUID SGUID find..." 1>>"${LOGFILE}"
    /os_srr/UNIX/baseline_suid_sgid.sh
}

######################################################################
## FUNCTION: hpux_services
## DESCRIPTION: Executes commands based on the parameters given for the Linux operating system
## RETURNS:NA
## None
## ERROR: NA
## NOTES:
## MODIFICATION HISTORY: 2013-07-03
######################################################################
hpux_services()
{
    cd ${TMP}/${OSL}
    if [ "${audit}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the audit option..." 1>>"${LOGFILE}"
        SRG_FILES="/etc/rc.config.d/auditing /etc/audit/audnames /toolkits/audit/xfer_audit_logs.sh"
        extract_tar_files
        touch /tmp/audit.err
        echo "Restarting the auditing service..." 1>>"${LOGFILE}"
        /sbin/init.d/auditing stop
        /sbin/init.d/auditing start
    fi
    cd ${TMP}/${OSL}
    if [ "${sshd}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the ssh option..." 1>>"${LOGFILE}"
        SRG_FILES="/opt/ssh/etc/sshd_config /opt/ssh/etc/ssh_config /etc/issue"
        extract_tar_files
        echo "Appending the allow groups option to the sshd_config" 1>>"${LOGFILE}"
        echo "AllowGroups disa disasa disa_sa lockheed dba CMgroup other disa_sa" >>/opt/ssh/etc/sshd_config
        sshd_fix_sftp
        echo "Restarting the ssh service..." 1>>"${LOGFILE}"
        /sbin/init.d/secsh stop
        /sbin/init.d/secsh start
        update_hosts
    fi
    cd ${TMP}/${OSL}
    if [ "${sysctl}" -eq 1 ]
    then
        if [ ! -s /etc/default/security ]; then
            SRG_FILES="/etc/default/security"
            extract_tar_files
        fi
    fi
    cd ${TMP}/${OSL}
    if [ "${ntp}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the ntp option..." 1>>"${LOGFILE}"
        SRG_FILES="/etc/ntp.conf"
        extract_tar_files
        if [ "$(crontab -l | grep -c "\/ntpdate ")" -eq 0 ]
        then
            echo "Appending the cron entry for ntp..." 1>>"${LOGFILE}"
            echo "04,34 * * * * /bin/su - root -c '/usr/sbin/ntpdate -u -s ${NTP_SERVER1} ${NTP_SERVER2}'  > /dev/null 2>&1" >>"${CRON}"
            echo "Restarting the ntp service..." 1>>"${LOGFILE}"
            /sbin/service ntpd restart
        fi
    fi
    cd ${TMP}/${OSL}
    if [ "${ldap}" -eq 1 -a ! -f /var/run/openldap/slapd.pid ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the ldap option..." 1>>"${LOGFILE}"
        echo "Removing the ldap entry in the nsswitch.conf file..." 1>>"${LOGFILE}"
        if [[ "$(cat /etc/nsswitch.conf | egrep -v "^[ ]*#" | egrep -c "ldap")" -eq 1 ]]; then
            perl -npe 's/ldap//g' -i /etc/nsswitch.conf;
        fi
    fi
    cd ${TMP}/${OSL}
    if [ "${selfhealing}" -eq 1 ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing the selfhealing option..." 1>>"${LOGFILE}"
        echo "Running GEN000595 and GEN000760 to correct account encryption and password expirations..." 1>>"${LOGFILE}"
        echo "Running any existing SRR healing scripts..." 1>>"${LOGFILE}"
        #./pdi_fix.sh 1>>${LOG_FILE}
        reset_accounts
        echo "Running the IAVM validation process..." 1>>"${LOGFILE}"
        ./lb.sh 1>>"${LOGFILE}"
        echo "Running the SRG stig lockdown - self healing enabled..." 1>>"${LOGFILE}"
        ./run_SRG.sh ALL 2>/dev/null 1>>/var/tmp/srg_out.Log
        echo "Converting the status codes SRG findings in the manual review file..." 1>>"${LOGFILE}"
        echo "Correcting Tivoli port issue for retina scan..." 1>>"${LOGFILE}"
    #./stat_tivoli.sh 1>>${LOG_FILE}
    #./install_scripts.sh 1>>${LOG_FILE}
    fi
    cd ${TMP}/${OSL}
    echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
    echo "Executing commands to remediate additional findings..." 1>>"${LOGFILE}"
    if [ -f /toolkits/db/ora/config/exemptions-SMC ]
    then
        echo "Setting root:root on the exemptions-SMC file..." 1>>"${LOGFILE}"
        chown root:root /toolkits/db/ora/config/exemptions-SMC
    fi
    cd /tmp/CMDB/${OSL}
    check_uvscan
    chmod o-w /opt/bmc/BladeLogic/8.1/NSH/Transactions/*
    echo "Removing global world writable permissions on the Tivoli installation direcoties..." 1>>"${LOGFILE}"
    chmod -R o-w /opt/IBM/ITM/config
    chmod -R o-w /opt/McAfee/hip
    echo "Executing the SRR Baseline SUID SGUID find..." 1>>"${LOGFILE}"
    /os_srr/UNIX/baseline_suid_sgid.sh
}

######################################################################
## FUNCTION: post_install
## DESCRIPTION: installs the post-installation procedures
## RETURNS:NA
## None
## ERROR: NA
## NOTES:
## MODIFICATION HISTORY: 2010-08-10
## MODIFICATION HISTORY: 2013-01-04
######################################################################
post_install()
{
    if [ "${INSTALL}" = "YES" ]
    then
        echo "-----------------------------------------------------------------------------------" 1>>"${LOGFILE}"
        echo "Executing post install procedures..." 1>>"${LOGFILE}"
        TMP="/tmp/CMDB"
        validate_tmp
        if [ ! -d /usr/local/uvscan ]
        then
            echo "Creating the default uvscan directory..." 1>>"${LOGFILE}"
            mkdir /usr/local/uvscan
        fi
        if [ "${OSL}" = "Linux" ]
        then
            touch /var/log/btmp
            chmod "600" /var/log/btmp
            chown root:utmp /var/log/btmp
            chmod "440" /etc/xinetd.conf
            chmod "440" /etc/xinetd.d/*
            chmod "755" /etc/xinetd.d
            chown root:root /etc/xinetd.conf
            chown -R root:root /etc/xinetd.d/
            chmod o-w /etc/cron.* /etc/crontab /var/spool/cron/*
            chmod "600" /var/log/cron
            chmod "600" /var/spool/cron/*
            if [ "${Rel}" = "5" ]
            then
                chmod "600" /etc/cron.d/*
                chmod "600" /etc/crontab
                chmod "700" /etc/cron.daily/*
                chmod "700" /etc/cron.hourly/*
                chmod "700" /etc/cron.monthly/*
                chmod "700" /etc/cron.weekly/*
            fi
            chmod "755" /var/spool/cron/ /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.monthly/ /etc/cron.weekly/
            chown root:root /var/spool/cron/ /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.monthly/ /etc/cron.weekly/
            if [ -d /usr/lib64/games ]
            then
                rm -r /usr/lib64/games
            fi
            if [ -d /var/cups ]
            then
                rm -rf /var/cups
            fi
            if [ -f /etc/foomatic/filter.conf ]
            then
                rm /etc/foomatic/filter.conf
            fi
            if [ "$(rpm -qa | grep -c "foomatic")" -gt 0 ]
            then
                rpm -e foomatic
            fi
            if [ ! -s /etc/pam.d/system-auth-local ]
            then
                cd /etc/pam.d
                cp system-auth-ac system-auth-local
                ln -sf system-auth-local system-auth
                chmod "644" system-auth-local
            fi
            cd ${TMP}/${OSL}
            if [ "${Rel}" = "5" ]; then
                if [ "$(grep "alias" /etc/modprobe.conf | grep "net-pf-10" | egrep -c "off")" -eq 0 ]
                then
                    echo "alias net-pf-10 off" >>/etc/modprobe.conf
                fi
                if [ "$(grep "alias" /etc/modprobe.conf | grep "ipv6" | egrep -c "off")" -eq 0 ]
                then
                    echo "alias ipv6 off" >>/etc/modprobe.conf
                fi
            fi
            /sbin/chkconfig xinetd off
            /sbin/service auditd restart
            /sbin/service sshd restart
        elif [ "${OSL}" = "SunOS" -a "${OSrev}" = "5.10" ]
        then
            if [ "${ZONE}" = "NO" ]
            then
                echo "/usr/sbin/auditconfig -setpolicy +perzone" >>/etc/security/audit_startup
                echo "/usr/sbin/auditconfig -setpolicy +zonename" >>/etc/security/audit_startup
                cd /etc/security
                #./bsmconv
                svcadm restart auditd
            else
                svcadm enable auditd
            fi
            ln -s /etc/issue /etc/ftpd/banner.msg
            inetadm -m ftp exec="/usr/sbin/in.ftpd -ald"
            inetadm -M tcp_wrappers=TRUE
            inetadm -M tcp_trace=TRUE
            svcadm restart ssh
            #
            svccfg -s inetd setprop defaults/tcp_wrappers=true
            svcadm refresh inetd
            svccfg -f svcadm.cfg
            #
            svccfg -s system-log setprop config/log_from_remote=false
            svcadm refresh system-log
            echo PASSREQ=YES >/etc/default/sulogin
            if [ "${ZONE}" = "NO" ]
            then
                svcadm enable network/ntp
            fi
            svcadm restart inetd
            svcadm restart system-log:default
            >/var/adm/wtmp
            >/var/adm/wtmpx
        fi

        ## Validate the contents in /etc/hosts are correct.
        if [ "$(grep -c "${SELF}" /etc/hosts)" -eq 0 ]
        then
            echo "Can't locate ${SELF} entries in /etc/hosts" 1>>"${LOGFILE}"
            echo "Review the hosts file and add or correct entries ASAP!" 1>>"${LOGFILE}"
        fi
        cd ${TMP}/${OSL}
    fi
}

######################################################################
## MAIN PROGRAM

run_lockdown

## Remove the retrieval directory
cd /
if [ -d ${TMP}/${OSL} ]
then
    echo "SRG Lockdown Complete - Removing the retrieval directory ${TMP}/${OSL}" 1>>"${LOGFILE}"
    rm -rf ${TMP}/${OSL}
    exit "0"
fi
