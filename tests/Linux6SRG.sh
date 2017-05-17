#!/bin/bash
#
#********************************************************************************************
#SRG checks
# Program to check the latest RHEL 6 SRG
#
# Bill Parrish
#
# Update 2017-03-07 (Brad Doucette)
# Additions 2017-03-27
#********************************************************************************************
# TODO
# RHEL-06-000163 check for single, suspend or halt
# RHEL-06-000508 check for duplicate vkey fixes
# RHEL-06-000278 - rpm -V audit | grep '^.M'   rpm --setperms audit
# RHEL-06-000279, 280 prelink -q /sbin/aureport
# backup sysctl once
#
OS="$(uname -s)"
REV="$(uname -r)"
RPM=/bin/rpm
CHMOD=/bin/chmod
CHOWN=/bin/chown
CHGRP=/bin/chgrp
PERL=/usr/bin/perl
SETFACL=/usr/bin/setfacl
HOSTNAME="$(hostname)"
CAT=/bin/cat
CHATTR=/usr/bin/chattr
MV=/bin/mv
FIND=/usr/bin/find
SED=/bin/sed
LINK="NO"
CORRECT="NO"
HEALING="YES"
IPTABLES="0"
IP6TABLES="0"
FOUND_AIDE="0"
TEST_DIR="/var/tmp/srg_stuff"
RECOVER_DIR=${TEST_DIR}/recover_dir
HEALING_FILE=${RECOVER_DIR}/healing_srg_tmp
RECOVERY_FILE=${RECOVER_DIR}/recovery_srg.sh
RPM_FILE=${TEST_DIR}/rpm_va.ot
PARAMS="$#"
OOB="$(netstat -rn | awk '{print $2}' | grep "^2\." | head -1)"
BOOT_LEVEL="$(grep "initdefault:" /etc/inittab | grep -v "^#" |  awk -F: '{print $2}')"
EXCEPTIONS=/opt/esps/exemptions/asset_status_overrides
if [ "$(ps -ef | grep -c "vmtoolsd")" -gt 0 ]; then
        VOE="YES"
else
        VOE="NO"
fi
##Create default test directories########################
if [ ! -d "${TEST_DIR}" ]
then
    umask 077 && mkdir "${TEST_DIR}" || exit
fi
if [ ! -d "${RECOVER_DIR}" ]
then
    umask 077 && mkdir "${RECOVER_DIR}" || exit
fi
if [ -f "${HEALING_FILE}" ]
then
   rm "${HEALING_FILE}"
fi
touch "${HEALING_FILE}"
if [ -f ${RECOVER_DIR}/srg_healing.sh ]
then
   rm ${RECOVER_DIR}/srg_healing.sh
fi
if [ -f "${RECOVERY_FILE}" ]
then
   rm "${RECOVERY_FILE}"
fi
if [ "${PARAMS}" -gt 0 ]
then
   HEALING="$1"
   if [ "${HEALING}" = "FIX" ]
   then
      HEALING="YES"
   fi
fi
export HEALING

#********************************************************************************************
# function getsetperms
#
#********************************************************************************************
getsetperms ()
{
   STAT="$1"
   sName="$2"

   if [ "$STAT" = "healing" ]
   then
        Permuser="$(echo "${sValidPerms}"|cut -c2-4)"
        Permgroup="$(echo "${sValidPerms}"|cut -c5-7)"
        Permother="$(echo "${sValidPerms}"|cut -c8-10)"
   elif [ "$STAT" = "recovery" ]
   then
        Permuser="$(echo "${sActualPerms}"|cut -c2-4)"
        Permgroup="$(echo "${sActualPerms}"|cut -c5-7)"
        Permother="$(echo "${sActualPerms}"|cut -c8-10)"
   fi
        case "${Permuser}"
        in
         rwx ) PERMUSER="700" ;;
         rws ) PERMUSER="4700" ;;
         rw- ) PERMUSER="600" ;;
         r-x ) PERMUSER="500" ;;
         r-s ) PERMUSER="4500" ;;
         r-- ) PERMUSER="400" ;;
         -wx ) PERMUSER="300" ;;
         -w- ) PERMUSER="200" ;;
         --x ) PERMUSER="100" ;;
         --s ) PERMUSER="4100" ;;
         --- ) PERMUSER="000" ;;
            *)  ;;
        esac
        case "${Permgroup}"
        in
         rwx ) PERMGROUP="70" ;;
         rws ) PERMGROUP="2070" ;;
         rw- ) PERMGROUP="60" ;;
         r-x ) PERMGROUP="50" ;;
         r-s ) PERMGROUP="2050" ;;
         r-- ) PERMGROUP="40" ;;
         -wx ) PERMGROUP="30" ;;
         -w- ) PERMGROUP="20" ;;
         --x ) PERMGROUP="10" ;;
         --s ) PERMGROUP="2010" ;;
         --- ) PERMGROUP="0" ;;
            *)  ;;
        esac
        case "${Permother}"
        in
         rwx ) PERMOTHER="7" ;;
         rwt ) PERMOTHER="1007" ;;
         rw- ) PERMOTHER="6" ;;
        r-x ) PERMOTHER="5" ;;
         r-s ) PERMOTHER="1050" ;;
         r-- ) PERMOTHER="4" ;;
         -wx ) PERMOTHER="3" ;;
         -wt ) PERMOTHER="1003" ;;
         -w- ) PERMOTHER="2" ;;
         --x ) PERMOTHER="1" ;;
         --t ) PERMOTHER="1001" ;;
         --- ) PERMOTHER="0" ;;
            *) ;;
         esac
        PERM="$(expr "${PERMUSER}" + "${PERMGROUP}" + "${PERMOTHER}")"
    if [ "${PERM}" -eq 0 ]
    then
        PERM="000"
        fi
        if [ "$STAT" = "healing" ]
        then
            echo "${stigID} ${CHMOD} ${PERM} ${sName}" >> "${HEALING_FILE}"
        elif [ "$STAT" = "recovery" ]
        then
            echo "${stigID} ${CHMOD} ${PERM} ${sName}" >> "${RECOVERY_FILE}"
        fi
}

#********************************************************************************************
# function backup
#
#********************************************************************************************
backup ()
{
FILE="$1"
DATE="$(date +"%m%d%Y%H%M")"
BASENAME="$(basename "${FILE}")"
if [ -f "${FILE}" ]
then
   i="0"
   if [ ! -f ${RECOVER_DIR}/${BASENAME}.${DATE} ]
   then
      cp -p "${FILE}" ${RECOVER_DIR}/${BASENAME}.${DATE}
      echo "cp -p ${RECOVER_DIR}/${BASENAME}.${DATE} ${FILE}" >> ${RECOVER_DIR}/${BASENAME}_recover
   else
    while [ "${i}" -le 10 ]
    do
        if [ ! -f ${RECOVER_DIR}/${BASENAME}.${DATE}.${i} ]
            then
                    cp -p "${FILE}" ${RECOVER_DIR}/${BASENAME}.${DATE}.${i}
                echo "cp -p ${RECOVER_DIR}/${BASENAME}.${DATE}.${i} ${FILE}" >> ${RECOVER_DIR}/${BASENAME}_recover
                break
        fi
        i="$(expr "${i}" + "1")"
    done
    fi
fi
}

#********************************************************************************************
# function get_audit_action
#
#********************************************************************************************
get_audit_action ()
{
   ACTION="$1"
   CHECK="0"
   AUDIT_ACTIONS="email ignore syslog exec single halt rotate keep_logs"
   if [ -s /etc/audit/auditd.conf ]
   then
    VAR="$(grep "^${ACTION}" /etc/audit/auditd.conf | awk -F"=" '{print $2}' |tr [:upper:] [:lower:])"
    if [ -n "$VAR" ]
    then
       for i in "${AUDIT_ACTIONS}"
       do
         if [ "${VAR}" = "${i}" ]
         then
         CHECK="1"
         fi
       done
        fi
   fi
   if [ "${CHECK}" -eq 1 ]
   then
    STATUS="NF"
   else
    STATUS="O"
   fi
}

#********************************************************************************************
# function chk_service_off
#
#********************************************************************************************
chk_service_off ()
{
ID="$1"
SVC="$2"
CHECK="0"
FOUND="0"
VAR=""
service "${SVC}" status 1>/tmp/a 2>&1
if [ "$(grep -c "unrecognized service" /tmp/a)" -eq 0 ]
then
    VAR="$(chkconfig "${SVC}" --list | awk '{print $2,$3,$4,$5,$6,$7,$8}')"
    for CHK in "${VAR}"
    do
            LEVEL="$(echo "${CHK}"| awk -F: '{print $1}')"
            STATE="$(echo "${CHK}"| awk -F: '{print $2}')"
#            echo "${ID}:${SVC} --level ${LEVEL} --STATE ${STATE}.. --CHECK ${CHECK}"
            if [ "${STATE}" != "off" ]
            then
              FOUND="1"
            if [ "${HEALING}" = "YES" ]
                then
                   echo "${stigID} /sbin/chkconfig --level ${LEVEL} ${SVC} off" >> "${HEALING_FILE}"
                   echo "${stigID} /sbin/chkconfig --level ${LEVEL} ${SVC} on" >> "${RECOVERY_FILE}"
            else
               echo "${ID}:${SVC} --level ${LEVEL} is on."
               CHECK="1"
            fi
          fi
    done
    if [ "${FOUND}" -eq 1 ]
    then
       echo "${stigID} /sbin/service ${SVC} stop" >> "${HEALING_FILE}"
       echo "${stigID} /sbin/service ${SVC} start" >> "${RECOVERY_FILE}"
       sleep "2"
    fi
fi
if [ "${CHECK}" -eq 1 ]
then
    STATUS="O"
else
    STATUS="NF"
fi
if [ -f /tmp/a ]
then
   rm /tmp/a
fi
}

#********************************************************************************************
# function f_SYSCTL_CHECK ( strStigID strName subSETTING )
#
#********************************************************************************************
f_SYSCTL_CHECK ()
{
subSTIGID="$1"
subNETNAME="$2"
subSETTING="$3"
subfNAME="/etc/sysctl.conf"
sActualPerms="$(stat --printf %04a "${subfNAME}")"
subOwnerGroup="$(ls -al "${subfNAME}" | awk '{print $3 ":" $4}')"
subCurrentSetting="$(sysctl "${subNETNAME}" | awk '{print $3'})"

if [ "$(sysctl "${subNETNAME}" | grep -c "${subSETTING}")" -eq "1" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        echo "${subSTIGID} sysctl -w ${subNETNAME}=${subCurrentSetting}" >> "${RECOVERY_FILE}"
        echo "${subSTIGID} sysctl -w ${subNETNAME}=${subSETTING}" >> "${HEALING_FILE}"
        STATUS="NF"
    else
        STATUS="O"
    fi
fi

if [ "$(grep -c "${subNETNAME} = ${subSETTING}" "${subfNAME}")" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        echo "${subSTIGID} grep -v \"^${subNETNAME}\" ${subfNAME} > /tmp/a" >> "${HEALING_FILE}"
        echo "${subSTIGID} mv /tmp/a ${subfNAME}" >> "${HEALING_FILE}"
        echo "${subSTIGID} echo \"${subNETNAME} = ${subSETTING}\" >> ${subfNAME}" >> "${HEALING_FILE}"
        backup "${subfNAME}"
        echo "${subSTIGID} echo \"Recover backup file ${subfNAME}\"" >> "${RECOVERY_FILE}"
        echo "${subSTIGID} chmod ${subActualPerms} ${subfNAME}" >> "${RECOVERY_FILE}"
        echo "${subSTIGID} chown ${subOwnerGroup} ${subfNAME}" >> "${RECOVERY_FILE}"
        echo "${subSTIGID} chmod 600 ${subfNAME}" >> "${HEALING_FILE}"
        echo "${subSTIGID} chown root:root ${subfNAME}" >> "${HEALING_FILE}"
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
}

#********************************************************************************************
#
# chk_service ()
#
# inputs:
#   None
# Output:
#
#********************************************************************************************
chk_service ()
{
ID="$1"
SVC="$2"
CHECK="0"
FOUND="0"
VAR=""
service "${SVC}" status 1>/tmp/a 2>&1
if [ "$(grep -c "unrecognized service" /tmp/a)" -eq 0 ]
then
    VAR="$(chkconfig "${SVC}" --list | awk '{print $2,$3,$4,$5,$6,$7,$8}')"
    for CHK in "${VAR}"
    do
            LEVEL="$(echo "${CHK}"| awk -F: '{print $1}')"
            STATE="$(echo "${CHK}"| awk -F: '{print $2}')"
            echo "${ID}:${SVC} --level ${LEVEL} --STATE ${STATE}.. --CHECK ${CHECK}"
            if [ "${STATE}" != "off" ]
            then
            FOUND="1"
            if [ "${HEALING}" = "YES" ]
                then
                   echo "${stigID} /sbin/chkconfig --level ${LEVEL} ${SVC} off" >> "${HEALING_FILE}"
                   echo "${stigID} /sbin/chkconfig --level ${LEVEL} ${SVC} on" >> "${RECOVERY_FILE}"
            else
               echo "${ID}:${SVC} --level ${LEVEL} is on."
               CHECK="1"
                fi
            fi
    done
    if [ "${FOUND}" -eq 1 ]
    then
       echo "${stigID} /sbin/service ${SVC} stop" >> "${HEALING_FILE}"
       sleep "2"
    fi
fi
if [ "${CHECK}" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
if [ -f /tmp/a ]
then
   rm /tmp/a
fi
}

#******************************************************************************
# Global
# Get the Application and Sub-Application from the SRR_CONFIG file
# inputs:
#   None
# Output:
#   sApplication
#   sSubApp
#******************************************************************************
sHostname="$(hostname)"
OSL="$(uname -s)"
if [ -f /os_srr/LOCAL/SRR_CONFIG ]
then
    sApplication="$(cat /os_srr/LOCAL/SRR_CONFIG | grep APPLICATION | awk -F":" '{print $2}' | sed s/" "//g)"
    if [ "$sApplication" = "" ]
    then
        sApplication="UNKNOWN"
    fi
    sSubApp="$(cat /os_srr/LOCAL/SRR_CONFIG | grep SUBAPP | awk -F":" '{print $2}' | sed s/" "//g)"
    if [ ! "$sSubApp" ]
    then
        sSubApp="UNKNOWN"
    fi
else
    sApplication="UNKNOWN"
    sSubApp="UNKNOWN"
fi
ReleaseFile="/etc/redhat-release"
if [ -s "${ReleaseFile}" ]
then
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
      fi
fi
########################################
rpm -Va --nodeps --noscripts --nosignature --nodigest --nofiledigest 1>"${RPM_FILE}"
########################################

BOOT_LEVEL="$(grep "initdefault:" /etc/inittab | grep -v "^#" |  awk -F: '{print $2}')"
if [ "${BOOT_LEVEL}" -le 3 ]
then
    ## No Graphical Interface
        SET="0"
else
    ## Graphical Interface
        SET="1"
fi

###############################################################################
### Start SRG Checks
#

########################################
stigID="RHEL-06-000001"

if [ "$(mount | grep -c 'on /tmp ')" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038455:3:${STATUS}:The system must use a separate file system for /tmp."

########################################
stigID="RHEL-06-000002"

if [ "$(mount | grep -c 'on /var ')" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038456:3:${STATUS}:The system must use a separate file system for /var."

########################################
stigID="RHEL-06-000003"

if [ "$(mount | grep -c 'on /var/log ')" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038463:3:${STATUS}:The system must use a separate file system for /var/log."

########################################
stigID="RHEL-06-000004"

if [ "$(mount | grep -c 'on /var/log/audit ')" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038467:3:${STATUS}:The system must use a separate file system for the system audit data path."

########################################
stigID="RHEL-06-000005"

get_audit_action space_left_action
if [ "${HEALING}" = "YES" -a "${VAR}" != "email" ]
then
   backup /etc/audit/auditd.conf
   echo "${stigID} grep -v \"^space_left_action\" /etc/audit/auditd.conf > /tmp/RHEL-06-000005" >> "${HEALING_FILE}"
   echo "${stigID} echo \"space_left_action = email\" >> /tmp/RHEL-06-000005" >> "${HEALING_FILE}"
   echo "${stigID} mv /tmp/RHEL-06-000005 /etc/audit/auditd.conf" >> "${HEALING_FILE}"
   echo "${stigID} restorecon -vvFR /etc/audit/auditd.conf" >> "${HEALING_FILE}"
   echo "${stigID} /sbin/service auditd restart" >> "${HEALING_FILE}"
   STATUS="NF"
fi
echo "${stigID}:V0038470:2:${STATUS}:The audit system must alert designated staff members when the audit storage volume approaches capacity."

########################################
stigID="RHEL-06-000007"

if [ "$(mount | grep -c 'on /home ')" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038473:3:${STATUS}:The system must use a separate file system for user home directories."

########################################
stigID="RHEL-06-000008"

if [ "$(rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep -c "is not installed")" -eq 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]; then
       echo "${stigID} rpm --import /etc/pki/rpm-gpg/*" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038476:2:${STATUS}:Vendor-provided cryptographic certificates must be installed to verify the integrity of system software."

########################################
stigID="RHEL-06-000009"

chk_service_off RHEL-06-000009 rhnsd
echo "${stigID}:V0038478:3:${STATUS}:The Red Hat Network Service (rhnsd) service must not be running, unless using RHN or an RHN Satellite."

########################################
stigID="RHEL-06-000011"

if [ "${HEALING}" = "YES" ]; then
    echo "${stigID} echo \"Manual Review - System security patches and updates must be installed and up-to-date.\"" >> "${HEALING_FILE}"
fi
echo "${stigID}:V0038481:2:NR:System security patches and updates must be installed and up-to-date."

########################################
stigID="RHEL-06-000012"

if [ "$(grep -c "gpgcheck=1" /etc/yum.conf)" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/yum.conf
       echo "${stigID} grep -v \"^gpgcheck=\" /etc/yum.conf > /tmp/RHEL-06-000013" >> "${HEALING_FILE}"
       echo "${stigID} echo \"gpgcheck=1\" >> /tmp/RHEL-06-000013" >> "${HEALING_FILE}"
       echo "${stigID} mv /tmp/RHEL-06-000013 /etc/yum.conf" >> "${HEALING_FILE}"
       STATUS="NF"
    else
        STATUS="O"
        fi
fi
echo "${stigID}:V0038483:2:${STATUS}:The system package management tool must cryptographically verify the authenticity of system software packages during installation."

########################################
stigID="RHEL-06-000015"

CHECK="0"
if [ -d /etc/yum.repos.d ]
then
  ls -1 /etc/yum.repos.d/* > /tmp/RHEL-06-000015
  if [ -s /tmp/RHEL-06-000015 ]
  then
     for ENTRY in "$(cat /tmp/RHEL-06-000015)"
     do
        if [ "$(grep -c "gpgcheck=0" "${ENTRY}")" -eq 1 ]
        then
        if [ "${HEALING}" = "YES" ]
        then
            backup "${ENTRY}"
        echo "${stigID} grep -v \"^gpgcheck=\" ${ENTRY} > /tmp/RHEL-06-000015" >> "${HEALING_FILE}"
        echo "${stigID} echo \"gpgcheck=1\" >> /tmp/RHEL-06-000015" >> "${HEALING_FILE}"
        echo "${stigID} mv /tmp/RHEL-06-000015 ${ENTRY}" >> "${HEALING_FILE}"
            STATUS="NF"
        else
           CHECK="1"
        fi
    elif [ "$(grep -c "gpgcheck=" "${ENTRY}")" -eq 0 ]
    then
        if [ "${HEALING}" = "YES" ]
        then
            backup "${ENTRY}"
        echo "${stigID} echo \"gpgcheck=1\" >> /tmp/RHEL-06-000015" >> "${HEALING_FILE}"
        echo "${stigID} mv /tmp/RHEL-06-000015 ${ENTRY}" >> "${HEALING_FILE}"
            STATUS="NF"
        fi
        fi
     done
     rm /tmp/RHEL-06-000015
  fi
  if [ "${CHECK}" -eq 0 ]
  then
     STATUS="NF"
  else
     STATUS="O"
  fi
else
  STATUS="NF"
fi
echo "${stigID}:V0038487:3:${STATUS}:The system package management tool must cryptographically verify the authenticity of all software packages during installation."

########################################
stigID="RHEL-06-000016"

if [ "$(rpm -q aide | grep -c "is not installed")" -eq 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
    if [ -f /tmp/CMDB/Linux/aide-0.14-8.el6.x86_64.rpm ]
    then
       echo "${stigID} rpm -ivh /tmp/CMDB/Linux/aide-0.14-8.el6.x86_64.rpm" >> "${HEALING_FILE}"
       if [ -f /etc/sysconfig/prelink ]
       then
         echo "${stigID} /usr/bin/perl -pi -w -e 's/PRELINKING=yes/PRELINKING=no/g;' /etc/sysconfig/prelink" >> "${HEALING_FILE}"
         echo "${stigID} /usr/sbin/prelink -ua" >> "${HEALING_FILE}"
       fi
       echo "${stigID} /usr/sbin/aide --init" >> "${HEALING_FILE}"
       echo "${stigID} cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz" >> "${HEALING_FILE}"
       echo "${stigID} /usr/sbin/aide --check" >> "${HEALING_FILE}"
       STATUS="NF"
       fi
    else
    STATUS="O"
    fi
fi
echo "${stigID}:V0038489:2:${STATUS}:A file integrity tool must be installed."

########################################
stigID="RHEL-06-000019"

find /home -name .rhosts > /tmp/SRG-OS-000019
if [ ! -s /tmp/SRG-OS-000019 -o ! -f /etc/hosts.equiv ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       for rHost in "$(cat /tmp/SRG-OS-000019)"
       do
         echo "${stigID} rm ${rHost}" >> "${HEALING_FILE}"
         STATUS="NF"
       done
    else
         STATUS="O"
    fi
fi
rm /tmp/SRG-OS-000019
echo "${stigID}:V0038491:1:${STATUS}:There must be no .rhosts or hosts.equiv files on the system."

########################################
stigID="RHEL-06-000027"

if [ "$(grep -c '^vc/[0-9]' /etc/securetty)" -eq 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/securetty
       echo "${stigID} grep -v \"^vc/[0-9]\" /etc/securetty > /tmp/f" >> "${HEALING_FILE}"
       echo "${stigID} mv /tmp/f /etc/securetty" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038492:2:${STATUS}:The system must prevent the root account from logging in from virtual consoles."

########################################
stigID="RHEL-06-000028"

if [ "$(grep -c '^ttyS[0-9]' /etc/securetty)" -eq 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/securetty
       echo "${stigID} grep -v \"^ttyS/[0-9]\" /etc/securetty > /tmp/f" >> "${HEALING_FILE}"
       echo "${stigID} mv /tmp/f /etc/securetty" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038494:3:${STATUS}:The system must prevent the root account from logging in from serial consoles."

########################################
stigID="RHEL-06-000029"

CHECK="0"
awk -F: '{print $1 ":" $2}' /etc/shadow | grep -v "!!" | grep -v "\*" |awk -F: '{print $1}' > /tmp/RHEL-06-000029
for ENTRY in "$(cat /tmp/RHEL-06-000029)"
do
    if [ "$(grep "^${ENTRY}:" /etc/passwd |awk -F: '{print $3}')" -lt 500 -a "${ENTRY}" != "root" ]
    then
    echo "$ENTRY"
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} passwd -l ${ENTRY}" >> "${HEALING_FILE}"
       echo "${stigID} passwd -u ${ENTRY}" >> "${RECOVERY_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
    fi
done
rm /tmp/RHEL-06-000029
echo "${stigID}:V0038496:2:${STATUS}:Default system accounts, other than root, must be locked."

########################################
stigID="RHEL-06-000030"

grep "nullok" /etc/pam.d/system-auth /etc/pam.d/system-auth > /tmp/RHEL-06-000030
if [ ! -s RHEL-06-000030 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
rm /tmp/RHEL-06-000030
echo "${stigID}:V0038497:1:${STATUS}:The system must not have accounts configured with blank or null passwords."

########################################
stigID="RHEL-06-000031"

if [ "$(awk -F: '($2 != "x") {print}' /etc/passwd |wc -l)" -eq 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038499:2:${STATUS}:The /etc/passwd file must not contain password hashes."

########################################
stigID="RHEL-06-000032"

if [ "$(awk -F: '($3 == "0") {print}' /etc/passwd|wc -l)" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038500:2:${STATUS}:The root account must be the only account having a UID of 0."

########################################
stigID="RHEL-06-000033"

if [ "$(ls -l /etc/shadow | awk '{print $3}')" = "root" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       Owner="$(ls -l /etc/shadow | awk '{print $3}')"
       echo "${stigID} chown ${Owner} /etc/shadow" >> "${RECOVERY_FILE}"
       echo "${stigID} chown root /etc/shadow" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038502:2:${STATUS}:The /etc/shadow file must be owned by root."

########################################
stigID="RHEL-06-000034"

if [ "$(ls -l /etc/shadow | awk '{print $4}')" = "root" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       Group="$(ls -l /etc/shadow | awk '{print $4}')"
       echo "${stigID} chgrp ${Group} /etc/shadow" >> "${RECOVERY_FILE}"
       echo "${stigID} chgrp root /etc/shadow" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038503:2:${STATUS}:The /etc/shadow file must be group-owned by root."

########################################
stigID="RHEL-06-000035"

sName="/etc/shadow"
sValidPerms="0000"
sActualPerms="$(stat --printf %04a "${sName}")"
if [ "${sActualPerms}" -eq "${sValidPerms}" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        echo "${stigID} chmod ${sValidPerms} ${sName}" >> "${HEALING_FILE}"
        echo "${stigID} chmod ${sActualPerms} ${sName}" >> "${RECOVERY_FILE}"
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038504:2:${STATUS}:The /etc/shadow file must have mode 0000."

########################################
stigID="RHEL-06-000036"

if [ "$(ls -l /etc/gshadow | awk '{print $3}')" = "root" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       Owner="$(ls -l /etc/gshadow | awk '{print $3}')"
       echo "${stigID} chown ${Owner} /etc/gshadow" >> "${RECOVERY_FILE}"
       echo "${stigID} chown root /etc/gshadow" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038443:2:${STATUS}:The /etc/gshadow file must be owned by root."

########################################
stigID="RHEL-06-000037"

if [ "$(ls -l /etc/gshadow | awk '{print $4}')" = "root" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       Group="$(ls -l /etc/gshadow | awk '{print $4}')"
       echo "${stigID} chgrp ${Group} /etc/gshadow" >> "${RECOVERY_FILE}"
       echo "${stigID} chgrp root /etc/gshadow" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038448:2:${STATUS}:The /etc/gshadow file must be group-owned by root."

########################################
stigID="RHEL-06-000038"

sName="/etc/gshadow"
sValidPerms="0000"
sActualPerms="$(stat --printf %04a "${sName}")"
if [ "${sActualPerms}" -eq "${sValidPerms}" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        echo "${stigID} ${CHMOD} ${sValidPerms} ${sName}" >> "${HEALING_FILE}"
        echo "${stigID} ${CHMOD} ${sActualPerms} ${sName}" >> "${RECOVERY_FILE}"
        STATUS="NF"
    else
        STATUS="O"
    fi
fi

echo "${stigID}:V0038449:2:${STATUS}:The /etc/gshadow file must have mode 0000."

########################################
stigID="RHEL-06-000039"

if [ "$(ls -l /etc/passwd | awk '{print $3}')" = "root" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       Owner="$(ls -l /etc/passwd | awk '{print $3}')"
       echo "${stigID} chown ${Owner} /etc/passwd" >> "${RECOVERY_FILE}"
       echo "${stigID} chown root /etc/passwd" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038450:2:${STATUS}:The /etc/passwd file must be owned by root."

########################################
stigID="RHEL-06-000040"

if [ "$(ls -l /etc/passwd | awk '{print $4}')" = "root" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       Group="$(ls -l /etc/passwd | awk '{print $4}')"
       echo "${stigID} chgrp ${Group} /etc/passwd" >> "${RECOVERY_FILE}"
       echo "${stigID} chgrp root /etc/passwd" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038451:2:${STATUS}:The /etc/passwd file must be group-owned by root."

########################################
stigID="RHEL-06-000041"

sName="/etc/passwd"
sValidPerms="0644"
sActualPerms="$(stat --printf %04a "${sName}")"

if [ "${sActualPerms}" -le "${sValidPerms}" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        echo "${stigID} ${CHMOD} ${sValidPerms} ${sName}" >> "${HEALING_FILE}"
        echo "${stigID} ${CHMOD} ${sActualPerms} ${sName}" >> "${RECOVERY_FILE}"
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038457:2:${STATUS}:The /etc/passwd file must have mode 0644 or less permissive."

########################################
stigID="RHEL-06-000042"

if [ "$(ls -l /etc/group | awk '{print $3}')" = "root" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       Owner="$(ls -l /etc/group | awk '{print $3}')"
       echo "${stigID} chown ${Owner} /etc/group" >> "${RECOVERY_FILE}"
       echo "${stigID} chown root /etc/group" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038458:2:${STATUS}:The /etc/group file must be owned by root."

########################################
stigID="RHEL-06-000043"

if [ "$(ls -l /etc/group | awk '{print $4}')" = "root" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       Group="$(ls -l /etc/group | awk '{print $4}')"
       echo "${stigID} chgrp ${Group} /etc/group" >> "${RECOVERY_FILE}"
       echo "${stigID} chgrp root /etc/group" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038459:2:${STATUS}:The /etc/group file must be group-owned by root."

########################################
stigID="RHEL-06-000044"

sName="/etc/group"
sValidPerms="0644"
sActualPerms="$(stat --printf %04a "${sName}")"

if [ "${sActualPerms}" -eq "${sValidPerms}" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        echo "${stigID} ${CHMOD} ${sValidPerms} ${sName}" >> "${HEALING_FILE}"
        echo "${stigID} ${CHMOD} ${sActualPerms} ${sName}" >> "${RECOVERY_FILE}"
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038461:2:${STATUS}:The /etc/group file must be set to 644."

########################################
stigID="RHEL-06-000045"

DIR="/lib /lib64 /usr/lib /usr/lib64"
if [ "$(find -L "${DIR}" -perm /022 -type f | wc -l)" -eq 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        for D in "${DIR}"
        do
            find -L "${D}" -perm /022 -type f > ${RECOVER_DIR}/${stigID}
            if [ -s ${RECOVER_DIR}/${stigID} ]
            then
                for FILE in "$(cat ${RECOVER_DIR}/${stigID})"
                do
                    if [ ! -e "${FILE}" ]
                    then
                        echo "${stigID} rm -f ${FILE}" >> "${HEALING_FILE}"
                    elif [ -f "${FILE}" ]
                    then
                        echo "${stigID} chmod go+w ${FILE}" >> "${RECOVERY_FILE}"
                        echo "${stigID} chmod go-w ${FILE}" >> "${HEALING_FILE}"
                    fi
                done
            fi
        done
        rm ${RECOVER_DIR}/${stigID}
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
if [ -f ${RECOVER_DIR}/${stigID} ]
then
    rm ${RECOVER_DIR}/${stigID}
fi
echo "${stigID}:V0038465:2:${STATUS}:Library files must have mode 0755 or less permissive."

########################################
stigID="RHEL-06-000046"

DIR="/lib /lib64 /usr/lib /usr/lib64"
if [ "$(find -L "${DIR}" \! -user root | wc -l)" -eq 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        for D in "${DIR}"
        do
            /bin/find -L "${D}" \! -user root > ${RECOVER_DIR}/${stigID}
            if [ -s ${RECOVER_DIR}/${stigID} ]
            then
                for FILE in "$(cat ${RECOVER_DIR}/${stigID})"
                do
                    if [ ! -e "${FILE}" ]
                    then
                        echo "${stigID} rm -f ${FILE}" >> "${HEALING_FILE}"
                    elif [ -f "${FILE}" ]
                    then
                        Owner="$(ls -l "${FILE}" | awk '{print $3}')"
                        echo "${stigID} chown ${Owner} ${FILE}" >> "${RECOVERY_FILE}"
                        echo "${stigID} chown root ${FILE}" >> "${HEALING_FILE}"
                    fi
                done
                STATUS="NF"
            fi
        done
        rm ${RECOVER_DIR}/${stigID}
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
if [ -f ${RECOVER_DIR}/${stigID} ]
then
    rm ${RECOVER_DIR}/${stigID}
fi
echo "${stigID}:V0038466:2:${STATUS}:Library files must be owned by root."

########################################
stigID="RHEL-06-000047"

DIR="/bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin"
if [ "$(find -L "${DIR}" -perm /022 -type f | wc -l)" -eq 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        for D in "${DIR}"
        do
            find -L "${D}" -perm /022 -type f > ${RECOVER_DIR}/${stigID}
            if [ -s ${RECOVER_DIR}/${stigID} ]
            then
                for FILE in "$(cat ${RECOVER_DIR}/${stigID})"
                do
                if [ ! -e "${FILE}" ]
                then
                    echo "${stigID} rm -f ${FILE}" >> "${HEALING_FILE}"
                elif [ -f "${FILE}" ]
                then
                    echo "${stigID} chmod go+w ${FILE}" >> "${RECOVERY_FILE}"
                    echo "${stigID} chmod go-w ${FILE}" >> "${HEALING_FILE}"
                fi
                done
            fi
        done
        rm ${RECOVER_DIR}/${stigID}
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
if [ -f ${RECOVER_DIR}/${stigID} ]
then
    rm ${RECOVER_DIR}/${stigID}
fi
echo "${stigID}:V0038469:2:${STATUS}:All system command files must have mode 0755 or less permissive."

########################################
stigID="RHEL-06-000048"

DIR="/bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin"
if [ "$(find -L "${DIR}" \! -user root | wc -l)" -eq 0 ]
then
    STATUS="NF"
else
   if [ "${HEALING}" = "YES" ]
   then
    for D in "${DIR}"
    do
       find -L "${D}" \! -user root > /tmp/f.ot
       if [ -s /tmp/f.ot ]
       then
        for FILE in "$(cat /tmp/f.ot)"
        do
           if [ ! -e "${FILE}" ]
           then
            echo "${stigID} rm -f ${FILE}" >> "${HEALING_FILE}"
           elif [ -f "${FILE}" ]
           then
            Owner="$(ls -l "${FILE}" | awk '{print $3}')"
            echo "${stigID} chown ${Owner} ${FILE}" >> "${RECOVERY_FILE}"
            echo "${stigID} chown root ${FILE}" >> "${HEALING_FILE}"
           fi
        done
       fi
    done
    rm /tmp/f.ot
    STATUS="NF"
   else
    STATUS="O"
   fi
fi
echo "${stigID}:V0038472:2:${STATUS}:All system command files must be owned by root."

########################################
stigID="RHEL-06-000050"

VAL="$(grep -v "^#" /etc/login.defs | grep -i "PASS_MIN_LEN" | awk '{print $2}')"
if [ "$VAL" -ge 15 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/login.defs
        if [ -s /etc/login.defs ]
        then
           echo "${stigID} grep -v \"PASS_MIN_LEN\" /etc/login.defs > ${RECOVER_DIR}/${stigID}" >> "${HEALING_FILE}"
           echo "${stigID} mv ${RECOVER_DIR}/${stigID} /etc/login.defs" >> "${HEALING_FILE}"
           echo "${stigID} echo \"PASS_MIN_LEN  15\" >> /etc/login.defs" >> "${HEALING_FILE}"
           echo "${stigID} chown root:root /etc/login.defs" >> "${HEALING_FILE}"
           echo "${stigID} chmod 644 /etc/login.defs" >> "${HEALING_FILE}"
           STATUS="NF"
        else
            STATUS="O"
        fi
    else
        STATUS="O"
    fi
fi
if [ -f ${RECOVER_DIR}/${stigID} ]
then
    rm ${RECOVER_DIR}/${stigID}
fi
echo "${stigID}:V0038475:2:${STATUS}:The system must require passwords to contain a minimum of 14 characters."

########################################
stigID="RHEL-06-000051"
#!!!!!!!!!!!!!!!!!!!
VAL="$(grep -v "^#" /etc/login.defs | grep -i "PASS_MIN_DAYS" | awk '{print $2}')"
if [ "$VAL" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" -a "${STATUS}" != "NF" ]
    then
        if [ -f rhel6_config.tar ]
        then
            backup /etc/login.defs
            echo "${stigID} tar xvfP /tmp/CMDB/Linux/rhel6_config.tar /etc/login.defs" >> "${HEALING_FILE}"
            STATUS="NF"
        else
            STATUS="O"
        fi
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038477:2:${STATUS}:Users must not be able to change passwords more than once every 24 hours."

########################################
stigID="RHEL-06-000052"
#!!!!!!!!!!!!!!!!!!!!!!
VAL="$(grep -v "^#" /etc/login.defs | grep "PASS_MAX_DAYS" | awk '{print $2}')"
if [ "$VAL" -eq 60 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" -a "${STATUS}" != "NF" ]
    then
        if [ -f rhel6_config.tar ]
        then
            backup /etc/login.defs
            echo "${stigID} tar xvfP /tmp/CMDB/Linux/rhel6_config.tar /etc/login.defs" >> "${HEALING_FILE}"
            STATUS="NF"
        else
            STATUS="O"
        fi
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038479:2:${STATUS}:User passwords must be changed at least every 60 days."

########################################
stigID="RHEL-06-000054"
#!!!!!!!!!!!!!!
VAL="$(grep -v "^#" /etc/login.defs | grep "PASS_WARN_AGE" | awk '{print $2}')"
if [ "$VAL" -eq 7 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" -a "${STATUS}" != "NF" ]
    then
        if [ -f rhel6_config.tar ]
        then
            backup /etc/login.defs
            echo "${stigID} tar xvfP /tmp/CMDB/Linux/rhel6_config.tar /etc/login.defs" >> "${HEALING_FILE}"
            STATUS="NF"
        else
            STATUS="O"
        fi
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038480:3:${STATUS}:Users must be warned 7 days in advance of password expiration."

########################################
stigID="RHEL-06-000055"

VAL="$(grep -v "^#" /etc/pam.d/system-auth | grep -i "dcredit" | awk -F"dcredit=" '{print $2}' | cut -d " " -f1,1)"
if [ "$VAL" -le -1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038482:3:${STATUS}:The system must require passwords to contain at least one numeric character."

########################################
stigID="RHEL-06-000057"

VAL="$(grep -v "^#" /etc/pam.d/system-auth | grep -i "ucredit" | awk -F"ucredit=" '{print $2}' | cut -d " " -f1,1)"
if [ "$VAL" -le -1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038569:3:${STATUS}:The system must require passwords to contain at least one uppercase alphabetic character."

########################################
stigID="RHEL-06-000058"

VAL="$(grep -v "^#" /etc/pam.d/system-auth | grep -i "ocredit" | awk -F"ocredit=" '{print $2}' | cut -d " " -f1,1)"
if [ "$VAL" -le -1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038570:3:${STATUS}:The system must require passwords to contain at least one special character."

########################################
stigID="RHEL-06-000059"

VAL="$(grep -v "^#" /etc/pam.d/system-auth | grep -i "lcredit" | awk -F"lcredit=" '{print $2}' | cut -d " " -f1,1)"
if [ "$VAL" -le -1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038571:3:${STATUS}:The system must require passwords to contain at least one lowercase alphabetic character."

########################################
stigID="RHEL-06-000060"

VAL="$(grep -v "^#" /etc/pam.d/system-auth | grep -i "difok" | awk -F"difok=" '{print $2}' | cut -d " " -f1,1)"
if [ "$VAL" -ge 8 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        backup /etc/pam.d/system-auth
        VAL="$(grep -v "^#" /etc/pam.d/system-auth | grep -i "difok" | awk -F"difok=" '{print $2}' | cut -d " " -f1,1)"
        echo "${stigID} sed -e \"s/difok=${VAL}/difok=8/g\" /etc/pam.d/system-auth > /tmp/RHEL-06-000060" >> "${HEALING_FILE}"
        echo "${stigID} mv /tmp/RHEL-06-000060 /etc/pam.d/system-auth" >> "${HEALING_FILE}"
        echo "${stigID} chown root:root /etc/pam.d/system-auth" >> "${HEALING_FILE}"
        echo "${stigID} chmod 644 /etc/pam.d/system-auth" >> "${HEALING_FILE}"
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038572:3:${STATUS}:The system must require at least four characters be changed between the old and new passwords during a password change."

########################################
stigID="RHEL-06-000061"

if [ "$(grep -c "pam_faillock" /etc/pam.d/system-auth)" -gt 0 ]
then
   if [ "$(grep "pam_faillock" /etc/pam.d/system-auth | grep -c "deny=3")" -gt 0 ]
   then
      if [ "$(grep "pam_faillock" /etc/pam.d/password-auth-ac | grep -c "deny=3")" -gt 0 ]
      then
      STATUS="NF"
      else
     backup /etc/pam.d/password-auth-ac
     echo "${stigID} cp /etc/pam.d/system-auth /etc/pam.d/password-auth-ac" >> "${HEALING_FILE}"
      fi
   else
        STATUS="O"
   fi
else
   STATUS="O"
fi
echo "${stigID}:V0038573:2:${STATUS}:The system must disable accounts after three consecutive unsuccessful login attempts."

########################################
stigID="RHEL-06-000062"

if [ "$(grep -c "sha512" /etc/pam.d/system-auth)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038574:2:${STATUS}:The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth)."

########################################
stigID="RHEL-06-000063"

if [ "$(grep "ENCRYPT_METHOD" /etc/login.defs | egrep -c -i "sha512")" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        if [ -f rhel6_config.tar ]
        then
            backup /etc/login.defs
            echo "${stigID} tar xvfP /tmp/CMDB/Linux/rhel6_config.tar /etc/login.defs" >> "${HEALING_FILE}"
            STATUS="NF"
        else
            STATUS="O"
        fi
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038576:2:${STATUS}:The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (login.defs)."

########################################
stigID="RHEL-06-000064"

if [ "$(grep -c "crypt_style = sha512" /etc/libuser.conf)" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        backup /etc/libuser.conf
        echo "${stigID} grep -v \"^crypt_style\" /etc/libuser.conf > /tmp/RHEL-06-000064" >> "${HEALING_FILE}"
        echo "${stigID} sed '/\[defaults\]/a\\" >> "${HEALING_FILE}"
        echo "${stigID} crypt_style = sha512' /tmp/RHEL-06-000064 > /tmp/libuser.ot" >> "${HEALING_FILE}"
        echo "${stigID} mv /tmp/libuser.ot /etc/libuser.conf" >> "${HEALING_FILE}"
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038577:2:${STATUS}:The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf)."

########################################
stigID="RHEL-06-000065"

if [ "$(ls -l /etc/grub.conf | awk '{print $3}')" = "root" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       Owner="$(ls -l /etc/grub.conf | awk '{print $3}')"
       echo "${stigID} chown ${Owner} /etc/grub.conf" >> "${RECOVERY_FILE}"
       echo "${stigID} chown root /etc/grub.conf" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038579:2:${STATUS}:The system boot loader configuration file(s) must be owned by root."

########################################
stigID="RHEL-06-000066"

if [ "$(ls -l /etc/grub.conf | awk '{print $4}')" = "root" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       Group="$(ls -l /etc/grub.conf | awk '{print $4}')"
       echo "${stigID} chgrp ${Group} /etc/grub.conf" >> "${RECOVERY_FILE}"
       echo "${stigID} chgrp root /etc/grub.conf" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038581:2:${STATUS}:The system boot loader configuration file(s) must be group-owned by root."

########################################
stigID="RHEL-06-000067"

sName="/boot/grub/grub.conf"
sValidPerms="0600"
sActualPerms="$(stat --printf %04a "${sName}")"

if [ "${sActualPerms}" -eq "${sValidPerms}" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        echo "${stigID} ${CHMOD} ${sValidPerms} ${sName}" >> "${HEALING_FILE}"
        echo "${stigID} ${CHMOD} ${sActualPerms} ${sName}" >> "${RECOVERY_FILE}"
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038583:2:${STATUS}:The system boot loader configuration file(s) must have mode 0600 or less permissive."

########################################
stigID="RHEL-06-000068"

if [ "$(grep password /etc/grub.conf | grep -c "password --encrypted "$6$"")" -gt 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        backup /boot/grub/grub.conf
       ./grubGenerator6.sh
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038585:2:${STATUS}:The system boot loader must require authentication."

########################################
stigID="RHEL-06-000069"

if [ "$(grep -c "SINGLE=/sbin/sulogin" /etc/sysconfig/init)" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/sysconfig/init
       echo "${stigID} grep -v \"^SINGLE=\" /etc/sysconfig/init > /tmp/RHEL-06-000069" >> "${HEALING_FILE}"
       echo "${stigID} echo \"SINGLE=/sbin/sulogin\" >> /tmp/RHEL-06-000069" >> "${HEALING_FILE}"
       echo "${stigID} mv /tmp/RHEL-06-000069 /etc/sysconfig/init" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038586:2:${STATUS}:The system must require authentication upon booting into single-user and maintenance modes."

########################################
stigID="RHEL-06-000070"

if [ "$(grep -c "PROMPT=no" /etc/sysconfig/init)" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/sysconfig/init
       echo "${stigID} grep -v \"^PROMPT=\" /etc/sysconfig/init > /tmp/RHEL-06-000070" >> "${HEALING_FILE}"
       echo "${stigID} echo \"PROMPT=no\" >> /tmp/RHEL-06-000070" >> "${HEALING_FILE}"
       echo "${stigID} mv /tmp/RHEL-06-000070 /etc/sysconfig/init" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038588:2:${STATUS}:The system must not permit interactive boot."

########################################
stigID="RHEL-06-000071"

if [ "$(rpm -q screen | grep -c "not installed")" -eq 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       if [ -f /tmp/CMDB/Linux/screen-4.0.3-19.el6.x86_64.rpm ]
       then
          echo "${stigID} rpm -ivh /tmp/CMDB/Linux/screen-4.0.3-19.el6.x86_64.rpm" >> "${HEALING_FILE}"
          STATUS="NF"
       fi
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038590:3:${STATUS}:The system must allow locking of the console screen in text mode."

########################################
stigID="RHEL-06-000073"
#!!!!!!!
echo "${stigID}:V0038593:2:NF:The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, console login prompts."

########################################
stigID="RHEL-06-000078"

if [ "$(sysctl kernel.randomize_va_space | grep -c "kernel.randomize_va_space = 2")" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/sysctl.conf
       if [ "$(grep -c "^kernel.randomize_va_space" /etc/sysctl.conf)" -gt 0 ]
       then
          VAL="$(grep "^kernel.randomize_va_space" /etc/sysctl.conf | awk -F"=" '{print $2}')"
          if [ "${VAL}" -ne 1 -o "${VAL}" -ne 2 ]
          then
             echo "${stigID} grep -v \"^kernel.randomize_va_space\" /etc/sysctl.conf > /tmp/d" >> "${HEALING_FILE}"
                 echo "${stigID} mv /tmp/d /etc/sysctl.conf" >> "${HEALING_FILE}"
             echo "${stigID} echo \"kernel.randomize_va_space = 2\" >> /etc/sysctl.conf" >> "${HEALING_FILE}"
         fi
       else
          echo "${stigID} echo \"kernel.randomize_va_space = 2\" >> /etc/sysctl.conf" >> "${HEALING_FILE}"
       fi
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038596:2:${STATUS}:The system must implement virtual address space randomization."

########################################
stigID="RHEL-06-000079"

if [ "$(sysctl kernel.exec-shield | grep -c "kernel.exec-shield = 1")" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/sysctl.conf
       if [ "$(grep -c "^kernel.exec-shield" /etc/sysctl.conf)" -gt 0 ]
       then
          VAL="$(grep "^kernel.exec-shield" /etc/sysctl.conf | awk -F"=" '{print $2}')"
           if [ "${VAL}" -ne 1 ]
           then
              echo "${stigID} grep -v \"^kernel.exec-shield\" /etc/sysctl.conf > /tmp/b" >> "${HEALING_FILE}"
                  echo "${stigID} mv /tmp/b /etc/sysctl.conf" >> "${HEALING_FILE}"
              echo "${stigID} echo \"kernel.exec-shield = 1\" >> /etc/sysctl.conf" >> "${HEALING_FILE}"
          fi
       else
          echo "${stigID} echo \"kernel.exec-shield = 1\" >> /etc/sysctl.conf" >> "${HEALING_FILE}"
       fi
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038597:2:${STATUS}:The system must limit the ability of processes to have simultaneous write and execute access to memory."

########################################
stigID="RHEL-06-000080"

f_SYSCTL_CHECK RHEL-06-000080 net.ipv4.conf.default.send_redirects "0"
echo "${stigID}:V0038600:2:${STATUS}:The system must not send ICMPv4 redirects by default."

########################################
stigID="RHEL-06-000081"

f_SYSCTL_CHECK RHEL-06-000081 net.ipv4.conf.all.send_redirects "0"
echo "${stigID}:V0038601:2:${STATUS}:The system must not send ICMPv4 redirects from any interface."

########################################
stigID="RHEL-06-000082"

f_SYSCTL_CHECK RHEL-06-000082 net.ipv4.ip_forward "0"
echo "${stigID}:V0038511:2:${STATUS}:IP forwarding for IPv4 must not be enabled, unless the system is a router."

########################################
stigID="RHEL-06-000083"

f_SYSCTL_CHECK RHEL-06-000083 net.ipv4.conf.all.accept_source_route "0"
echo "${stigID}:V0038523:2:${STATUS}:The system must not accept IPv4 source-routed packets on any interface."

########################################
stigID="RHEL-06-000084"

f_SYSCTL_CHECK RHEL-06-000084 net.ipv4.conf.all.accept_redirects "0"
echo "${stigID}:V0038524:2:${STATUS}:The system must not accept ICMPv4 redirect packets on any interface."

########################################
stigID="RHEL-06-000086"

f_SYSCTL_CHECK RHEL-06-000086 net.ipv4.conf.all.secure_redirects "0"
echo "${stigID}:V0038526:2:${STATUS}:The system must not accept ICMPv4 secure redirect packets on any interface."

########################################
stigID="RHEL-06-000088"

f_SYSCTL_CHECK RHEL-06-000088 net.ipv4.conf.all.log_martians "1"
echo "${stigID}:V0038528:3:${STATUS}:The system must log Martian packets."

########################################
stigID="RHEL-06-000089"

f_SYSCTL_CHECK RHEL-06-000089 net.ipv4.conf.default.accept_source_route "0"
echo "${stigID}:V0038529:2:${STATUS}:The system must not accept IPv4 source-routed packets by default."

########################################
stigID="RHEL-06-000090"

f_SYSCTL_CHECK RHEL-06-000090 net.ipv4.conf.default.secure_redirects "0"
echo "${stigID}:V0038532:2:${STATUS}:The system must not accept ICMPv4 secure redirect packets by default."

########################################
stigID="RHEL-06-000091"

f_SYSCTL_CHECK RHEL-06-000091 net.ipv4.conf.default.accept_redirects "0"
echo "${stigID}:V0038533:3:${STATUS}:The system must ignore IPv4 ICMP redirect messages."

########################################
stigID="RHEL-06-000092"

f_SYSCTL_CHECK RHEL-06-000092 net.ipv4.icmp_echo_ignore_broadcasts "1"
echo "${stigID}:V0038535:3:${STATUS}:The system must not respond to ICMPv4 sent to a broadcast address."

########################################
stigID="RHEL-06-000093"

f_SYSCTL_CHECK RHEL-06-000093 net.ipv4.icmp_ignore_bogus_error_responses "1"
echo "${stigID}:V0038537:3:${STATUS}:The system must ignore ICMPv4 bogus error responses."

########################################
stigID="RHEL-06-000095"

f_SYSCTL_CHECK RHEL-06-000095 net.ipv4.tcp_syncookies "1"
echo "${stigID}:V0038539:2:${STATUS}:The system must be configured to use TCP syncookies."

########################################
stigID="RHEL-06-000096"

f_SYSCTL_CHECK RHEL-06-000096 net.ipv4.conf.all.rp_filter "1"
echo "${stigID}:V0038542:2:${STATUS}:The system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces."

########################################
stigID="RHEL-06-000097"

f_SYSCTL_CHECK RHEL-06-000097 net.ipv4.conf.default.rp_filter "1"
echo "${stigID}:V0038544:2:${STATUS}:The system must use a reverse-path filter for IPv4 network traffic when possible by default."

########################################
stigID="RHEL-06-000098"

if [ "$(lsmod | grep -c "ipv6")" -gt 0 ]
then
    if [ "$(grep -r ipv6 /etc/modprobe.d | grep -c "options ipv6 disable=1")" -gt 0 ]
    then
    STATUS="NF"
    else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/modprobe.d/stig-items.conf
       echo "${stigID} echo \"options ipv6 disable=1\" >> /etc/modprobe.d/stig-items.conf" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
    fi
else
   STATUS="NF"
fi
echo "${stigID}:V0038546:2:${STATUS}:The IPv6 protocol handler must not be bound to the network stack unless needed."

########################################
stigID="RHEL-06-000099"

if [ "$(lsmod | grep -c "ipv6")" -gt 0 ]
then
    if [ "$(sysctl net.ipv6.conf.default.accept_redirects | grep -c "net.ipv6.conf.default.accept_redirects = 0")" -eq 1 ]
    then
        STATUS="NF"
    else
        if [ "${HEALING}" = "YES" ]
        then
            backup /etc/sysctl.conf
            if [ "$(grep -c "net.ipv6.conf.default.accept_redirects" /etc/sysctl.conf)" -eq 0 ]
            then
                echo "${stigID} echo \"net.ipv6.conf.default.accept_redirects = 0\" >> /etc/sysctl.conf" >> "${HEALING_FILE}"
            STATUS="NF"
            fi
        else
            STATUS="O"
        fi
    fi
else
   STATUS="NF"
fi
echo "${stigID}:V0038548:2:${STATUS}:The system must ignore ICMPv6 redirects by default."

########################################
stigID="RHEL-06-000103"

if [ "$(lsmod | grep -c "ipv6")" -gt 0 ]
then
    if [ "$(service ip6tables status | grep -c "not running")" -eq 0 ]
    then
        STATUS="NF"
    else
        if [ "${HEALING}" = "YES" ]
        then
            IP6TABLES="1"
            if [ ! -s /etc/sysconfig/ip6tables ]; then
                gen_ip6tables
            else
                echo "${stigID} /sbin/service ip6tables start" >> "${HEALING_FILE}"
            fi
            backup /etc/sysconfig/ip6tables
            STATUS="NF"
        else
            STATUS="O"
        fi
    fi
else
    STATUS="NF"
fi
echo "${stigID}:V0038549:2:${STATUS}:The system must employ a local IPv6 firewall."

########################################
stigID="RHEL-06-000106"

if [ "$(lsmod | grep -c "ipv6")" -gt 0 ]
then
    if [ "$(service ip6tables status | grep -c "not running")" -eq 0 -o "${IP6TABLES}" -eq 1 ]
    then
        STATUS="NF"
    else
        if [ "${HEALING}" = "YES" ]
        then
            STATUS="NF"
        else
            STATUS="O"
        fi
    fi
else
    STATUS="NF"
fi
echo "${stigID}:V0038551:2:${STATUS}:The operating system must connect to external networks or information systems only through managed IPv6 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture."

########################################
stigID="RHEL-06-000107"

if [ "$(lsmod | grep -c "ipv6")" -gt 0 ]
then
    if [ "$(service ip6tables status | grep -c "not running")" -eq 0 -o "${IP6TABLES}" -eq 1 ]
    then
        STATUS="NF"
    else
        if [ "${HEALING}" = "YES" ]
        then
            STATUS="NF"
        else
            STATUS="O"
        fi
        STATUS="O"
    fi
else
    STATUS="NF"
fi
echo "${stigID}:V0038553:2:${STATUS}:The operating system must prevent public IPv6 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices."

########################################
stigID="RHEL-06-000113"

if [ "${HEALING}" = "YES" ]; then
    echo "${stigID} echo \"Manual Review - The iptables service provides the system's host-based fire-walling capability for IPv4 and ICMP.""\"" >> "${HEALING_FILE}"
fi
echo "${stigID}:V0038555:2:${NR}:The iptables service provides the system's host-based fire-walling capability for IPv4 and ICMP."

########################################
stigID="RHEL-06-000116"
if [ "$(service iptables status | grep -c "not running")" -eq 0 -o "${IPTABLES}" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038560:2:${STATUS}:The operating system must connect to external networks or information systems only through managed IPv4 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture."

########################################
stigID="RHEL-06-000117"

if [ "$(lsmod | grep -c "ipv4")" -gt 0 ]
then
   if [ "$(service iptables status | grep -c "not running")" -eq 0 -o "${IPTABLES}" -eq 1 ]
   then
    STATUS="NF"
   else
    STATUS="O"
   fi
else
   STATUS="NF"
fi
echo "${stigID}:V0038512:2:${STATUS}:The operating system must prevent public IPv4 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices."

########################################
stigID="RHEL-06-000120"

if [ "$(grep "\:INPUT" /etc/sysconfig/iptables | grep -c "DROP")" -eq 1 ]
then
        STATUS="NF"
else
        if [ "${HEALING}" = "YES" ]
        then
           backup /etc/sysconfig/iptables
           echo "${stigID} grep -v \":INPUT ACCEPT\" /etc/sysconfig/iptables > ${RECOVER_DIR}/${stigID}" >> "${HEALING_FILE}"
           echo "${stigID} mv ${RECOVER_DIR}/${stigID} /etc/sysconfig/iptables" >> "${HEALING_FILE}"
           echo "${stigID} sed '/*filter/a\\" >> "${HEALING_FILE}"
           echo "${stigID} :INPUT DROP [0:0]' /etc/sysconfig/iptables > ${RECOVER_DIR}/${stigID}" >> "${HEALING_FILE}"
           echo "${stigID} mv ${RECOVER_DIR}/${stigID} /etc/sysconfig/iptables" >> "${HEALING_FILE}"
           echo "${stigID} chown root:root /etc/sysconfig/iptables" >> "${HEALING_FILE}"
           echo "${stigID} chmod 600 /etc/sysconfig/iptables" >> "${HEALING_FILE}"
           echo "${stigID} service iptables restart" >> "${HEALING_FILE}"
       STATUS="NF"
        else
           STATUS="O"
        fi
fi
if [ -f ${RECOVER_DIR}/${stigID} ]
then
    rm ${RECOVER_DIR}/${stigID}
fi
echo "${stigID}:V0038513:2:${STATUS}:The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound packets."

########################################
stigID="RHEL-06-000124"

if [ "$(grep -r dccp /etc/modprobe.d |grep -v "\#" |wc -l)" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038514:2:${STATUS}:The Datagram Congestion Control Protocol must be disabled unless required."

########################################
stigID="RHEL-06-000125"

if [ "$(grep -r sctp /etc/modprobe.d |grep -v "\#" |wc -l)" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038515:2:${STATUS}:The Stream Control Transmission Protocol must be disabled unless required."

########################################
stigID="RHEL-06-000126"

if [ "$(grep -r rds /etc/modprobe.d |grep -v "\#" |wc -l)" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038516:3:${STATUS}:The Reliable Datagram Sockets protocol must be disabled unless required."

########################################
stigID="RHEL-06-000127"

if [ "$(grep -r tipc /etc/modprobe.d |grep -v "\#" |wc -l)" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038517:2:${STATUS}:The Transparent Inter-Process Communication protocol must be disabled unless required."

########################################
stigID="RHEL-06-000128"

CHECK="0"
cat /etc/rsyslog.conf | grep -v "#" | awk '{print $2}' | grep -v "^$" |grep "^\/" | grep log|grep -v "/etc/rsyslog.d" > /tmp/RHEL-06-000133
for ENTRY in "$(cat /tmp/RHEL-06-000133)"
do
    if [ "$(ls -l "${ENTRY}" | awk '{print $3}')" != "root" ]
    then
       if [ "${HEALING}" = "YES" ]
       then
          Owner="$(ls -l "${ENTRY}" | awk '{print $3}')"
          echo "${stigID} chown ${Owner} ${ENTRY}" >> "${RECOVERY_FILE}"
          echo "${stigID} chown root ${ENTRY}" >> "${HEALING_FILE}"
        STATUS="NF"
       else
        CHECK="1"
       fi
    fi
done
if [ "${CHECK}" -eq 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
rm /tmp/RHEL-06-000133
echo "${stigID}:V0038518:2:${STATUS}:All rsyslog-generated log files must be owned by root."

########################################
stigID="RHEL-06-000134"

CHECK="0"
cat /etc/rsyslog.conf | grep -v "#" | awk '{print $2}' | grep -v "^$" | grep "^\/" | grep log | grep -v "/etc/rsyslog.d" > /tmp/RHEL-06-000134
for ENTRY in "$(cat /tmp/RHEL-06-000134)"
do
    if [ "$(ls -l "${ENTRY}" | awk '{print $4}')" != "root" ]
    then
       if [ "${HEALING}" = "YES" ]
       then
          Group="$(ls -l "${ENTRY}" | awk '{print $4}')"
          echo "${stigID} chgrp ${Group} ${ENTRY}" >> "${RECOVERY_FILE}"
          echo "${stigID} chgrp root ${ENTRY}" >> "${HEALING_FILE}"
        STATUS="NF"
       else
        CHECK="1"
       fi
        fi
done
if [ "${CHECK}" -eq 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
rm /tmp/RHEL-06-000134
echo "${stigID}:V0038519:2:${STATUS}:All rsyslog-generated log files must be group-owned by root."

########################################
stigID="RHEL-06-000135"

CHECK="0"
sValidPerms="0600"
cat /etc/rsyslog.conf | grep -v "#" | awk '{print $2}' | grep -v "^$" |grep "^\/" | grep log|grep -v "/etc/rsyslog.d" > /tmp/RHEL-06-000135

for ENTRY in "$(cat /tmp/RHEL-06-000135)"
do
	sActualPerms="$(stat --printf %04a "${ENTRY}")"
    if [ "${sActualPerms}" -le "${sValidPerms}" ]
    then
        STATUS="NF"
    else
        if [ "${HEALING}" = "YES" ]
        then
            echo "${stigID} chmod ${sValidPerms} ${ENTRY}"  >> "${HEALING_FILE}"
            echo "${stigID} chmod ${sActualPerms} ${ENTRY}" >> "${RECOVERY_FILE}"
            STATUS="NF"
        else
            CHECK="1"
        fi
    fi
done

if [ "${CHECK}" -eq 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi

rm /tmp/RHEL-06-000135
echo "${stigID}:V0038623:2:${STATUS}:All rsyslog-generated log files must have mode 0600 or less permissive."

########################################
stigID="RHEL-06-000136"

if [ "${HEALING}" = "YES" ]; then
    echo "${stigID} echo \"Manual Review - The operating system must back up audit records on an organization defined frequency onto a different system or media than the system being audited.""\"" >> "${HEALING_FILE}"
fi
echo "${stigID}:V0038520:2:NR:The operating system must back up audit records on an organization defined frequency onto a different system or media than the system being audited."

########################################
stigID="RHEL-06-000137"

if [ "${HEALING}" = "YES" ]; then
    echo "${stigID} echo \"Manual Review - The operating system must support the requirement to centrally manage the content of audit records generated by organization defined information system components.""\"" >> "${HEALING_FILE}"
fi
echo "${stigID}:V0038521:2:NR:The operating system must support the requirement to centrally manage the content of audit records generated by organization defined information system components."

########################################
stigID="RHEL-06-000138"

#grep "logrotate" /etc/cron* > /tmp/RHEL-06-000138
#grep "logrotate" /var/spool/cron/* >> RHEL-06-000138
grep "logrotate" /var/log/cron* > RHEL-06-000138
#if [ `grep -c "uvscan" RHEL-06-000138` -gt 0 ]
if [ "$(grep "cron.daily" RHEL-06-000138 |grep -c "finished logrotate")" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
rm RHEL-06-000138
echo "${stigID}:V0038624:3:${STATUS}:System logs must be rotated daily."

########################################
stigID="RHEL-06-000139"
if [ "$(service auditd status | grep -c "is running")" -gt 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} /sbin/service auditd restart" >> "${HEALING_FILE}"
       echo "${stigID} /sbin/service auditd stop" >> "${RECOVERY_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038628:2:${STATUS}:The operating system must produce audit records containing sufficient information to establish the identity of any user/subject associated with the event."

########################################
stigID="RHEL-06-000145"

if [ "$(service auditd status | grep -c "is running")" -gt 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} /sbin/service auditd restart" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038631:2:${STATUS}:The operating system must employ automated mechanisms to facilitate the monitoring and control of remote access methods."

########################################
stigID="RHEL-06-000148"

if [ "$(service auditd status | grep -c "is running")" -gt 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} /sbin/service auditd restart" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038632:2:${STATUS}:The operating system must produce audit records containing sufficient information to establish what type of events occurred."

########################################
stigID="RHEL-06-000159"

if [ "$(grep "num_logs" /etc/audit/auditd.conf | awk -F= '{print $2}')" -ge 5 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038636:2:${STATUS}:The system must retain enough rotated audit logs to cover the required log retention period"

########################################
stigID="RHEL-06-000160"

if [ "$(grep "max_log_file =" /etc/audit/auditd.conf| awk -F= '{print $2}')" -ge 6 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038633:2:${STATUS}:The system must set a maximum audit log file size."
stigID="RHEL-06-000161"

get_audit_action max_log_file_action
echo "${stigID}:V0038634:2:${STATUS}:The system must rotate audit log files that reach the maximum file size."

########################################

stigID="RHEL-06-000163"

get_audit_action admin_space_left_action
if [ "${HEALING}" = "YES" -a "${VAR}" != "single" ]
then
   backup /etc/audit/auditd.conf
   echo "${stigID} grep -v \"^admin_space_left_action\" /etc/audit/auditd.conf > /tmp/RHEL-06-000163" >> "${HEALING_FILE}"
   echo "${stigID} echo \"admin_space_left_action = single\" >> /tmp/RHEL-06-000163" >> "${HEALING_FILE}"
   echo "${stigID} mv /tmp/RHEL-06-000163 /etc/audit/auditd.conf" >> "${HEALING_FILE}"
   echo "${stigID} restorecon -vvFR /etc/audit/auditd.conf" >> "${HEALING_FILE}"
   echo "${stigID} /sbin/service auditd restart" >> "${HEALING_FILE}"
   STATUS="NF"
fi
echo "${stigID}:V0038470:2:${STATUS}:The audit system must alert designated staff members when the audit admin storage volume approaches capacity."

########################################
stigID="RHEL-06-000165"

if [ "$(auditctl -l | grep -c adjtimex)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038635:3:${STATUS}:The audit system must be configured to audit all attempts to alter system time through adjtimex."

########################################
stigID="RHEL-06-000167"

if [ "$(auditctl -l | grep -c settimeofday)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038522:3:${STATUS}:The audit system must be configured to audit all attempts to alter system time through settimeofday."

########################################
stigID="RHEL-06-000169"

if [ "$(auditctl -l | grep -c stime)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038525:3:${STATUS}:The audit system must be configured to audit all attempts to alter system time through stime."

########################################
stigID="RHEL-06-000171"

if [ "$(auditctl -l | grep -c clock_settime)" -gt 0 ]
then
    STATUS="NF"
else
        STATUS="O"
fi
echo "${stigID}:V0038527:3:${STATUS}:The audit system must be configured to audit all attempts to alter system time through clock_settime."

########################################
stigID="RHEL-06-000173"

if [ "$(auditctl -l | grep -c "\-w /etc/localtime")" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038530:3:${STATUS}:The audit system must be configured to audit all attempts to alter system time through /etc/localtime."

########################################
stigID="RHEL-06-000174"

if [ "$(auditctl -l | egrep "/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd"| grep -c "\-p wa")" -eq 5 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038531:3:${STATUS}:The operating system must automatically audit account creation."

########################################
stigID="RHEL-06-000175"

if [ "$(auditctl -l | egrep "/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd"| grep -c "\-p wa")" -eq 5 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038534:3:${STATUS}:The operating system must automatically audit account modification."

########################################
stigID="RHEL-06-000176"

if [ "$(auditctl -l | egrep "/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd"| grep -c "\-p wa")" -eq 5 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038536:3:${STATUS}:The operating system must automatically audit account disabling actions."

########################################
stigID="RHEL-06-000177"

if [ "$(auditctl -l | egrep "/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd"| grep -c "\-p wa")" -eq 5 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038538:3:${STATUS}:The operating system must automatically audit account termination."

########################################
stigID="RHEL-06-000182"

if [ "$(auditctl -l | egrep -c "sethostname|setdomainname")" -eq 2 ]
then
    if [ "$(auditctl -l | egrep "/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network"| grep -c "\-p wa")" -eq 4 ]
    then
        STATUS="NF"
    else
        STATUS="O"
     fi
else
    STATUS="O"
fi
echo "${stigID}:V0038540:3:${STATUS}:The audit system must be configured to audit modifications to the systems network configuration."

########################################
stigID="RHEL-06-000183"

if [ "$(auditctl -l | grep "/etc/selinux" | grep -c "\-p wa")" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038541:3:${STATUS}:The audit system must be configured to audit modifications to the systems Mandatory Access Control MAC configuration SELinux."

########################################
stigID="RHEL-06-000184"

if [ "$(auditctl -l | grep "chmod" | grep -c "auid=0")" -gt 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ];
    then
       if [ -f auditFix.sh ]; then
        cp auditFix.sh "${RECOVER_DIR}"
        chmod "700" ${RECOVER_DIR}/auditFix.sh
        echo "${stigID} ./auditFix.sh" >> "${HEALING_FILE}"
            STATUS="NF"
       fi
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038543:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using chmod."

########################################
stigID="RHEL-06-000185"

if [ "$(auditctl -l | grep -c chown)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038545:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using chown."

########################################
stigID="RHEL-06-000186"

if [ "$(auditctl -l |  grep -c fchmod)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038547:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using fchmod."

########################################
stigID="RHEL-06-000187"

if [ "$(auditctl -l |  grep -c fchmodat)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038550:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using fchmodat."

########################################
stigID="RHEL-06-000188"

if [ "$(auditctl -l | grep -c fchown)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038552:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using fchown."

########################################
stigID="RHEL-06-000189"

if [ "$(auditctl -l | grep -c fchownat)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038554:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using fchownat."

########################################
stigID="RHEL-06-000190"

if [ "$(auditctl -l |  grep -c fremovexattr)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038556:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using fremovexattr."

########################################
stigID="RHEL-06-000191"

if [ "$(auditctl -l | grep -c fsetxattr)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038557:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using fsetxattr."

########################################
stigID="RHEL-06-000192"

if [ "$(auditctl -l | grep -c lchown)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038558:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using lchown."

########################################
stigID="RHEL-06-000193"

if [ "$(auditctl -l | grep -c lremovexattr)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038559:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using lremovexattr."

########################################
stigID="RHEL-06-000194"

if [ "$(auditctl -l | grep -c lsetxattr)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038561:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using lsetxattr."

########################################
stigID="RHEL-06-000195"

if [ "$(auditctl -l | grep -c removexattr)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038563:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using removexattr."

########################################
stigID="RHEL-06-000196"

if [ "$(auditctl -l | grep -c setxattr)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038565:3:${STATUS}:The audit system must be configured to audit all discretionary access control permission modifications using setxattr."

########################################
stigID="RHEL-06-000197"

if [ "$(grep -c "EACCES" /etc/audit/audit.rules`" -gt 0 -a "`grep -c "EPERM" /etc/audit/audit.rules)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038566:3:${STATUS}:The audit system must be configured to audit failed attempts to access files and programs."

########################################
stigID="RHEL-06-000198"

CHECK="0"
find / -xdev -type f -perm -4000 -o -perm -2000 1>/tmp/RHEL-06-000198 2>/dev/null
if [ -s /tmp/RHEL-06-000198 ]
then
    grep -v "\/bladelogic" /tmp/RHEL-06-000198 > /tmp/a
    mv /tmp/a /tmp/RHEL-06-000198
    for FILE in "$(cat /tmp/RHEL-06-000198)"
    do
        if [ "$(grep -c "${FILE}" /etc/audit/audit.rules)" -eq 0 ]
        then
            if [ "${HEALING}" = "YES" ]
            then
                echo "${stigID} grep -v \"^\-e\" /etc/audit/audit.rules > /tmp/a" >> "${HEALING_FILE}"
                echo "${stigID} echo \"-a always,exit -F path=${FILE} -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged\" >> /tmp/a" >> "${HEALING_FILE}"
                echo "${stigID} echo \"-e 1\" >> /tmp/a" >> "${HEALING_FILE}"
                echo "${stigID} mv /tmp/a /etc/audit/audit.rules" >> "${HEALING_FILE}"
                CHECK="1"
                STATUS="NF"
            else
                STATUS="O"
            fi
        fi
    done
fi

if [ "${HEALING}" = "YES" -a "${CHECK}" = 1 ]
    then
        backup /etc/audit/audit.rules
        echo "${stigID} chmod 640 /etc/audit/audit.rules" >> "${HEALING_FILE}"
        echo "${stigID} /sbin/service auditd restart" >> "${HEALING_FILE}"
fi

rm /tmp/RHEL-06-000198
echo "${stigID}:V0038567:3:${STATUS}:The audit system must be configured to audit all use of setuid programs."

########################################
stigID="RHEL-06-000199"

if [ "$(auditctl -l |  grep -c mount)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038568:3:${STATUS}:The audit system must be configured to audit successful file system mounts."

########################################
stigID="RHEL-06-000200"

if [ "$(auditctl -l | grep -c "/etc/sudoers")" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038575:3:${STATUS}:The audit system must be configured to audit user deletions of files and programs."

########################################
stigID="RHEL-06-000201"

if [ "$(auditctl -l | grep -c "/etc/sudoers")" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038578:3:${STATUS}:The audit system must be configured to audit changes to the /etc/sudoers file."

########################################
stigID="RHEL-06-000202"

if [ "$(auditctl -l | grep -c "/sbin/insmod")" -gt 0 ]
then
    if [ "$(auditctl -l | grep -c "/sbin/rmmod")" -gt 0 ]
    then
        if [ "$(auditctl -l | grep -c "/sbin/modprobe")" -gt 0 ]
        then
            if [ "$(auditctl -l | grep -c "init_module")" -gt 0 ]
            then
                if [ "$(auditctl -l | grep -c "delete_module")" -gt 0 ]
                then
                    STATUS="NF"
                fi
            fi
        fi
    fi
else
    STATUS="O"
fi
echo "${stigID}:V0038580:2:${STATUS}:The audit system must be configured to audit the loading and unloading of dynamic kernel modules."

########################################
stigID="RHEL-06-000203"

chk_service_off RHEL-06-000203 xinetd
echo "${stigID}:V0038582:2:${STATUS}:The xinetd service must be disabled if no network services utilizing it are enabled."

########################################
stigID="RHEL-06-000204"

if [ "$(rpm -q xinetd | grep -v grep | grep -c "xinetd-")" -eq 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} rpm -e --nodeps xinetd" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038584:3:${STATUS}:The xinetd service must be uninstalled if no network services utilizing it are enabled."

########################################
stigID="RHEL-06-000206"

if [ "$(rpm -q telnet-server | grep -c "not installed")" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} rpm -e --nodeps telnet-server" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038587:1:${STATUS}:The telnet-server package must not be installed."

########################################
stigID="RHEL-06-000207"

chk_service_off RHEL-06-000211 telnet
echo "${stigID}:V0038589:1:${STATUS}:The telnet daemon must not be running."

########################################
stigID="RHEL-06-000213"

if [ "$(rpm -q rsh-server | grep -c "not installed")" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} rpm -e --nodeps rsh-server" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038591:1:${STATUS}:The rsh-server package must not be installed."

########################################
stigID="RHEL-06-000214"

chk_service_off RHEL-06-000214 rsh
echo "${stigID}:V0038594:1:${STATUS}:The rshd service must not be running."

########################################
stigID="RHEL-06-000215"

chk_service_off RHEL-06-000216 rexec
echo "${stigID}:V0038598:1:${STATUS}:The rexecd service must not be running."

########################################
stigID="RHEL-06-000217"

chk_service_off RHEL-06-000218 rlogin
echo "${stigID}:V0038602:1:${STATUS}:The rlogind service must not be running."

########################################
stigID="RHEL-06-000220"

if [ "$(rpm -q ypserv | grep -c "not installed")" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} rpm -e --nodeps ypserv" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038603:2:${STATUS}:The ypserv package must not be installed."

########################################
stigID="RHEL-06-000221"

chk_service_off RHEL-06-000221 ypbind
echo "${stigID}:V0038604:2:${STATUS}:The ypbind service must not be running."

########################################
stigID="RHEL-06-000222"

if [ "$(rpm -q tftp-server | grep -c "is not installed")" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} rpm -e --nodeps tftp-server" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038606:2:${STATUS}:The tftp-server package must not be installed."

########################################
stigID="RHEL-06-000223"

chk_service_off RHEL-06-000223 tftp-server
echo "${stigID}:V0038609:2:${STATUS}:The TFTP service must not be running."

########################################
stigID="RHEL-06-000224"

if [ "$(service crond status |grep -c "is running")" -gt 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} /sbin/service crond restart" >> "${HEALING_FILE}"
       echo "${stigID} /sbin/service crond stop" >> "${RECOVERY_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038605:2:${STATUS}:The cron service must be running."

########################################
stigID="RHEL-06-000227"

if [ "$(grep "^Protocol" /etc/ssh/sshd_config|awk '{print $2}' | sed 's/ //g')" -eq 2 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038607:1:${STATUS}:The SSH daemon must be configured to use only the SSHv2 protocol."

########################################
stigID="RHEL-06-000230"

if [ "$(grep ClientAliveInterval /etc/ssh/sshd_config | grep -v "#" | grep -c "900")" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038608:3:${STATUS}:The SSH daemon must set a timeout interval on idle sessions."

########################################
stigID="RHEL-06-000231"

if [ "$(grep ClientAliveCountMax /etc/ssh/sshd_config | grep -v "#" | grep -c "0")" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038610:3:${STATUS}:The SSH daemon must set a timeout count on idle sessions."

########################################
stigID="RHEL-06-000234"

if [ "$(grep -i IgnoreRhosts /etc/ssh/sshd_config | grep -v "#" | grep -c "no")" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038611:2:${STATUS}:The SSH daemon must ignore .rhosts files."

########################################
stigID="RHEL-06-000236"

if [ "$(grep -i HostbasedAuthentication /etc/ssh/sshd_config | grep -v "#" | grep -c "no")" -gt 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/ssh/sshd_config
       echo "${stigID} grep -v \"^HostbasedAuthentication\" /etc/ssh/sshd_config > /tmp/e" >> "${HEALING_FILE}"
       echo "${stigID} mv /tmp/e /etc/ssh/sshd_config" >> "${HEALING_FILE}"
       echo "${stigID} echo \"HostbasedAuthentication  no\" >> /etc/ssh/sshd_config" >> "${HEALING_FILE}"
       echo "${stigID} service sshd restart" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038612:2:${STATUS}:The SSH daemon must not allow host-based authentication."

########################################
stigID="RHEL-06-000237"

if [ "$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config | grep -v "#" | awk '{print $2}')" = no ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/ssh/sshd_config
       echo "${stigID} grep -v \"^PermitRootLogin\" /etc/ssh/sshd_config > /tmp/e" >> "${HEALING_FILE}"
       echo "${stigID} mv /tmp/e /etc/ssh/sshd_config" >> "${HEALING_FILE}"
       echo "${stigID} echo \"PermitRootLogin  no\" >> /etc/ssh/sshd_config" >> "${HEALING_FILE}"
       echo "${stigID} service sshd restart" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038613:2:${STATUS}:The system must not permit root logins using remote access programs such as ssh."

########################################
stigID="RHEL-06-000239"

if [ "$(grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config|awk '{print $2}')" = "no" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/ssh/sshd_config
       echo "${stigID} grep -v \"^PermitEmptyPasswords\" /etc/ssh/sshd_config > /tmp/e" >> "${HEALING_FILE}"
       echo "${stigID} mv /tmp/e /etc/ssh/sshd_config" >> "${HEALING_FILE}"
       echo "${stigID} echo \"PermitEmptyPasswords  no\" >> /etc/ssh/sshd_config" >> "${HEALING_FILE}"
       echo "${stigID} service sshd restart" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038614:1:${STATUS}:The SSH daemon must not allow authentication using an empty password."

########################################
stigID="RHEL-06-000240"

if [ "$(grep -i Banner /etc/ssh/sshd_config | grep -v "#" | awk '{print $2}')" = "/etc/issue" ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038615:2:${STATUS}:The SSH daemon must be configured with the Department of Defense login banner."

########################################
stigID="RHEL-06-000241"

if [ "$(grep -i "^PermitUserEnvironment" /etc/ssh/sshd_config | grep -v "#" | grep -c "no")" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038616:3:${STATUS}:The SSH daemon must not permit user environment settings."

########################################
stigID="RHEL-06-000243"

if [ "$(grep -i Ciphers /etc/ssh/sshd_config | grep -iv "aes" | grep -iv "3des" | wc -l)" = 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038617:2:${STATUS}:The SSH daemon must be configured to use only FIPS 140-2 approved ciphers."

########################################
stigID="RHEL-06-000246"

chk_service_off RHEL-06-000246 avahi-daemon
echo "${stigID}:V0038618:3:${STATUS}:The avahi service must be disabled."

########################################
stigID="RHEL-06-000247"

if [ "$(service ntpd status | grep -c "is running"`" -gt 0 -a "`chkconfig | grep "ntpd " | grep -c ":on")" -gt 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} chkconfig ntpd on" >> "${HEALING_FILE}"
       echo "${stigID} /sbin/service ntpd restart" >> "${HEALING_FILE}"
       echo "${stigID} /sbin/service ntpd stop" >> "${RECOVERY_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038620:2:${STATUS}:The system clock must be synchronized continuously, or at least daily."

########################################
stigID="RHEL-06-000248"

if [ "$(grep "^server " /etc/ntp.conf | egrep -c "[0-9]")" -gt 0 ]
then
   STATUS="NF"
else
   STATUS="O"
fi

echo "${stigID}:V0038621:2:${STATUS}:The system clock must be synchronized to an authoritative DoD time source."

########################################
stigID="RHEL-06-000249"

if [ "$(grep -v "^#" /etc/postfix/main.cf | egrep -c "inet_interfaces")" -eq 1 ]
then
   if [ "$(grep inet_interfaces /etc/postfix/main.cf | grep -v "#"| grep -i "localhost" |wc -l)" -eq 1 ]
   then
    STATUS="NF"
   else
        if [ "${HEALING}" = "YES" ]
    then
        echo "${stigID} grep -v \"^inet_interfaces\" /etc/postfix/main.cf > /tmp/b" >> "${HEALING_FILE}"
        echo "${stigID} mv /tmp/b /etc/postfix/main.cf" >> "${HEALING_FILE}"
        echo "${stigID} echo \"inet_interfaces = localhost\" >> /etc/postfix/main.cf" >> "${HEALING_FILE}"
        echo "${stigID} chmod 644 /etc/postfix/main.cf" >> "${HEALING_FILE}"
        echo "${stigID} /sbin/service postfix restart" >> "${HEALIG_FILE}"
        STATUS="NF"
    else
        STATUS="O"
    fi
   fi
else
   if [ "${HEALING}" = "YES" ]
   then
    echo "${stigID} grep -v \"^inet_interfaces\" /etc/postfix/main.cf > /tmp/b" >> "${HEALING_FILE}"
    echo "${stigID} mv /tmp/b /etc/postfix/main.cf" >> "${HEALING_FILE}"
    echo "${stigID} echo \"inet_interfaces = localhost\" >> /etc/postfix/main.cf" >> "${HEALING_FILE}"
    echo "${stigID} chmod 644 /etc/postfix/main.cf" >> "${HEALING_FILE}"
    echo "${stigID} /sbin/service postfix restart" >> "${HEALIG_FILE}"
    STATUS="NF"
   else
    STATUS="O"
   fi
fi
echo "${stigID}:V0038622:2:${STATUS}:Mail relaying must be restricted."

########################################
stigID="RHEL-06-000252"

if [ ! -f /etc/pam_ldap.conf ]
then
    STATUS="NF"
else
     if [ "$(grep -c "start_tls" /etc/pam_ldap.conf)" -eq 0 ]
     then
       STATUS="O"
     else
       STATUS="NF"
     fi
fi
echo "${stigID}:V0038625:2:${STATUS}:If the system is using LDAP for authentication or account information, the system must use a TLS connection using FIPS 140-2 approved cryptographic algorithms."

########################################
stigID="RHEL-06-000253"

#if [ `rpm -q openldap-servers | grep -c "is not installed"` -eq 0 ]
if [ ! -f /etc/pam_ldap.conf ]
then
    STATUS="NF"
else
    if [ "$(grep -c "cert" /etc/pam_ldap.conf)" -eq 0 ]
    then
       STATUS="O"
    else
       STATUS="NF"
    fi
fi
echo "${stigID}:V0038626:2:${STATUS}:The LDAP client must use a TLS connection using trust certificates signed by the site CA."

########################################
stigID="RHEL-06-000256"

if [ "$(rpm -q openldap-servers | grep -c "is not installed")" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038627:3:${STATUS}:The openldap-servers package must not be installed unless required."

########################################
stigID="RHEL-06-000257"

if [ -x /usr/bin/gconftool-2 ]; then
   if [ "$(gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_delay |grep -c "15")" -eq 1 ]
   then
    STATUS="NF"
   else
    if [ "${HEALING}" = "YES" ]; then
       echo "${stigID} gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type int --set /apps/gnome-screensaver/idle_delay 15" >> "${HEALING_FILE}"
      STATUS="NF"
    else
      STATUS="O"
        fi
   fi
else
   STATUS="NF"
fi
echo "${stigID}:V0038629:2:${STATUS}:The graphical desktop environment must set the idle timeout to no more than 15 minutes."

########################################
stigID="RHEL-06-000258"

if [ -x /usr/bin/gconftool-2 ]; then
   if [ "$(gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_activation_enabled |grep -c "true")" -eq 1 ]
   then
    STATUS="NF"
   else
    if [ "${HEALING}" = "YES" ]; then
       echo "${stigID} gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gnome-screensaver/idle_activation_enabled true" >> "${HEALING_FILE}"
      STATUS="NF"
    else
      STATUS="O"
        fi
    STATUS="O"
   fi
else
   STATUS="NF"
fi
echo "${stigID}:V0038630:2:${STATUS}:The graphical desktop environment must automatically lock after 15 minutes of inactivity and the system must require user to re-authenticate to unlock the environment."

########################################
stigID="RHEL-06-000259"

if [ -x /usr/bin/gconftool-2 ]; then
   if [ "$(gconftool-2 -g /apps/gnome-screensaver/lock_enabled|grep -c "true")" -eq 1 ]
   then
    STATUS="NF"
   else
    if [ "${HEALING}" = "YES" ]; then
       echo "${stigID} gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gnome-screensaver/lock_enabled true" >> "${HEALING_FILE}"
      STATUS="NF"
    else
      STATUS="O"
    fi
   fi
else
    STATUS="NF"
fi
echo "${stigID}:V0038638:2:${STATUS}:The graphical desktop environment must have automatic lock enabled."

########################################
stigID="RHEL-06-000260"

if [ -x /usr/bin/gconftool-2 ]; then
   if [ "$(gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/mode | grep -c "blank-only")" -eq 1 ]
   then
    STATUS="NF"
   else
    if [ "${HEALING}" = "YES" ]; then
       echo "${stigID} gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type string --set /apps/gnome-screensaver/mode blank-only" >> "${HEALING_FILE}"
      STATUS="NF"
    else
      STATUS="O"
    fi
   fi
else
    STATUS="NF"
fi
echo "${stigID}:V0038639:3:${STATUS}:The system must display a publicly-viewable pattern during a graphical desktop environment session lock."

########################################
stigID="RHEL-06-000261"

chk_service_off RHEL-06-000261 abrtd
echo "${stigID}:V0038640:3:${STATUS}:The Automatic Bug Reporting Tool abrtd service must not be running."

########################################
stigID="RHEL-06-000262"

chk_service_off RHEL-06-000262 atd
echo "${stigID}:V0038641:3:${STATUS}:The atd service must be disabled."

########################################
stigID="RHEL-06-000263"

chk_service_off RHEL-06-000265 ntpdate
echo "${stigID}:V0038644:3:${STATUS}:The ntpdate service must not be running."

########################################
stigID="RHEL-06-000266"

chk_service_off RHEL-06-000266 oddjobd
echo "${stigID}:V0038646:3:${STATUS}:The oddjobd service must not be running."

########################################
stigID="RHEL-06-000267"

chk_service_off RHEL-06-000267 qpidd
echo "${stigID}:V0038648:3:${STATUS}:The qpidd service must not be running."

########################################
stigID="RHEL-06-000268"

chk_service_off RHEL-06-000268 rdisc
echo "${stigID}:V0038650:3:${STATUS}:The rdisc service must not be running."

########################################
stigID="RHEL-06-000269"

if [ "$(mount | grep nfs | egrep -v "nodev|rpc_pipefs" | wc -l)" -eq 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038652:2:${STATUS}:Remote file systems must be mounted with the nodev option."

########################################
stigID="RHEL-06-000270"

if [ "$(mount | grep nfs | egrep -v "nosuid|rpc_pipefs" | wc -l)" -eq 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038654:2:${STATUS}:Remote file systems must be mounted with the nosuid option."

########################################
stigID="RHEL-06-000271"

if [ "$(grep -c noexec /etc/fstab)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038655:3:${STATUS}:The noexec option must be added to removable media partitions."

########################################
stigID="RHEL-06-000272"

if [ "$(rpm -q samba | grep -c "is not installed")" -eq 1 ]
then
    STATUS="NF"
fi
if [ "$(grep "^client signing" /etc/samba/smb.conf | egrep -c "mandatory")" -gt 0 ]
then
    STATUS="NF"
else
   if [ "${HEALING}" = "YES" ]
   then
        backup /etc/samba/smb.conf
		echo "${stigID} grep -v \"^client signing\" /etc/samba/smb.conf > /tmp/RHEL-06-000272" >> "${HEALING_FILE}"
		echo "${stigID} echo \"client signing = mandatory\" >> /tmp/RHEL-06-000272" >> "${HEALING_FILE}"
		echo "${stigID} mv /tmp/RHEL-06-000272 /etc/samba/smb.conf" >> "${HEALING_FILE}"
		STATUS="NF"
	else
		STATUS="O"
	fi
fi
echo "${stigID}:V0038656:3:${STATUS}:The system must use SMB client signing for connecting to samba servers using smbclient."

########################################
stigID="RHEL-06-000273"

if [ "$(rpm -q samba | grep -c "is not installed")" -eq 1 ]
then
    STATUS="NF"
elif [ "$(grep "sec" /etc/fstab | egrep -c "krb5i|ntlmv2i")" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038657:3:${STATUS}:The system must use SMB client signing for connecting to samba servers using mount.cifs."

########################################
stigID="RHEL-06-000274"

if [ "$(grep "remember" /etc/pam.d/system-auth | grep -c "remember=5")" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       DEFAULT=/etc/pam.d/system-auth
       backup "${DEFAULT}"
       if [ "$(grep -i -c "remember" "${DEFAULT}")" -gt 0 ]
       then
           VAL="$(grep -v "^#" /etc/pam.d/system-auth | grep remember | awk -F "remember=" '{print $2}'| awk '{print $1}'| sed 's/ //g')"
               Bit1="$(echo "${VAL}" |cut -c1)"
               Bit2="$(echo "${VAL}" |cut -c2)"
               HISTORY="${Bit1}${Bit2}"
               if [ "${HISTORY}X" != "X" ]
               then
                  if [ "${HISTORY}" -eq 24 -o "${HISTORY}" -lt 5 ]
          then
                     echo "${stigID} sed 's/remember=${HISTORY}/remember=5/g' ${DEFAULT} > /tmp/b" >> "${HEALING_FILE}"
                     echo "${stigID} mv /tmp/b ${DEFAULT}" >> "${HEALING_FILE}"
                  fi
               fi
           STATUS="NF"
       fi
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038658:2:${STATUS}:The system must prohibit the reuse of passwords within twenty-four iterations."

########################################
stigID="RHEL-06-000275"

if [ "${HEALING}" = "YES" ]; then
    echo "${stigID} echo \"Manual Review - The operating system must employ cryptographic mechanisms to protect information in storage.\"" >> "${HEALING_FILE}"
fi
echo "${stigID}:V0038659:3:NR:The operating system must employ cryptographic mechanisms to protect information in storage."

########################################
stigID="RHEL-06-000276"

if [ "${HEALING}" = "YES" ]; then
    echo "${stigID} echo \"Manual Review - The operating system must protect the confidentiality and integrity of data at rest.\"" >> "${HEALING_FILE}"
fi
echo "${stigID}:V0038661:3:NR:The operating system must protect the confidentiality and integrity of data at rest."

########################################
stigID="RHEL-06-000277"

if [ "${HEALING}" = "YES" ]; then
    echo "${stigID} echo \"Manual Review - The operating system must employ cryptographic mechanisms to prevent unauthorized disclosure of data at rest unless otherwise protected by alternative physical measures.\"" >> "${HEALING_FILE}"
fi
echo "${stigID}:V0038662:3:NR:The operating system must employ cryptographic mechanisms to prevent unauthorized disclosure of data at rest unless otherwise protected by alternative physical measures."

########################################
stigID="RHEL-06-000278"
#!!!!!!!!!!!!
#rpm -V audit | grep '^.M' | sed 's/ c / /' | grep -v "total" |awk '{print $2}' > /tmp/RHEL-06-000278
#for FILE in `cat /tmp/RHEL-06-000278`
#do
#    i=0
#    A=`rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\n]" audit | grep ${FILE}`
#    if [ -f ${FILE} ]
#    then
#        B=`ls -al ${FILE}| awk '{print $9" " $1}'`
#    else
#        B=`ls -ald ${FILE}|awk '{print $9" " $1}'`
#    fi
#    sValidPerms=`echo "${A}" | grep -v "total" | awk '{print $2}' | sed -e s/'\.$'//`
#    if [ -d ${FILE} ]
#    then
#        sActualPerms=`ls -ld ${FILE} | grep -v "total" | awk '{print $1}' | sed -e s/'\.$'//`
#    else
#        sActualPerms=`ls -l ${FILE} | grep -v "total" | awk '{print $1}' | sed -e s/'\.$'//`
#    fi
#if [[  "$sActualPerms" != "$sValidPerms" || "$sActualPerms" > "$sValidPerms" ]]
##    if [ ${sActualPerms} -ge ${sValidPerms} ]
#    then
#        if [ ${HEALING} = "YES" ]
#        then
#            getsetperms healing ${FILE}
#            getsetperms recovery ${FILE}
#            STATUS="NF"
#        else
#            CHECK=1
#        fi
#   fi
#done
#if [ ${CHECK} -eq 0 ]
#then
#    STATUS="NF"
#else
#    STATUS="O"
#fi
#rm /tmp/RHEL-06-000278

STATUS="NR"
echo "${stigID}:V0038663:2:${STATUS}:The system package management tool must verify permissions on all files and directories associated with the audit package."

########################################
stigID="RHEL-06-000279"

if [ "$(rpm -V audit | grep -c '^.....U')" -eq 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038664:2:${STATUS}:The system package management tool must verify ownership on all files and directories associated with the audit package."

########################################
stigID="RHEL-06-000280"

if [ "$(rpm -V audit | grep -c '^......G')" -eq 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038665:2:${STATUS}:The system package management tool must verify group-ownership on all files and directories associated with the audit package."

########################################
stigID="RHEL-06-000281"

if [ "$(rpm -V audit | grep -c '$1 ~ /..5/ && $2 != 'c'')" -eq 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038637:2:${STATUS}:The system package management tool must verify contents of all files associated with the audit package."

########################################
stigID="RHEL-06-000282"

if [ "$(awk '$3 ~ /^(ext|minix|reiserfs|sysv|tmpfs|ufs|xfs)/ {print $2}' /proc/mounts | xargs -iFS find FS -xdev -type f -perm -002 -exec stat -c %U:%G:%n "{}" \; > /tmp/${stigID}; cat /tmp/${stigID} | wc -l)" -eq 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        for file in "$(cat /tmp/${stigID})"
        do
            echo "${stigID} echo $file | awk -F: '{system(\"chmod o-w \"\$3)}'" >> "${HEALING_FILE}"
            echo "${stigID} echo $file | awk -F: '{system(\"chmod o+w \"\$3)}'" >> "${RECOVERY_FILE}"
        done
        STATUS="O"
    fi
fi
rm /tmp/RHEL-06-000282
echo "${stigID}:V0038643:2:${STATUS}:There must be no world-writable files on the system."

########################################
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#stigID="RHEL-06-000284"
#
#chk_service RHEL-06-000009 nails
#grep "uvscan" /etc/cron* > /tmp/RHEL-06-000284
#grep "uvscan" /var/spool/cron/* >> /tmp/RHEL-06-000284
#if [ `grep -c "uvscan" RHEL-06-000284` -gt 0 ]
#then
#    STATUS="NF"
#else
#    if [ ${HEALING} = "YES" ]
#    then
#       backup /var/spool/cron/root
#       echo "${stigID} echo "0 7 * * 0 /scripts/uvscan_check > /tmp/uv.ot 2>&1" >> /var/spool/cron/root" >> ${HEALING_FILE}
#           STATUS="NF"
#    else
#       STATUS="O"
#    fi
#fi
#rm /tmp/RHEL-06-000284

#Inspect the system for a cron job or system service which executes a virus scanning tool regularly.
#To verify the McAfee VSEL system service is operational, run the following command:
#
# /etc/init.d/nails status
#
#To check on the age of uvscan virus definition files, run the following command:
#
# cd /opt/NAI/LinuxShield/engine/dat
# ls -la avvscan.dat avvnames.dat avvclean.dat
#
#If virus scanning software does not run continuously, or at least daily, or has signatures that are out of date, this is a finding.


#echo "${stigID}:V0038666:1:${STATUS}:The system must use and update a DoD-approved virus scan program."

########################################
stigID="RHEL-06-000285"

if [ "$( ps -ef |grep -v grep | grep -c twagent)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038667:2:${STATUS}:The system must have a host-based intrusion detection tool installed."

########################################
stigID="RHEL-06-000286"

configFile=/etc/init/control-alt-delete.override
if [ -s "$configFile" ]; then
    egrep '^[       ]*exec /usr/bin/logger -p security.info \"Ctrl-Alt-Delete pressed\"' \
            "$configFile" > /dev/null
    if [ "$?" -eq 0 ]; then
        STATUS="NF"
    else
        if [ "${HEALING}" = "YES" ]
        then
            backup "${configFile}"
            echo "${stigID} grep -v \"^exec \" ${configFile} > ${RECOVER_DIR}/${stigID}" >> "${HEALING_FILE}"
            echo "${stigID} mv ${RECOVER_DIR}/${stigID} ${configFile}" >> "${HEALING_FILE}"
            echo "${stigID} echo 'exec /usr/bin/logger -p security.info \"Ctrl-Alt-Delete pressed\"' >> ${configFile}" >> "${HEALING_FILE}"
            echo "${stigID} chmod 644 ${configFile}" >> "${HEALING_FILE}"
            STATUS="NF"
        else
            STATUS="O"
        fi
    fi
else
    STATUS="O"
fi
if [ -f ${RECOVER_DIR}/${stigID} ]
then
    rm ${RECOVER_DIR}/${stigID}
fi
echo "${stigID}:V0038668:3:${STATUS}:The x86 Ctrl-Alt-Delete key sequence must be disabled."

########################################
stigID="RHEL-06-000287"

if [ "$(service postfix status | grep -c "is running")" -gt 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} /sbin/chkconfig postfix on" >> "${HEALING_FILE}"
       echo "${stigID} /sbin/chkconfig postfix off" >> "${RECOVERY_FILE}"
       echo "${stigID} /sbin/service postfix start" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038669:3:${STATUS}:The postfix service must be enabled for mail delivery."

########################################
stigID="RHEL-06-000288"

if [ "$(rpm -q sendmail | grep -c "is not installed")" -gt 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       echo "${stigID} rpm -e --nodeps sendmail" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038671:2:${STATUS}:The sendmail package must be removed."

########################################
stigID="RHEL-06-000289"

chk_service_off RHEL-06-000289 netconsole
echo "${stigID}:V0038672:3:${STATUS}:The netconsole service must be disabled unless required."

########################################
stigID="RHEL-06-000290"

if [ "$(grep initdefault /etc/inittab | grep -c "id:3:initdefault:")" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038674:2:${STATUS}:X Windows must not be enabled unless required."

########################################
stigID="RHEL-06-000291"

if [ "$(rpm -qi xorg-x11-server-common | grep -c "is not installed")" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038676:3:${STATUS}:The xorg-x11-server-common X Windows package must not be installed, unless required."

########################################
stigID="RHEL-06-000292"

CHECK="0"
ls -l /etc/sysconfig/network-scripts/ifcfg-* | grep -v "ifcfg-lo" |awk '{print $9}' > /tmp/RHEL-06-000292
#cat /tmp/RHEL-06-000292
for FILE in "$(cat /tmp/RHEL-06-000292)"
do
    egrep "BOOTPROTO|NETMASK|IPADDR|GATEWAY" "${FILE}" > /tmp/RHEL-06-000292-1
        if [ "$(grep -i "bootproto=" /tmp/RHEL-06-000292-1 | egrep -i -c "dhcp")" -gt 0 ]
        then
       CHECK="1"
       sed 's/^/RHEL-06-000292:/g' /tmp/RHEL-06-000292-1
        fi
done
rm /tmp/RHEL-06-000292 /tmp/RHEL-06-000292-1
if [ "${CHECK}" -eq 0 ]
then
   STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]; then
        ConfigDir='/etc/sysconfig/network-scripts/'
        ConfigFilenameBase="ifcfg-"
        for Interface in "$(ifconfig -a | awk '/^[A-Za-z]/ {print $1}')"
        do
            if [ "$Interface" = "lo" ]; then
                      continue
            fi
            if [ -f "${ConfigDir}${ConfigFilenameBase}${Interface}" ]; then
                if [ "$(grep -i "bootproto=" "${ConfigDir}${ConfigFilenameBase}${Interface}" | egrep -i -c "dhcp")" -gt 0 ]; then
                  backup "${ConfigDir}${ConfigFilenameBase}${Interface}"
                      echo "${stigID} /usr/bin/perl -pi -w -e 's/dhcp/static/g;' ${ConfigDir}${ConfigFilenameBase}${Interface}" >> "${HEALING_FILE}"
                  STATUS="NF"
                fi
            fi
        done
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038679:2:${STATUS}:The DHCP client must be disabled if not needed."

########################################
stigID="RHEL-06-000293"

if [ "$(pwck -rq |wc -l)" -eq 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038681:3:${STATUS}:All GIDs referenced in /etc/passwd must be defined in /etc/group"

########################################
stigID="RHEL-06-000295"

if [ "$(pwck -rq |wc -l)" -eq 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038683:3:${STATUS}:All accounts on the system must have unique user or account names"

########################################
stigID="RHEL-06-000297"

if [ "${HEALING}" = "YES" ]; then
    echo "${stigID} echo \"Manual Review - Temporary accounts must be provisioned with an expiration date.\"" >> "${HEALING_FILE}"
fi
echo "${stigID}:V0038685:3:NR:Temporary accounts must be provisioned with an expiration date."

########################################
stigID="RHEL-06-000298"

if [ "${HEALING}" = "YES" ]; then
    echo "${stigID} echo \"Manual Review - Emergency accounts must be provisioned with an expiration date.\"" >> "${HEALING_FILE}"
fi
echo "${stigID}:V0038690:3:NR:Emergency accounts must be provisioned with an expiration date."

########################################
stigID="RHEL-06-000299"

if [ "$(grep pam_cracklib /etc/pam.d/system-auth | grep -c "maxrepeat=3")" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038693:3:${STATUS}:The system must require passwords to contain no more than three consecutive repeating characters."

########################################
stigID="RHEL-06-000302"
if [ "$(rpm -q aide | grep -c "is not installed")" -eq 0 ]
then
   if [ "$(grep -c "\/aide" /etc/crontab)" -eq 0 ]
   then
    if [ "${HEALING}" = "YES" ]
    then
       FOUND_AIDE="1"
       backup /etc/crontab
       echo "${stigID} echo \"05 4 * * * root /usr/sbin/aide --check\" >> /etc/crontab" >> "${HEALING_FILE}"
       STATUS="NF"
        else
       STATUS="O"
    fi
   else
    STATUS="NF"
   fi
else
   STATUS="O"
fi
echo "${stigID}:V0038695:2:${STATUS}:A file integrity tool must be used at least weekly to check for unauthorized file changes, particularly the addition of unauthorized system libraries or binaries, or for unauthorized modification to authorized system libraries or binaries."

########################################
stigID="RHEL-06-000303"

if [ "$(rpm -q aide | grep -c "is not installed")" -eq 0 ]
then
   if [ "$(grep -c "\/aide" /etc/crontab)" -eq 0 ]
   then
    if [ "${HEALING}" = "YES" -a "${FOUND_AIDE}" -eq 0 ]
    then
       backup /etc/crontab
       echo "${stigID} echo \"05 4 * * * root /usr/sbin/aide --check\" >> /etc/crontab" >> "${HEALING_FILE}"
       STATUS="NF"
        else
       STATUS="O"
    fi
   else
    STATUS="NF"
   fi
else
   STATUS="O"
fi
echo "${stigID}:V0038696:2:${STATUS}:The operating system must employ automated mechanisms, per organization defined frequency, to detect the addition of unauthorized components/devices into the operating system."

########################################
stigID="RHEL-06-000304"

if [ "$(rpm -q aide | grep -c "aide")" -gt 0 ]
then
   if [ "$(grep -c "\/aide" /etc/crontab)" -eq 0 ]
   then
    if [ "${HEALING}" = "YES" -a "${FOUND_AIDE}" -eq 0 ]
    then
       backup /etc/crontab
       echo "${stigID} echo \"05 4 * * * root /usr/sbin/aide --check\" >> /etc/crontab" >> "${HEALING_FILE}"
       STATUS="NF"
        else
       STATUS="O"
    fi
   else
    STATUS="NF"
   fi
else
   STATUS="O"
fi
echo "${stigID}:V0038698:2:${STATUS}:The operating system must employ automated mechanisms to detect the presence of unauthorized software on organizational information systems and notify designated organizational officials in accordance with the organization defined frequency."

########################################
stigID="RHEL-06-000305"

if [ "$(rpm -q aide | grep -c "is not installed")" -eq 0 ]
then
   if [ "$(grep -c "\/aide" /etc/crontab)" -eq 0 ]
   then
    if [ "${HEALING}" = "YES" -a "${FOUND_AIDE}" -eq 0 ]
    then
       backup /etc/crontab
       echo "${stigID} echo \"05 4 * * * root /usr/sbin/aide --check\" >> /etc/crontab" >> "${HEALING_FILE}"
       STATUS="NF"
        else
       STATUS="O"
    fi
   else
    STATUS="NF"
   fi
else
   STATUS="O"
fi
echo "${stigID}:V0038700:2:${STATUS}:The operating system must provide a near real-time alert when any of the organization defined list of compromise or potential compromise indicators occurs."

########################################
stigID="RHEL-06-000306"
if [ "$(rpm -q aide | grep -c "is not installed")" -eq 0 ]
then
   if [ "$(grep -c "\/aide" /etc/crontab)" -eq 0 ]
   then
    if [ "${HEALING}" = "YES" -a "${FOUND_AIDE}" -eq 0 ]
    then
       backup /etc/crontab
       echo "${stigID} echo \"05 4 * * * root /usr/sbin/aide --check\" >> /etc/crontab" >> "${HEALING_FILE}"
       STATUS="NF"
        else
       STATUS="O"
    fi
   else
    STATUS="NF"
   fi
else
   STATUS="O"
fi
echo "${stigID}:V0038670:2:${STATUS}:The operating system must detect unauthorized changes to software and information."

########################################
stigID="RHEL-06-000307"

if [ "$(rpm -q aide | grep -c "is not installed")" -eq 0 ]
then
   if [ "$(grep -c "\/aide" /etc/crontab)" -eq 0 ]
   then
    if [ "${HEALING}" = "YES" -a "${FOUND_AIDE}" -eq 0 ]
    then
       backup /etc/crontab
       echo "${stigID} echo \"05 4 * * * root /usr/sbin/aide --check\" >> /etc/crontab" >> "${HEALING_FILE}"
       STATUS="NF"
        else
       STATUS="O"
    fi
   else
    STATUS="NF"
   fi
else
   STATUS="O"
fi
echo "${stigID}:V0038673:2:${STATUS}:The operating system must ensure unauthorized, security-relevant configuration changes detected are tracked."

########################################
stigID="RHEL-06-000308"

if [ "$(grep core /etc/security/limits.conf | grep "hard" | egrep -c "0")" -gt 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/security/limits.conf
       echo "${stigID} echo \"* hard core 0\" >> /etc/security/limits.conf" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038675:3:${STATUS}:Process core dumps must be disabled unless needed."

########################################
stigID="RHEL-06-000309"

if [ "$(grep -c "insecure_locks" /etc/exports)" -eq 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038677:1:${STATUS}:The NFS server must not have the insecure file locking option enabled."

########################################
stigID="RHEL-06-000311"

if [ "$(grep -c "^space_left = 75" /etc/audit/auditd.conf)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038678:2:${STATUS}:The audit system must provide a warning when allocated audit record storage volume reaches a documented percentage of maximum audit record storage capacity.:Needs documentation - If the "num_megabytes" value does not correspond to a documented value for remaining audit partition capacity or if there is no locally documented value for remaining audit partition capacity, this is a finding."

########################################
stigID="RHEL-06-000313"

if [ "$(grep -c "action_mail_acct = root" /etc/audit/auditd.conf)" -gt 0 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038680:2:${STATUS}:The audit system must identify staff members to receive notifications of audit log storage volume capacity issues."

########################################
stigID="RHEL-06-000314"

if [ "$(egrep -rc "bluetooth" /etc/modprobe.d | egrep -c ":1$")" -gt 0 ]
then
   if [ "$(egrep -rc "net-pf-31" /etc/modprobe.d | egrep -c ":1$")" -gt 0 ]
   then
    STATUS="NF"
   else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/modprobe.d/stig-items.conf
       echo "${stigID} echo \"install net-pf-31 /bin/true\" >> /etc/modprobe.d/stig-items.conf" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
   fi
else
    STATUS="O"
fi
echo "${stigID}:V0038682:2:${STATUS}:The Bluetooth kernel module must be disabled."

########################################
stigID="RHEL-06-000319"

if [ "$(grep "maxlogins" /etc/security/limits.conf | grep -v "#" | awk '{print $4}')" = 10 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/security/limits.conf
       echo "${stigID} grep -v \"hard maxlogins\" /etc/security/limits.conf > /tmp/a" >> "${HEALING_FILE}"
       echo "${stigID} echo \"* hard maxlogins 10\" >> /tmp/a" >> "${HEALING_FILE}"
       echo "${stigID} mv /tmp/a /etc/security/limits.conf" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038684:3:${STATUS}:The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements.:Needs documentation - If it is not set to 10 or a documented site-defined number, this is a finding."

########################################
stigID="RHEL-06-000320"

if [ "$(lsmod | grep -c "ipv4")" -gt 0 ]
then
   if [ "$(grep "\:FORWARD" /etc/sysconfig/iptables | grep -c "DROP")" -eq 1 ]
   then
        STATUS="NF"
   else
        if [ "${HEALING}" = "YES" ]
        then
           backup /etc/sysconfig/iptables
           echo "${stigID} grep -v \":FORWARD ACCEPT\" /etc/sysconfig/iptables > /tmp/a.ot" >> "${HEALING_FILE}"
           echo "${stigID} mv /tmp/a.ot /etc/sysconfig/iptables" >> "${HEALING_FILE}"
           echo "${stigID} sed '/:INPUT DROP/a\\" >> "${HEALING_FILE}"
           echo "${stigID} :FORWARD DROP [0:0]' /etc/sysconfig/iptables > /tmp/b.ot" >> "${HEALING_FILE}"
           echo "${stigID} mv /tmp/b.ot /etc/sysconfig/iptables" >> "${HEALING_FILE}"
           echo "${stigID} chown root:root /etc/sysconfig/iptables" >> "${HEALING_FILE}"
           echo "${stigID} chmod 600 /etc/sysconfig/iptables" >> "${HEALING_FILE}"
           echo "${stigID} service iptables restart" >> "${HEALING_FILE}"
        else
           STATUS="O"
        fi
   fi
else
   STATUS="NF"
fi
echo "${stigID}:V0038686:2:${STATUS}:The systems local firewall must implement a deny-all, allow-by-exception policy for forwarded packets."

########################################
stigID="RHEL-06-000321"

if [ "$(rpm -q openswan | grep -c "not installed")" -eq 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       if [ -f /tmp/CMDB/Linux/openswan-2.6.32-37.el6.x86_64.rpm ]
       then
            if [ "$(rpm -qa | grep -i -c "libreswan")" -gt 0 ];
        then
            echo "${stigID} rpm -e libreswan" >> "${HEALING_FILE}"
        fi
          echo "${stigID} rpm -ivh /tmp/CMDB/Linux/openswan-2.6.32-37.el6.x86_64.rpm" >> "${HEALING_FILE}"
          STATUS="NF"
       fi
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038687:3:${STATUS}:he system must provide VPN connectivity for communications over untrusted networks."

########################################
stigID="RHEL-06-000324"
if [ -x /usr/bin/gconftool-2 ]; then
   if [ "$(gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_enable | grep -c "true")" -eq 1 ]
   then
    STATUS="NF"
   else
    if [ "${HEALING}" = "YES" ]; then
       echo "${stigID} gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gdm/simple-greeter/banner_message_enable true" >> "${HEALING_FILE}"
      STATUS="NF"
    else
      STATUS="O"
        fi
   fi
else
    STATUS="NF"
fi
echo "${stigID}:V0038688:2:${STATUS}:A login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts."

########################################
stigID="RHEL-06-000326"
if [ -x /usr/bin/gconftool-2 ]; then
   gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_text </dev/null 1>/tmp/a 2>&1
   if [ "$(cat /tmp/a | grep -c "^No")" -eq 0 ]
   then
    STATUS="NF"
   else
    if [ "${HEALING}" = "YES" ]; then
       echo "${stigID} gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type string --set /apps/gdm/simple-greeter/banner_message_text \"I've read & consent to terms in IS user agreem't.\"" >> "${HEALING_FILE}"
      STATUS="NF"
    else
      STATUS="O"
        fi
   fi
else
    STATUS="NF"
fi
echo "${stigID}:V0038688:2:${STATUS}:A login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts."

########################################
stigID="RHEL-06-000325"

echo "${stigID}:V0038639:3:${STATUS}:The system must display a publicly-viewable pattern during a graphical desktop environment session lock."

########################################
stigID="RHEL-06-000261"

chk_service_off RHEL-06-000261 abrtd
echo "${stigID}:V0038640:3:${STATUS}:The Automatic Bug Reporting Tool abrtd service must not be running."

########################################
stigID="RHEL-06-000262"

chk_service_off RHEL-06-000262 atd
echo "${stigID}:V0038641:3:${STATUS}:The atd service must be disabled."

########################################
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#stigID="RHEL-06-000263"
#
#chk_service_off RHEL-06-000265 ntpdate
#echo "${stigID}:V0038644:3:${STATUS}:The ntpdate service must not be running."

########################################
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#stigID="RHEL-06-000327"
#gconftool-2 -g apps/gdm/simple-greeter/banner_message_text

########################################
stigID="RHEL-06-000331"

chk_service_off RHEL-06-000331 bluetooth
echo "${stigID}:V0038691:2:${STATUS}:The Bluetooth service must be disabled."

########################################
stigID="RHEL-06-000334"

if [ "$(grep -c "INACTIVE=35" /etc/default/useradd)" -eq 1 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/default/useradd
       if [ "$(grep -c "^INACTIVE" /etc/default/useradd)" -gt 0 ]
       then
           VAL="$(grep "^INACTIVE" /etc/default/useradd | awk -F"=" '{print $2}')"
           echo "${stigID} sed "s/INACTIVE=${VAL}/INACTIVE=35/g" /etc/default/useradd > /tmp/c" >> "${HEALING_FILE}"
           echo "${stigID} mv /tmp/c /etc/default/useradd" >> "${HEALING_FILE}"
       else
          echo "${stigID} echo \"INACTIVE=35\" >> /etc/default/useradd" >> "${HEALING_FILE}"
       fi
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038692:3:${STATUS}:Accounts must be locked upon 35 days of inactivity."

########################################
stigID="RHEL-06-000335"

if [ "$(grep -c "INACTIVE=35" /etc/default/useradd)" -eq 1 ]
then
    STATUS="NF"
else
    STATUS="O"
fi
echo "${stigID}:V0038694:3:${STATUS}:The operating system must manage information system identifiers for users and devices by disabling the user identifier after an organization defined time period of inactivity."

########################################
stigID="RHEL-06-000336"

awk '$3 ~ /^(ext|minix|reiserfs|sysv|tmpfs|ufs|xfs)/ {print $2}' /proc/mounts | xargs -iFS find FS -xdev -type d -perm -002 ! -perm -1000 > ${RECOVER_DIR}/${stigID}
if [ ! -s ${RECOVER_DIR}/${stigID} ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        sed "s/^/${stigID} echo \"Manual Review - chmod o+t /g" ${RECOVER_DIR}/${stigID} > /tmp/a
        sed "s/$/\"/" /tmp/a >> "${HEALING_FILE}"
        rm /tmp/a
        rm ${RECOVER_DIR}/${stigID}
    else
       STATUS="NR"
    fi
fi
echo "${stigID}:V0038697:3:${STATUS}:The sticky bit must be set on all public directories."

########################################
stigID="RHEL-06-000337"

awk '$3 ~ /^(ext|minix|reiserfs|sysv|tmpfs|ufs|xfs)/ {print $2}' /proc/mounts | xargs -iFS find FS -xdev -type d -perm -002 -uid +500 > ${RECOVER_DIR}/${stigID}
if [ ! -s ${RECOVER_DIR}/${stigID} ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
    sed "s/^/${stigID} chown root /g" ${RECOVER_DIR}/${stigID} >> "${HEALING_FILE}"
        for F in "$(cat ${RECOVER_DIR}/${stigID})"
        do
            OrigOwner="$(ls -l "${F}" | awk '{print $3}')"
            echo "chown ${OrigOwner} ${F}" >> "${RECOVERY_FILE}"
        done
            STATUS="NF"
    else
        STATUS="O"
    fi
fi
if [ -f ${RECOVER_DIR}/${stigID} ]
then
    rm ${RECOVER_DIR}/${stigID}
fi
echo "${stigID}:V0038699:3:${STATUS}:All public directories must be owned by a system account."

########################################
stigID="RHEL-06-000338"

if [ -s /etc/xinetd.d/tftp ]
then
   if [ "$(grep "server_args" /etc/xinetd.d/tftp | grep -c "\-s")" -gt 0 ]
   then
    STATUS="NF"
   else
    STATUS="O"
   fi
else
   STATUS="NF"
fi
echo "${stigID}:V0038701:1:${STATUS}:The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system."

########################################
stigID="RHEL-06-000339"

grep vsftpd /etc/xinetd.d/* > /tmp/RHEL-06-000339
if [ -s /tmp/RHEL-06-000339 ]
then
   if [ "$(grep "xferlog_enable" /etc/vsftpd/vsftpd.conf | egrep -i -c "NO")" -gt 0 ]
   then
      if [ "${HEALING}" = "YES" ]
      then
     backup /etc/vsftpd/vsftpd.conf
     echo "${stigID} grep -v \"xferlog_enable\" /etc/vsftpd/vsftpd.conf > /tmp/c.ot" >> "${HEALING_FILE}"
     echo "${stigID} mv /tmp/c.ot /etc/vsftpd/vsftpd.conf" >> "${HEALING_FILE}"
     echo "${stigID} echo \"xferlog_enable=YES\" /etc/vsftpd/vsftpd.conf" >> "${HEALING_FILE}"
     STATUS="NF"
      else
     STATUS="O"
      fi
   else
    STATUS="NF"
   fi
else
   STATUS="NF"
fi
rm /tmp/RHEL-06-000339
echo "${stigID}:V0038702:3:${STATUS}:The FTP daemon must be configured for logging or verbose mode."

########################################
stigID="RHEL-06-000340"

if [ -f /etc/snmp/snmpd.conf ]
then
   if [ "$(grep 'v1\|v2c\|com2sec' /etc/snmp/snmpd.conf | grep -v '^#' |wc -l)" -eq 0 ]
   then
      STATUS="NF"
   else
      STATUS="O"
   fi
else
   STATUS="NF"
fi
echo "${stigID}:V0038660:2:${STATUS}:The snmpd service must use only SNMP protocol version 3 or newer."

########################################
stigID="RHEL-06-000341"

if [ -s /etc/snmp/snmpd.conf ]
then
 if [ "$(grep -v "^#" /etc/snmp/snmpd.conf| grep -c public)" -eq 0 ]
 then
    STATUS="NF"
 else
    STATUS="O"
 fi
else
   STATUS="NF"
fi
echo "${stigID}:V0038653:1:${STATUS}:The snmpd service must not use a default password."

########################################
stigID="RHEL-06-000342"

if [ "$(grep -i "umask" /etc/bashrc | grep -c "077")" -gt 0 ]
then
   STATUS="NF"
else
   if [ "${HEALING}" = "YES" ]
   then
    backup /etc/bashrc
        echo "${stigID} /usr/bin/perl -pi -w -e 's/022/077/g;' /etc/bashrc" >> "${HEALING_FILE}"
        echo "${stigID} /usr/bin/perl -pi -w -e 's/0077/077/g;' /etc/bashrc" >> "${HEALING_FILE}"
        STATUS="NF"
   else
        STATUS="O"
   fi
fi
echo "${stigID}:V0038651:3:${STATUS}:The system default umask for the bash shell must be 077."

########################################
stigID="RHEL-06-000343"

if [ "$(grep -i "umask" /etc/csh.cshrc | grep -c "077")" -gt 0 ]
then
   STATUS="NF"
else
   if [ "${HEALING}" = "YES" ]
   then
    backup /etc/csh.cshrc
    echo "${stigID} echo \"umask 077\" >> /etc/csh.cshrc" >> "${HEALING_FILE}"
        STATUS="NF"
   else
        STATUS="O"
   fi
fi
echo "${stigID}:V0038649:3:${STATUS}:The system default umask for the csh shell must be 077."

########################################
stigID="RHEL-06-000344"

if [ "$(grep -i "umask" /etc/profile | egrep -c "022|002")" -eq 0 ]
then
   STATUS="NF"
else
   if [ "${HEALING}" = "YES" ]
   then
    backup /etc/profile
        echo "${stigID} /usr/bin/perl -pi -w -e 's/022/077/g;' /etc/profile" >> "${HEALING_FILE}"
        echo "${stigID} /usr/bin/perl -pi -w -e 's/002/077/g;' /etc/profile" >> "${HEALING_FILE}"
    if [ "$(grep -i "umask" /etc/profile | grep -c "077")" -eq 0 ]
    then
        echo "${stigID} echo \"umask 077\" >> /etc/profile" >> "${HEALING_FILE}"
    fi
        STATUS="NF"
   else
        STATUS="O"
   fi
fi
echo "${stigID}:V0038647:3:${STATUS}:The system default umask in /etc/profile must be 077."

########################################
stigID="RHEL-06-000345"

if [ "$(grep -i "umask" /etc/login.defs | grep -c "077")" -gt 0 ]
then
   STATUS="NF"
else
   if [ "${HEALING}" = "YES" ]
   then
    backup /etc/login.defs
    echo "${stigID} echo \"UMASK 077\" >> /etc/login.defs" >> "${HEALING_FILE}"
        STATUS="NF"
   else
        STATUS="O"
   fi
fi
echo "${stigID}:V0038645:3:${STATUS}:The system default umask in /etc/login.defs must be 077."

########################################
stigID="RHEL-06-000346"

if [ "$(grep "umask" /etc/init.d/functions | grep -c "027"`" -gt 0 -o "`grep "umask" /etc/init.d/functions | grep -c "022")" -gt 0 ]
then
   STATUS="NF"
else
   STATUS="O"
fi
echo "${stigID}:V0038642:3:${STATUS}:The system default umask for daemons must be 027 or 022."

########################################
stigID="RHEL-06-000347"

if [ "$(find /home -xdev -name .netrc |wc -l)" -eq 0 ]
then
   STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       find /home -xdev -name .netrc >> /tmp/a.ot
           if [ -s /tmp/a.ot ]
           then
          for i in "$(cat /a.ot)"
          do
        backup "${i}"
          done
              sed "s/^/${stigID} rm /g" /tmp/a.ot >> "${HEALING_FILE}"
           fi
       rm /tmp/a.ot
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038619:2:${STATUS}:There must be no .netrc files on the system."

########################################
stigID="RHEL-06-000348"

if [ -f /etc/vsftpd/vsftpd.conf ]
then
   if [ "$(grep "banner_file" /etc/vsftpd/vsftpd.conf | grep -c "/etc/issue")" -gt 0 ]
   then
      STATUS="NF"
   else
    if [ "${HEALING}" = "YES" ]; then
        backup /etc/vsftpd/vsftpd.conf
        echo "${stigID} echo \"banner_file = /etc/issue\" >> /etc/vsftpd/vsftpd.conf" >> "${HEALING_FILE}"
        STATUS="NF"
    else
            STATUS="O"
    fi
   fi
else
    STATUS="NF"
fi
echo "${stigID}:V0038599:2:${STATUS}:The FTPS/FTP service on the system must be configured with the Department of Defense (DoD) login banner."

########################################
stigID="RHEL-06-000349"

if [ "${HEALING}" = "YES" ]; then
    echo "${stigID} echo \"Manual Review - The system must be configured to require the use of a CAC, PIV compliant hardware token, or Alternate Logon Token for authentication.\"" >> "${HEALING_FILE}"
fi
echo "${stigID}:V0038595:2:NR:The system must be configured to require the use of a CAC, PIV compliant hardware token, or Alternate Logon Token for authentication."

########################################
stigID="RHEL-06-000356"

if [ "$(grep -c "pam_faillock" /etc/pam.d/system-auth)" -gt 0 ]
then
   STATUS="NR"
else
   STATUS="O"
fi
echo "${stigID}:V0038592:2:${STATUS}:grep pam_faillock /etc/pam.d/system-auth-ac"

########################################
stigID="RHEL-06-000357"

if [ "$(grep -c "pam_faillock" /etc/pam.d/system-auth)" -gt 0 ]
then
   STATUS="NR"
else
   STATUS="O"
fi
echo "${stigID}:V0038501:2:${STATUS}:The system must disable accounts after excessive login failures within a 15-minute interval."

########################################
stigID="RHEL-06-000372"

if [ "$(grep -c "pam_lastlog.so" /etc/pam.d/system-auth)" -eq 0 ]; then
   if [ "$(grep "^session" /etc/pam.d/system-auth | egrep -c "pam_limits.so")" -gt 0 ]; then
        if [ "${HEALING}" = "YES" ]; then
                backup /etc/pam.d/system-auth
                echo "${stigID} sed '/session[ ]*required[ ]*pam_limits.so/a\\" >> "${HEALING_FILE}"
                echo "${stigID} session     required      pam_lastlog.so     showfailed' /etc/pam.d/system-auth > ${RECOVER_DIR}/${stigID}" >> "${HEALING_FILE}"
                echo "${stigID} find /etc/pam.d -type f -name \"system-auth*\" -exec mv ${RECOVER_DIR}/${stigID} {} \;" >> "${HEALING_FILE}"
                STATUS="NF"
        else
                STATUS="O"
        fi
   else
        STATUS="O"
   fi
else
        STATUS="NF"
fi
echo "${stigID}:V0038501:2:${STATUS}:he operating system, upon successful logon/access, must display to the user the number of unsuccessful logon/access attempts since the last successful logon/access."

########################################
stigID="RHEL-06-000383"

sName="$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//)"
sValidPerms="0640"
sActualPerms="$(stat --printf %04a "${sName}")"

if [ "${sActualPerms}" -le "${sValidPerms}" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        echo "${stigID} ${CHMOD} ${sValidPerms} ${sName}" >> "${HEALING_FILE}"
        echo "${stigID} ${CHMOD} ${sActualPerms} ${sName}" >> "${RECOVERY_FILE}"
        STATUS="NF"
    else
        STATUS="O"
    fi
fi

echo "${stigID}:V0038498:2:${STATUS}:Audit log files must have mode 0640 or less permissive."

########################################
stigID="RHEL-06-000384"

if [ "$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %U:%n |awk -F: '{print $1}')" = "root" ]
then
    STATUS="NF"
else
   if [ "${HEALING}" = "YES" ]
   then
       FILE="$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//)"
       Owner="$(ls -l "${FILE}" | awk '{print $3}')"
           echo "${stigID} chown ${Owner} ${FILE}" >> "${RECOVERY_FILE}"
           echo "${stigID} chown root ${FILE}" >> "${HEALING_FILE}"
           STATUS="NF"
   else
      STATUS="O"
   fi
fi
echo "${stigID}:V0038495:2:${STATUS}:Audit log files must be owned by root."

########################################
stigID="RHEL-06-000385"

sName="$(grep "^log_file" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//')"
sValidPerms="0755"
sActualPerms="$(stat --printf %04a "${sName}")"

if [ "${sActualPerms}" -le "${sValidPerms}" ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        echo "${stigID} ${CHMOD} ${sValidPerms} ${sName}" >> "${HEALING_FILE}"
        echo "${stigID} ${CHMOD} ${sActualPerms} ${sName}" >> "${RECOVERY_FILE}"
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038493:2:${STATUS}:Audit log directories must have mode 0755 or less permissive."

########################################
stigID="RHEL-06-000503"

if [ "$(egrep -rc "usb-storage" /etc/modprobe.d | egrep -c ":1$")" -gt 0 ]
then
   STATUS="NF"
else
   STATUS="O"
fi
echo "${stigID}:V0038490:2:${STATUS}:The operating system must enforce requirements for the connection of mobile devices to operating systems."

########################################
stigID="RHEL-06-000504"

echo "${stigID}:V0038488:2:NF:The operating system must conduct backups of user-level information contained in the operating system per organization defined frequency to conduct backups consistent with recovery time and recovery point objectives."

########################################
stigID="RHEL-06-000505"

echo "${stigID}:V0038486:2:NF:The operating system must conduct backups of system-level information contained in the information system per organization defined frequency to conduct backups that are consistent with recovery time and recovery point objectives."

########################################
stigID="RHEL-06-000506"

find /etc -name hushlogins > /tmp/RHEL-06-000506
find /home -name .hushlogin >> /tmp/RHEL-06-000506
if [ ! -s /tmp/RHEL-06-00506 ]
then
   STATUS="NF"
else
   if [ "${HEALING}" = "YES" ]
   then
    for i in "$(cat /tmp/RHEL-06-000506)"
    do
       echo "${stigID} rm ${i}" >> "${HEALING_FILE}"
    done
    STATUS="NF"
    rm /tmp/RHEL-06-000506
   else
      STATUS="O"
   fi
fi
rm /tmp/RHEL-06-000506
echo "${stigID}:V0038485:2:${STATUS}:The operating system, upon successful logon, must display to the user the date and time of the last logon or access via a local console or tty."

########################################
stigID="RHEL-06-000507"

if [ "$(grep -i "PrintLastLog" /etc/ssh/sshd_config | awk '{print $2}')" = yes ]
then
   STATUS="NF"
else
   STATUS="O"
fi
echo "${stigID}:V0038484:2:${STATUS}:The operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh."

########################################
stigID="RHEL-06-000508"

if [ -x /usr/bin/gconftool-2 ]; then
   gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome_settings_daemon/keybindings/screensaver </dev/null 1>/tmp/a 2>&1
   if [ "$(cat /tmp/a | egrep -c "^No")" -eq 0 ]
   then
      STATUS="NF"
   else
    if [ "${HEALING}" = "YES" ]; then
       echo "${stigID} gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type string --set /apps/gnome_settings_daemon/keybindings/screensaver \"<Control><Alt>l\"" >> "${HEALING_FILE}"
       STATUS="NF"
    else
      STATUS="O"
    fi
    fi
else
    STATUS="NF"
fi
echo "${stigID}:V0038638:2:${STATUS}:The graphical desktop environment must have automatic lock enabled."

stigID="RHEL-06-000508"
echo "${stigID}:V0038474:3:${STATUS}:The system must allow locking of graphical desktop sessions."

########################################
stigID="RHEL-06-000509"

if [ "$(grep active /etc/audisp/plugins.d/syslog.conf | awk -F= '{print $2}')" = yes ]
then
   STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
       backup /etc/audisp/plugins.d/syslog.conf
       echo "${stigID} grep -v \"^active\" /etc/audisp/plugins.d/syslog.conf > ${RECOVER_DIR}/${stigID}" >> "${HEALING_FILE}"
       echo "${stigID} mv ${RECOVER_DIR}/${stigID} /etc/audisp/plugins.d/syslog.conf" >> "${HEALING_FILE}"
       echo "${stigID} echo \"active = yes\" >> /etc/audisp/plugins.d/syslog.conf" >> "${HEALING_FILE}"
       echo "${stigID} chmod 640 /etc/audisp/plugins.d/syslog.conf" >> "${HEALING_FILE}"
       STATUS="NF"
    else
       STATUS="O"
    fi
fi
echo "${stigID}:V0038471:3:${STATUS}:The system must forward audit records to the syslog service."

########################################
stigID="RHEL-06-000510"

get_audit_action disk_full_action
echo "${stigID}:V0038468:2:${STATUS}:The audit system must take appropriate action when the audit storage volume is full."

########################################
stigID="RHEL-06-000511"

get_audit_action disk_error_action
echo "${stigID}:V0038464:2:${STATUS}:The audit system must take appropriate action when there are disk errors on the audit storage volume."

########################################
stigID="RHEL-06-000514"

CHECK="0"
DIR="/etc/rpmrc /usr/lib/rpm/rpmrc /usr/lib/rpm/redhat/rpmrc ~root/.rpmrc"
for file in "${DIR}"
do
 if [ -f "${file}" ]
 then
    if [ "$(grep -c "nosignature" "${file}")" -gt 0 ]
    then
        if [ "${HEALING}" = "YES" ]
        then
            backup "${file}"
            echo "${stigID} grep -v \"nosignature\" ${file} > /tmp/f.ot" >> "${HEALING_FILE}"
            echo "${stigID} mv /tmp/f.ot ${file}" >> "${HEALING_FILE}"
            STATUS="NF"
        else
                CHECK="1"
        fi
    fi
 fi
done
if [ "${CHECK}" -eq 0 ]
then
   STATUS="NF"
else
   STATUS="O"
fi
echo "${stigID}:V0038462:1:${STATUS}:The RPM package management tool must cryptographically verify the authenticity of all software packages during installation."

########################################
stigID="RHEL-06-000515"

if [ -s /etc/exports ]
then
 if [ "$(grep -c "all_squash" /etc/exports)" -eq 0 ]
 then
    STATUS="NF"
 else
    STATUS="O"
 fi
else
   STATUS="NF"
fi
echo "${stigID}:V0038460:3:${STATUS}:The NFS server must not have the all_squash option enabled."

########################################
stigID="RHEL-06-000516"

if [ "$(grep -c '^.....U' "${RPM_FILE}")" -eq 0 ]
then
   STATUS="NF"
else
   if [ "${HEALING}" = "YES" ]; then
    rpm -Va </dev/null 1>/var/tmp/srg_stuff/rpm_va2.ot 2>&1
    sleep "2"
    if [ "$(grep -c "^prelink:" /var/tmp/srg_stuff/rpm_va2.ot)" -gt 0 ]; then
        RPM_VA2=/var/tmp/srg_stuff/rpm_va2.ot
            PRELINK="$(grep "^prelink:" "${RPM_VA2}" | awk 'BEGIN{FS=OFS=" "}{$1="";gsub(FS," ")}1' | sed 's/^ //g' | sed "s/^[a-d] //g" | awk '{print $1}' | sed "s/://g")"
        for P in "${PRELINK}"
        do
            echo "${stigID} prelink -q ${P}" >> "${HEALING_FILE}"
        done
    fi
#
    FILES="$(grep '^.....U' "${RPM_FILE}" | awk 'BEGIN{FS=OFS=" "}{$1="";gsub(FS," ")}1' | sed 's/^ //g' | sed "s/^[a-d] //g")"
    for F in "${FILES}"
    do
        if [ "${F}" = "/var/lib/unbound" ]; then
            if [ "$(grep -c "^unbound:" /etc/passwd)" -eq 1 ]; then
                echo "${stigID} userdel unbound" >> "${HEALING_FILE}"
            fi
            if [ "$(grep -c "^unbound:" /etc/group)" -eq 1 ]; then
                echo "${stigID} groupdel unbound" >> "${HEALING_FILE}"
            fi
            echo "${stigID} groupadd -g 325 unbound" >> "${HEALING_FILE}"
            echo "${stigID} useradd -c \"Unbound DNS resolver\" -d "/etc/unbound" -g unbound -m -s /sbin/nologin -u 325 unbound" >> "${HEALING_FILE}"
        fi
        PKG="$(rpm -qf "${F}" | head -1)"
        echo "${stigID} rpm -setugids ${PKG}" >> "${HEALING_FILE}"
    done
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038454:3:${STATUS}:The system package management tool must verify ownership on all files and directories associated with packages."

########################################
stigID="RHEL-06-000517"

if [ "$(grep -c '^......G' "${RPM_FILE}")" -eq 0 ]
then
    STATUS="NF"
else
    if [ "${HEALING}" = "YES" ]
    then
        FILES="$(grep '^......G' "${RPM_FILE}" | awk 'BEGIN{FS=OFS=" "}{$1="";gsub(FS," ")}1' | sed 's/^ //g' | sed "s/^[a-d] //g")"
        for F in "${FILES}"
        do
            PKG="$(rpm -qf "${F}" | head -1)"
            echo "${stigID} rpm -setugids ${PKG}" >> "${HEALING_FILE}"
        done
        STATUS="NF"
    else
        STATUS="O"
    fi
fi
echo "${stigID}:V0038453:3:${STATUS}:The system package management tool must verify group-ownership on all files and directories associated with packages."

########################################
#stigID="RHEL-06-000518"
#
#if [ `grep -c '^.M' ${RPM_FILE}` -eq 0 ]
#then
#   STATUS="NF"
#else
#   if [ ${HEALING} = "YES" ]; then
#       FILES=`grep '^.M' ${RPM_FILE} | awk 'BEGIN{FS=OFS=" "}{$1="";gsub(FS," ")}1' | sed 's/^ //g' | sed "s/^[a-d] //g"`
#   for M in ${FILES}
#   do
#      PKG=`rpm -qf ${M} | head -1`
#      SETTINGS=`rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\n]" ${PKG} | grep ${M}`
#      for ENTRY in ${SETTINGS}
#      do
#           FILE=`echo "${ENTRY}" | awk '{print $1}'`
#       if [ ${FILE} = "/etc/passwd" ]; then
#          continue
#       fi
#           sValidPerms=`echo "${ENTRY}" | awk '{print $2}'`
#       sActualPerms=`ls -l ${FILE} | awk '{print $1}'`
#       if [ ${sActualPerms} != "${sValidPerms}" ]; then
#          getsetperms healing ${FILE}
#          getsetperms recovery ${FILE}
#       fi
#      done
#   done
#   STATUS="NF"
#   else
#      STATUS="O"
#   fi
#fi
#echo "${stigID}:V0038452:3:${STATUS}:The system package management tool must verify permissions on all files and directories associated with packages."

########################################
stigID="RHEL-06-000519"

if [ "$(cat "${RPM_FILE}" | awk '$1 ~ /..5/ && $2 != "c"' | wc -l)" -eq 0 ]
then
   STATUS="NF"
else
   STATUS="O"
fi
echo "${stigID}:V0038447:3:${STATUS}:The system package management tool must verify contents of all files associated with packages."

########################################
stigID="RHEL-06-000521"

# postconf alias_maps
# Query the Postfix alias maps for an alias for "root":
# postmap -q root hash:/etc/aliases
# If there are no aliases configured for root that forward to a monitored email address, this is a finding.
# Set up an alias for root that forwards to a monitored email address:
# echo "root: <system.administrator>@mail.mil" >> /etc/aliases
# newaliases

if [ "${HEALING}" = "YES" ]; then
    echo "${stigID} echo \"Manual Review - The mail system must forward all mail for root to one or more system administrators.\"" >> "${HEALING_FILE}"
fi
echo "${stigID}:V0038446:2:NR:The mail system must forward all mail for root to one or more system administrators."

########################################
stigID="RHEL-06-000522"

if [ "$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %G:%n |awk -F: '{print $1}')" = "root" ]
then
   STATUS="NF"
else
   if [ "${HEALING}" = "YES" ]
   then
       FILE="$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//)"
       Group="$(ls -l "${FILE}" | awk '{print $4}')"
           echo "${stigID} chgrp ${Group} ${FILE}" >> "${RECOVERY_FILE}"
           echo "${stigID} chgrp root ${FILE}" >> "${HEALING_FILE}"
           STATUS="NF"
   else
      STATUS="O"
   fi
fi
echo "${stigID}:V0038445:2:${STATUS}:Audit log files must be group-owned by root."

########################################
stigID="RHEL-06-000523"

if [ "$(lsmod | grep -c "ipv6")" -gt 0 ]
then
    if [ -f /etc/sysconfig/ip6tables ]
    then
        if [ "$(grep ":INPUT" /etc/sysconfig/ip6tables | grep -c "DROP")" -gt 0 -o "${IP6TABLES}" -eq 1 ]
        then
            STATUS="NF"
        else
            if [ "${HEALING}" = "YES" ]
            then
                IP6TABLES="1"
                backup /etc/sysconfig/ip6tables
                gen_ip6tables
            else
                STATUS="O"
            fi
        fi
    fi
else
   STATUS="NF"
fi
echo "${stigID}:V0038444:2:${STATUS}:The systems local IPv6 firewall must implement a deny-all, allow-by-exception policy for inbound packets."

########################################
stigID="RHEL-06-000524"

CHECK="0"
echo "${stigID}:V0038439:2:NF:The system must provide automated support for account management functions."
stigID="RHEL-06-000525"
if [ -s /boot/grub/grub.conf ]
then
   KERN_CNT="$(grep "kernel" /boot/grub/grub.conf | grep -v "^#" | egrep -c "\/vmlinuz")"
   AUD_CNT="$(grep "kernel" /boot/grub/grub.conf | grep -v "^#" | egrep "\/vmlinuz" | egrep -c "audit=1")"
   if [ "${KERN_CNT}" -ne "${AUD_CNT}" ]
   then
      CHECK="1"
   fi
fi
if [ "${CHECK}" -eq 0 ]
then
   STATUS="NF"
else
   STATUS="O"
fi
echo "${stigID}:V0038438:3:${STATUS}:Auditing must be enabled at boot by setting a kernel parameter."

########################################
stigID="RHEL-06-000526"

chk_service_off RHEL-06-000526 autofs
echo "${stigID}:V0038437:3:${STATUS}:Automated file system mounting tools must not be enabled unless needed."

########################################
stigID="RHEL-06-000528"

CHECK="0"
if [ -s /etc/fstab ]
then
   if [ "$(grep -c '\/tmp' /etc/fstab)" -gt 0 ]; then
      CHECK="1"
   fi
fi
if [ "${CHECK}" -eq 0 ]
then
   STATUS="NF"
else
   STATUS="O"
fi
echo "${stigID}:V0038439:2:${STATUS}:The noexec option must be added to the /tmp partition."

########################################
stigID="RHEL-06-000529"

CHECK="0"
if [ -d /etc/sudoers.d ]
then
    touch /etc/sudoers.d/temp
fi
if [ -s /etc/sudoers ]
then
    if [ "$(egrep '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/* | wc -l)" -gt 0 ]; then
      CHECK="1"
    fi
    if [ "$(egrep '^[^#]*!authenticate' /etc/sudoers /etc/sudoers.d/* | wc -l)" -gt 0 ]; then
       CHECK="1"
    fi
fi
if [ "${CHECK}" -eq 0 ]
then
   STATUS="NF"
else
   STATUS="O"
fi
echo "${stigID}:V0038440:2:${STATUS}:The sudo command must require authentication."

###############################################################################
## Check and exclude any exceptions
#
if [ -s /opt/esps/exemptions/asset_status_overrides ]; then
   awk -F: '{print $1}' /opt/esps/exemptions/asset_status_overrides | sort -u > /tmp/a
   for VKEY in "$(cat /tmp/a)"
   do
    STIG_ID="$(grep "|${VKEY}|" /os_srr/Script/PDI-DB.master | awk -F"|" '{print $2}')"
    if [ "$(grep -c "^${STIG_ID} " /var/tmp/srg_stuff/recover_dir/healing_srg_tmp)" -gt 0 ]; then
       ITEMS="$(grep "^${VKEY}:" /opt/esps/exemptions/asset_status_overrides | awk -F: '{print $6}')"
       for item in "${ITEMS}"
       do
         if [ "$(echo "${item}" | grep -c "\\*")" -gt 0 ]; then
                grep -v "^${STIG_ID} " /var/tmp/srg_stuff/recover_dir/healing_srg_tmp > /tmp/b
                mv /tmp/b /var/tmp/srg_stuff/recover_dir/healing_srg_tmp
        else
              grep -v "^${STIG_ID} " /var/tmp/srg_stuff/recover_dir/healing_srg_tmp > /tmp/c
              grep "^${STIG_ID} " /var/tmp/srg_stuff/recover_dir/healing_srg_tmp | egrep -v "${item}" > /tmp/d
              cat /tmp/d >> /tmp/c
              mv /tmp/c /var/tmp/srg_stuff/recover_dir/healing_srg_tmp
        fi
      done
    fi
  done
  for i in a b c d
  do
    if [ -s /tmp/${i} ]; then
      rm /tmp/${i}
    fi
  done
fi

###############################################################################
## Sort the healing and recovery scripts
#
if [ -s "${HEALING_FILE}" -a "${HEALING}" = "YES" ]
then
   if [ -s increment_corrections ]; then
      for PDI in "$(cat increment_corrections | egrep "^Linux:6:|^ALL:" | awk -F: '{print $3}')"
      do
        grep "^${PDI}" "${HEALING_FILE}" | awk 'BEGIN{FS=OFS=" "}{$1="";gsub(FS," ")}1' | sed 's/^ //g' >> ${RECOVER_DIR}/srg_healing.sh
      done
   else
        cat "${HEALING_FILE}" | awk 'BEGIN{FS=OFS=" "}{$1="";gsub(FS," ")}1' | sed 's/^ //g' > ${RECOVER_DIR}/srg_healing.sh
   fi
   chmod "700" ${RECOVER_DIR}/srg_healing.sh
   chown root:root ${RECOVER_DIR}/srg_healing.sh
    echo " "
   echo "Executing SRG healing ..."
   cat ${RECOVER_DIR}/srg_healing.sh
#   ${RECOVER_DIR}/srg_healing.sh
   RECOVERY_FILES="$(ls ${RECOVER_DIR}/*recover)"
   for FILE in "${RECOVERY_FILES}"
   do
      echo "chmod 700 ${FILE}" >> "${RECOVERY_FILE}"
      echo "${FILE}" >> "${RECOVERY_FILE}"
   done
   echo "tar xvfP /var/tmp/srg_stuff/base_files.tar" >> "${RECOVERY_FILE}"
   echo "tar xvfP /var/tmp/srg_stuff/base_pam_files.tar" >> "${RECOVERY_FILE}"
   chmod "700" "${RECOVERY_FILE}"
   cp fix.sh "${RECOVER_DIR}"
fi
