# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030360
#
# VULN ID
#   V-72095
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000327-GPOS-00127
#
# RULE ID
#   SV-86719r2_rule
#
# STIG ID
#   RHEL-07-030360
#
# RULE TITLE
#   All privileged function executions must be audited.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030360;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# Scar modules
use Scar;
use Scar::Util::Log;
use Scar::Util::Backup;

# Plugin version
our $VERSION = 0.01;

sub new {
    my ( $class, $parent ) = @_;
    my $self = bless { parent => $parent }, $class;

    return $self;
}

sub check {
    my ($self) = @_;

    return $self;
}

sub remediate {
    my ($self) = @_;

    return $self;
}

sub _set_finding_status {
    my ( $self, $finding_status ) = @_;
    $self->{finding_status} = $finding_status;
    return $self->{finding_status};
}

sub get_finding_status {
    my ($self) = @_;
    return defined $self->{finding_status} ? $self->{finding_status} : undef;
}

sub get_vuln_id {
    return 'V-72095';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000327-GPOS-00127';
}

sub get_rule_id {
    return 'SV-86719r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-030360';
}

sub get_rule_title {
    return 'All privileged function executions must be audited.';
}

sub get_discussion {
    return <<'DISCUSSION';
Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system audits the execution of privileged functions.



To find relevant setuid and setgid programs, use the following command once for each local partition [PART]:



# find [PART] -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null



Run the following command to verify entries in the audit rules for all programs found with the previous command:



# grep <suid_prog_with_full_path> -a always,exit -F <suid_prog_with_full_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -k setuid/setgid



All ""setuid"" and ""setgid"" files on the system must have a corresponding audit rule, or must have an audit rule for the (sub) directory that contains the ""setuid""/""setgid"" file.



If all ""setuid""/""setgid"" files on the system do not have audit rule coverage, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to audit the execution of privileged functions.



To find the relevant ""setuid""/""setgid"" programs, run the following command for each local partition [PART]:



# find [PART] -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null



For each ""setuid""/""setgid"" program on the system, which is not covered by an audit rule for a (sub) directory (such as ""/usr/sbin""), add a line of the following form to ""/etc/audit/audit.rules"", where <suid_prog_with_full_path> is the full path to each ""setuid""/""setgid"" program in the list:



-a always,exit -F <suid_prog_with_full_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -k setuid/setgid
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-002234

The information system audits the execution of privileged functions.

NIST SP 800-53 Revision 4 :: AC-6 (9)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
