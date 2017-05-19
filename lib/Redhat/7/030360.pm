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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-72095';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000327-GPOS-00127';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86719r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-030360';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'All privileged function executions must be audited.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system audits the execution of privileged functions.



To find relevant setuid and setgid programs, use the following command once for each local partition [PART]:



# find [PART] -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null



Run the following command to verify entries in the audit rules for all programs found with the previous command:



# grep <suid_prog_with_full_path> -a always,exit -F <suid_prog_with_full_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -k setuid/setgid



All ""setuid"" and ""setgid"" files on the system must have a corresponding audit rule, or must have an audit rule for the (sub) directory that contains the ""setuid""/""setgid"" file.



If all ""setuid""/""setgid"" files on the system do not have audit rule coverage, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to audit the execution of privileged functions.



To find the relevant ""setuid""/""setgid"" programs, run the following command for each local partition [PART]:



# find [PART] -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null



For each ""setuid""/""setgid"" program on the system, which is not covered by an audit rule for a (sub) directory (such as ""/usr/sbin""), add a line of the following form to ""/etc/audit/audit.rules"", where <suid_prog_with_full_path> is the full path to each ""setuid""/""setgid"" program in the list:



-a always,exit -F <suid_prog_with_full_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -k setuid/setgid
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-002234

The information system audits the execution of privileged functions.

NIST SP 800-53 Revision 4 :: AC-6 (9)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
