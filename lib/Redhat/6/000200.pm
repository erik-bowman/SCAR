# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000200
#
# VULN ID
#   V-38575
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000064
#
# RULE ID
#   SV-50376r4_rule
#
# STIG ID
#   RHEL-06-000200
#
# RULE TITLE
#   The audit system must be configured to audit user deletions of files and programs.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000200;

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
    return 'V-38575';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000064';
}

sub get_rule_id {
    return 'SV-50376r4_rule';
}

sub get_stig_id {
    return 'RHEL-06-000200';
}

sub get_rule_title {
    return
        'The audit system must be configured to audit user deletions of files and programs.';
}

sub get_discussion {
    return <<'DISCUSSION';
Auditing file deletions will create an audit trail for files that are removed from the system. The audit trail could aid in system troubleshooting, as well as detecting malicious processes that attempt to delete log files to conceal their presence.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine if the system is configured to audit calls to the ""rmdir"" system call, run the following command:



$ sudo grep -w ""rmdir"" /etc/audit/audit.rules



If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the ""unlink"" system call, run the following command:



$ sudo grep -w ""unlink"" /etc/audit/audit.rules



If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the ""unlinkat"" system call, run the following command:



$ sudo grep -w ""unlinkat"" /etc/audit/audit.rules



If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the ""rename"" system call, run the following command:



$ sudo grep -w ""rename"" /etc/audit/audit.rules



If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the ""renameat"" system call, run the following command:



$ sudo grep -w ""renameat"" /etc/audit/audit.rules



If the system is configured to audit this activity, it will return a line.



If no line is returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
At a minimum, the audit system should collect file deletion events for all users and root. Add the following (or equivalent) to ""/etc/audit/audit.rules"", setting ARCH to either b32 or b64 as appropriate for your system:



-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete




FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000172

The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.

NIST SP 800-53 :: AU-12 c

NIST SP 800-53A :: AU-12.1 (iv)

NIST SP 800-53 Revision 4 :: AU-12 c




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
