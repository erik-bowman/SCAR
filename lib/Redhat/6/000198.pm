# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000198
#
# VULN ID
#   V-38567
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000020
#
# RULE ID
#   SV-50368r4_rule
#
# STIG ID
#   RHEL-06-000198
#
# RULE TITLE
#   The audit system must be configured to audit all use of setuid and setgid programs.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000198;

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
    return 'V-38567';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000020';
}

sub get_rule_id {
    return 'SV-50368r4_rule';
}

sub get_stig_id {
    return 'RHEL-06-000198';
}

sub get_rule_title {
    return
        'The audit system must be configured to audit all use of setuid and setgid programs.';
}

sub get_discussion {
    return <<'DISCUSSION';
Privileged programs are subject to escalation-of-privilege attacks, which attempt to subvert their normal role of providing some necessary but limited capability. As such, motivation exists to monitor these programs for unusual activity.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify that auditing of privileged command use is configured, run the following command once for each local partition [PART] to find relevant setuid / setgid programs:



$ sudo find [PART] -xdev -type f -perm /6000 2>/dev/null



Run the following command to verify entries in the audit rules for all programs found with the previous command:



$ sudo grep path /etc/audit/audit.rules



It should be the case that all relevant setuid / setgid programs have a line in the audit rules. If that is not the case, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
At a minimum, the audit system should collect the execution of privileged commands for all users and root. To find the relevant setuid / setgid programs, run the following command for each local partition [PART]:



$ sudo find [PART] -xdev -type f -perm /6000 2>/dev/null



Then, for each setuid / setgid program on the system, add a line of the following form to ""/etc/audit/audit.rules"", where [SETUID_PROG_PATH] is the full path to each setuid / setgid program in the list:



-a always,exit -F path=[SETUID_PROG_PATH] -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000040

The organization audits any use of privileged accounts, or roles, with access to organization defined security functions or security-relevant information, when accessing other system functions.

NIST SP 800-53 :: AC-6 (2)

NIST SP 800-53A :: AC-6 (2).1 (iii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
