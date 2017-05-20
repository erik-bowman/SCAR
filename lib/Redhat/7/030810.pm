# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030810
#
# VULN ID
#   V-72185
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000471-GPOS-00215
#
# RULE ID
#   SV-86809r2_rule
#
# STIG ID
#   RHEL-07-030810
#
# RULE TITLE
#   All uses of the pam_timestamp_check command must be audited.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030810;

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
    return 'V-72185';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000471-GPOS-00215';
}

sub get_rule_id {
    return 'SV-86809r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-030810';
}

sub get_rule_title {
    return 'All uses of the pam_timestamp_check command must be audited.';
}

sub get_discussion {
    return <<'DISCUSSION';
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system generates audit records when successful/unsuccessful attempts to use the ""pam_timestamp_check"" command occur.



Check the auditing rules in ""/etc/audit/audit.rules"" with the following command:



# grep -i /sbin/pam_timestamp_check /etc/audit/audit.rules



-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295  -k privileged-pam



If the command does not return any output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to generate audit records when successful/unsuccessful attempts to use the ""pam_timestamp_check"" command occur.



Add or update the following rule in ""/etc/audit/rules.d/audit.rules"":



-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-pam



The audit daemon must be restarted for the changes to take effect.
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
