# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000197
#
# VULN ID
#   V-38566
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000064
#
# RULE ID
#   SV-50367r2_rule
#
# STIG ID
#   RHEL-06-000197
#
# RULE TITLE
#   The audit system must be configured to audit failed attempts to access files and programs.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000197;

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
    return 'V-38566';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000064';
}

sub get_rule_id {
    return 'SV-50367r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000197';
}

sub get_rule_title {
    return
        'The audit system must be configured to audit failed attempts to access files and programs.';
}

sub get_discussion {
    return <<'DISCUSSION';
Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify that the audit system collects unauthorized file accesses, run the following commands:



# grep EACCES /etc/audit/audit.rules







# grep EPERM /etc/audit/audit.rules





If either command lacks output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
At a minimum, the audit system should collect unauthorized file accesses for all users and root. Add the following to ""/etc/audit/audit.rules"", setting ARCH to either b32 or b64 as appropriate for your system:



-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \

-S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access

-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \

-S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \

-S ftruncate -F exit=-EACCES -F auid=0 -k access

-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \

-S ftruncate -F exit=-EPERM -F auid=0 -k access
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
