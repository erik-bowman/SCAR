# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000184
#
# VULN ID
#   V-38543
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000064
#
# RULE ID
#   SV-50344r3_rule
#
# STIG ID
#   RHEL-06-000184
#
# RULE TITLE
#   The audit system must be configured to audit all discretionary access control permission modifications using chmod.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000184;

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
    return 'V-38543';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000064';
}

sub get_rule_id {
    return 'SV-50344r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000184';
}

sub get_rule_title {
    return
        'The audit system must be configured to audit all discretionary access control permission modifications using chmod.';
}

sub get_discussion {
    return <<'DISCUSSION';
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine if the system is configured to audit calls to the ""chmod"" system call, run the following command:



$ sudo grep -w ""chmod"" /etc/audit/audit.rules



If the system is configured to audit this activity, it will return several lines.



If the system is not configured to audit permission changes, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to ""/etc/audit/audit.rules"":



-a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 \

-k perm_mod

-a always,exit -F arch=b32 -S chmod -F auid=0 -k perm_mod



If the system is 64-bit, then also add the following:



-a always,exit -F arch=b64 -S chmod -F auid>=500 -F auid!=4294967295 \

-k perm_mod

-a always,exit -F arch=b64 -S chmod -F auid=0 -k perm_mod
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
