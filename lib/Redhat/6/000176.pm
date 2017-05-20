# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000176
#
# VULN ID
#   V-38536
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000240
#
# RULE ID
#   SV-50337r2_rule
#
# STIG ID
#   RHEL-06-000176
#
# RULE TITLE
#   The operating system must automatically audit account disabling actions.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000176;

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
    return 'V-38536';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000240';
}

sub get_rule_id {
    return 'SV-50337r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000176';
}

sub get_rule_title {
    return
        'The operating system must automatically audit account disabling actions.';
}

sub get_discussion {
    return <<'DISCUSSION';
In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine if the system is configured to audit account changes, run the following command:



$sudo egrep -w '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)' /etc/audit/audit.rules



If the system is configured to watch for account changes, lines should be returned for each file specified (and with ""-p wa"" for each).



If the system is not configured to audit account changes, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Add the following to ""/etc/audit/audit.rules"", in order to capture events that modify account changes:



# audit_account_changes

-w /etc/group -p wa -k audit_account_changes

-w /etc/passwd -p wa -k audit_account_changes

-w /etc/gshadow -p wa -k audit_account_changes

-w /etc/shadow -p wa -k audit_account_changes

-w /etc/security/opasswd -p wa -k audit_account_changes
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001404

The information system automatically audits account disabling actions.

NIST SP 800-53 :: AC-2 (4)

NIST SP 800-53A :: AC-2 (4).1 (i&ii)

NIST SP 800-53 Revision 4 :: AC-2 (4)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
