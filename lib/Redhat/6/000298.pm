# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000298
#
# VULN ID
#   V-38690
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000123
#
# RULE ID
#   SV-50491r1_rule
#
# STIG ID
#   RHEL-06-000298
#
# RULE TITLE
#   Emergency accounts must be provisioned with an expiration date.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000298;

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
    return 'V-38690';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000123';
}

sub get_rule_id {
    return 'SV-50491r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000298';
}

sub get_rule_title {
    return 'Emergency accounts must be provisioned with an expiration date.';
}

sub get_discussion {
    return <<'DISCUSSION';
When emergency accounts are created, there is a risk they may remain in place and active after the need for them no longer exists. Account expiration greatly reduces the risk of accounts being misused or hijacked.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
For every emergency account, run the following command to obtain its account aging and expiration information:



# chage -l [USER]



Verify each of these accounts has an expiration date set as documented.

If any emergency accounts have no expiration date set or do not expire within a documented time frame, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
In the event emergency accounts are required, configure the system to terminate them after a documented time period. For every emergency account, run the following command to set an expiration date on it, substituting ""[USER]"" and ""[YYYY-MM-DD]"" appropriately:



# chage -E [YYYY-MM-DD] [USER]



""[YYYY-MM-DD]"" indicates the documented expiration date for the account.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001682

The information system automatically removes or disables emergency accounts after an organization-defined time period for each type of account.

NIST SP 800-53 :: AC-2 (2)

NIST SP 800-53A :: AC-2 (2).1 (ii)

NIST SP 800-53 Revision 4 :: AC-2 (2)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
