#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000298
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

package RHEL_06_000298;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# SCAR modules
use SCAR;
use SCAR::Log;
use SCAR::Backup;

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
    $self->{VULN_ID} = 'V-38690';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000123';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50491r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000298';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'Emergency accounts must be provisioned with an expiration date.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
When emergency accounts are created, there is a risk they may remain in place and active after the need for them no longer exists. Account expiration greatly reduces the risk of accounts being misused or hijacked.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
For every emergency account, run the following command to obtain its account aging and expiration information:



# chage -l [USER]



Verify each of these accounts has an expiration date set as documented.

If any emergency accounts have no expiration date set or do not expire within a documented time frame, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
In the event emergency accounts are required, configure the system to terminate them after a documented time period. For every emergency account, run the following command to set an expiration date on it, substituting ""[USER]"" and ""[YYYY-MM-DD]"" appropriately:



# chage -E [YYYY-MM-DD] [USER]



""[YYYY-MM-DD]"" indicates the documented expiration date for the account.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001682

The information system automatically removes or disables emergency accounts after an organization-defined time period for each type of account.

NIST SP 800-53 :: AC-2 (2)

NIST SP 800-53A :: AC-2 (2).1 (ii)

NIST SP 800-53 Revision 4 :: AC-2 (2)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
