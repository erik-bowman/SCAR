#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000174
#
# VULN ID
#   V-38531
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000004
#
# RULE ID
#   SV-50332r2_rule
#
# STIG ID
#   RHEL-06-000174
#
# RULE TITLE
#   The operating system must automatically audit account creation.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000174;

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
    $self->{VULN_ID} = 'V-38531';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000004';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50332r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000174';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must automatically audit account creation.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To determine if the system is configured to audit account changes, run the following command:



$ sudo egrep -w '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)' /etc/audit/audit.rules



If the system is configured to watch for account changes, lines should be returned for each file specified (and with ""-p wa"" for each).



If the system is not configured to audit account changes, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Add the following to ""/etc/audit/audit.rules"", in order to capture events that modify account changes:



# audit_account_changes

-w /etc/group -p wa -k audit_account_changes

-w /etc/passwd -p wa -k audit_account_changes

-w /etc/gshadow -p wa -k audit_account_changes

-w /etc/shadow -p wa -k audit_account_changes

-w /etc/security/opasswd -p wa -k audit_account_changes
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000018

The information system automatically audits account creation actions.

NIST SP 800-53 :: AC-2 (4)

NIST SP 800-53A :: AC-2 (4).1 (i&ii)

NIST SP 800-53 Revision 4 :: AC-2 (4)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
