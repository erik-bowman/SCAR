#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000027
#
# VULN ID
#   V-38492
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000109
#
# RULE ID
#   SV-50293r1_rule
#
# STIG ID
#   RHEL-06-000027
#
# RULE TITLE
#   The system must prevent the root account from logging in from virtual consoles.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000027;

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
    $self->{VULN_ID} = 'V-38492';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000109';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50293r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000027';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must prevent the root account from logging in from virtual consoles.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Preventing direct root login to virtual console devices helps ensure accountability for actions taken on the system using the root account.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To check for virtual console entries which permit root login, run the following command:



# grep '^vc/[0-9]' /etc/securetty



If any output is returned, then root logins over virtual console devices is permitted.

If root login over virtual console devices is permitted, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To restrict root logins through the (deprecated) virtual console devices, ensure lines of this form do not appear in ""/etc/securetty"":



vc/1

vc/2

vc/3

vc/4



Note:  Virtual console entries are not limited to those listed above.  Any lines starting with ""vc/"" followed by numerals should be removed.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000770

The organization requires individuals to be authenticated with an individual authenticator when a group authenticator is employed.

NIST SP 800-53 :: IA-2 (5) (b)

NIST SP 800-53A :: IA-2 (5).2 (ii)

NIST SP 800-53 Revision 4 :: IA-2 (5)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
