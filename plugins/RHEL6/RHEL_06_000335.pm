#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000335
#
# VULN ID
#   V-38694
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000118
#
# RULE ID
#   SV-50495r1_rule
#
# STIG ID
#   RHEL-06-000335
#
# RULE TITLE
#   The operating system must manage information system identifiers for users and devices by disabling the user identifier after an organization defined time period of inactivity.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000335;

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
    $self->{VULN_ID} = 'V-38694';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000118';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50495r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000335';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must manage information system identifiers for users and devices by disabling the user identifier after an organization defined time period of inactivity.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Disabling inactive accounts ensures that accounts which may not have been responsibly removed are not available to attackers who may have compromised their credentials.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To verify the ""INACTIVE"" setting, run the following command:



grep ""INACTIVE"" /etc/default/useradd



The output should indicate the ""INACTIVE"" configuration option is set to an appropriate integer as shown in the example below:



# grep ""INACTIVE"" /etc/default/useradd

INACTIVE=35



If it does not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To specify the number of days after a password expires (which signifies inactivity) until an account is permanently disabled, add or correct the following lines in ""/etc/default/useradd"", substituting ""[NUM_DAYS]"" appropriately:



INACTIVE=[NUM_DAYS]



A value of 35 is recommended. If a password is currently on the verge of expiration, then 35 days remain until the account is automatically disabled. However, if the password will not expire for another 60 days, then 95 days could elapse until the account would be automatically disabled. See the ""useradd"" man page for more information. Determining the inactivity timeout must be done with careful consideration of the length of a ""normal"" period of inactivity for users in the particular environment. Setting the timeout too low incurs support costs and also has the potential to impact availability of the system to legitimate users.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000795

The organization manages information system identifiers by disabling the identifier after an organization defined time period of inactivity.

NIST SP 800-53 :: IA-4 e

NIST SP 800-53A :: IA-4.1 (iii)

NIST SP 800-53 Revision 4 :: IA-4 e




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
