#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000220
#
# VULN ID
#   V-38603
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000095
#
# RULE ID
#   SV-50404r1_rule
#
# STIG ID
#   RHEL-06-000220
#
# RULE TITLE
#   The ypserv package must not be installed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000220;

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
    $self->{VULN_ID} = 'V-38603';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000095';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50404r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000220';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'The ypserv package must not be installed.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Removing the ""ypserv"" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Run the following command to determine if the ""ypserv"" package is installed:



# rpm -q ypserv





If the package is installed, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The ""ypserv"" package can be uninstalled with the following command:



# yum erase ypserv
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000381

The organization configures the information system to provide only essential capabilities.

NIST SP 800-53 :: CM-7

NIST SP 800-53A :: CM-7.1 (ii)

NIST SP 800-53 Revision 4 :: CM-7 a




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
