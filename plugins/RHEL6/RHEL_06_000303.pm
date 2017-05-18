#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000303
#
# VULN ID
#   V-38696
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000098
#
# RULE ID
#   SV-50497r2_rule
#
# STIG ID
#   RHEL-06-000303
#
# RULE TITLE
#   The operating system must employ automated mechanisms, per organization defined frequency, to detect the addition of unauthorized components/devices into the operating system.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000303;

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
    $self->{VULN_ID} = 'V-38696';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000098';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50497r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000303';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must employ automated mechanisms, per organization defined frequency, to detect the addition of unauthorized components/devices into the operating system.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To determine that periodic AIDE execution has been scheduled, run the following command:



# grep aide /etc/crontab /etc/cron.*/*



If there is no output, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab:



05 4 * * * root /usr/sbin/aide --check



AIDE can be executed periodically through other means; this is merely one example.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000416

The organization employs automated mechanisms, per organization defined frequency, to detect the presence of unauthorized hardware, software, and firmware components within the information system.

NIST SP 800-53 :: CM-8 (3) (a)

NIST SP 800-53A :: CM-8 (3).1 (ii)

NIST SP 800-53 Revision 4 :: CM-8 (3) (a)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
