#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000331
#
# VULN ID
#   V-38691
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000034
#
# RULE ID
#   SV-50492r2_rule
#
# STIG ID
#   RHEL-06-000331
#
# RULE TITLE
#   The Bluetooth service must be disabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000331;

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
    $self->{VULN_ID} = 'V-38691';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000034';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50492r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000331';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'The Bluetooth service must be disabled.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Disabling the ""bluetooth"" service prevents the system from attempting connections to Bluetooth devices, which entails some security risk. Nevertheless, variation in this risk decision may be expected due to the utility of Bluetooth connectivity and its limited range.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To check that the ""bluetooth"" service is disabled in system boot configuration, run the following command:



# chkconfig ""bluetooth"" --list



Output should indicate the ""bluetooth"" service has either not been installed or has been disabled at all runlevels, as shown in the example below:



# chkconfig ""bluetooth"" --list

""bluetooth"" 0:off 1:off 2:off 3:off 4:off 5:off 6:off





If the service is configured to run, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The ""bluetooth"" service can be disabled with the following command:



# chkconfig bluetooth off







# service bluetooth stop
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000085

The organization monitors for unauthorized connections of mobile devices to organizational information systems.

NIST SP 800-53 :: AC-19 c

NIST SP 800-53A :: AC-19.1 (iii)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
