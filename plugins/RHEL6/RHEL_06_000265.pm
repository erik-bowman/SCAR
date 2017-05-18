#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000265
#
# VULN ID
#   V-38644
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50445r2_rule
#
# STIG ID
#   RHEL-06-000265
#
# RULE TITLE
#   The ntpdate service must not be running.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000265;

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
    $self->{VULN_ID} = 'V-38644';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000096';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50445r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000265';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'The ntpdate service must not be running.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The ""ntpdate"" service may only be suitable for systems which are rebooted frequently enough that clock drift does not cause problems between reboots. In any event, the functionality of the ntpdate service is now available in the ntpd program and should be considered deprecated.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To check that the ""ntpdate"" service is disabled in system boot configuration, run the following command:



# chkconfig ""ntpdate"" --list



Output should indicate the ""ntpdate"" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:



# chkconfig ""ntpdate"" --list

""ntpdate"" 0:off 1:off 2:off 3:off 4:off 5:off 6:off



Run the following command to verify ""ntpdate"" is disabled through current runtime configuration:



# service ntpdate status



If the service is disabled the command will return the following output:



ntpdate is stopped





If the service is running, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The ntpdate service sets the local hardware clock by polling NTP servers when the system boots. It synchronizes to the NTP servers listed in ""/etc/ntp/step-tickers"" or ""/etc/ntp.conf"" and then sets the local hardware clock to the newly synchronized system time. The ""ntpdate"" service can be disabled with the following commands:



# chkconfig ntpdate off

# service ntpdate stop
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000382

The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.

NIST SP 800-53 :: CM-7

NIST SP 800-53A :: CM-7.1 (iii)

NIST SP 800-53 Revision 4 :: CM-7 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
