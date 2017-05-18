#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_010100
#
# VULN ID
#   V-71899
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000029-GPOS-00010
#
# RULE ID
#   SV-86523r1_rule
#
# STIG ID
#   RHEL-07-010100
#
# RULE TITLE
#   The operating system must initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_010100;

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
    $self->{VULN_ID} = 'V-71899';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000029-GPOS-00010';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86523r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010100';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.



The session lock is implemented at the point where session activity can be determined and/or controlled.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system initiates a session lock after a 15-minute period of inactivity for graphical user interfaces. The screen program must be installed to lock sessions on the console.



If it is installed, GNOME must be configured to enforce a session lock after a 15-minute delay. Check for the session lock settings with the following commands:



# grep -i  idle_activation_enabled /etc/dconf/db/local.d/*

[org/gnome/desktop/screensaver]   idle-activation-enabled=true



If ""idle-activation-enabled"" is not set to ""true"", this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to initiate a session lock after a 15-minute period of inactivity for graphical user interfaces.



Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:



# touch /etc/dconf/db/local.d/00-screensaver



Add the setting to enable screensaver locking after 15 minutes of inactivity:



[org/gnome/desktop/screensaver]



idle-activation-enabled=true
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000057

The information system initiates a session lock after the organization-defined time period of inactivity.

NIST SP 800-53 :: AC-11 a

NIST SP 800-53A :: AC-11.1 (ii)

NIST SP 800-53 Revision 4 :: AC-11 a




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
