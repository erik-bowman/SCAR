#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_010070
#
# VULN ID
#   V-71893
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000029-GPOS-00010
#
# RULE ID
#   SV-86517r2_rule
#
# STIG ID
#   RHEL-07-010070
#
# RULE TITLE
#   The operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_010070;

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
    $self->{VULN_ID} = 'V-71893';
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
    $self->{RULE_ID} = 'SV-86517r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010070';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.';
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
Verify the operating system initiates a screensaver after a 15-minute period of inactivity for graphical user interfaces. The screen program must be installed to lock sessions on the console.



Note: If the system does not have GNOME installed, this requirement is Not Applicable.



Check to see if GNOME is configured to display a screensaver after a 15 minute delay with the following command:



# grep -i idle-delay /etc/dconf/db/local.d/*

idle-delay=uint32 900



If the ""idle-delay"" setting is missing or is not set to ""900"" or less, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.



Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:



# touch /etc/dconf/db/local.d/00-screensaver



Edit ""org/gnome/desktop/session"" and add or update the following lines:



# Set the lock time out to 900 seconds before the session is considered idle

idle-delay=uint32 900



Edit ""org/gnome/desktop/screensaver"" and add or update the following lines:



# Set this to true to lock the screen when the screensaver activates

lock-enabled=true

# Set the lock timeout to 180 seconds after the screensaver has been activated

lock-delay=uint32 180



You must include the ""uint32"" along with the integer key values as shown.



Override the user's setting and prevent the user from changing it by editing ""/etc/dconf/db/local.d/locks/screensaver"" and adding or updating the following lines:



# Lock desktop screensaver settings

/org/gnome/desktop/session/idle-delay

/org/gnome/desktop/screensaver/lock-enabled

/org/gnome/desktop/screensaver/lock-delay



Update the system databases:



# dconf update



Users must log out and back in again before the system-wide settings take effect.
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
