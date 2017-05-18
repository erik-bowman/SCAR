#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000508
#
# VULN ID
#   V-38474
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000030
#
# RULE ID
#   SV-50274r2_rule
#
# STIG ID
#   RHEL-06-000508
#
# RULE TITLE
#   The system must allow locking of graphical desktop sessions.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000508;

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
    $self->{VULN_ID} = 'V-38474';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000030';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50274r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000508';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must allow locking of graphical desktop sessions.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The ability to lock graphical desktop sessions manually allows users to easily secure their accounts should they need to depart from their workstations temporarily.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If the GConf2 package is not installed, this is not applicable.



Verify the keybindings for the Gnome screensaver:



# gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome_settings_daemon/keybindings/screensaver



If no output is visible, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Run the following command to set the Gnome desktop keybinding for locking the screen:



# gconftool-2

--direct \

--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \

--type string \

--set /apps/gnome_settings_daemon/keybindings/screensaver ""<Control><Alt>l""



Another keyboard sequence may be substituted for ""<Control><Alt>l"", which is the default for the Gnome desktop.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000058

The information system provides the capability for users to directly initiate session lock mechanisms.

NIST SP 800-53 :: AC-11 a

NIST SP 800-53A :: AC-11

NIST SP 800-53 Revision 4 :: AC-11 a




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
