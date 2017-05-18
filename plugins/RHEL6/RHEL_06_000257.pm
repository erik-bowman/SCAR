#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000257
#
# VULN ID
#   V-38629
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000029
#
# RULE ID
#   SV-50430r3_rule
#
# STIG ID
#   RHEL-06-000257
#
# RULE TITLE
#   The graphical desktop environment must set the idle timeout to no more than 15 minutes.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000257;

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
    $self->{VULN_ID} = 'V-38629';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000029';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50430r3_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000257';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The graphical desktop environment must set the idle timeout to no more than 15 minutes.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Setting the idle delay controls when the screensaver will start, and can be combined with screen locking to prevent access from passersby.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If the GConf2 package is not installed, this is not applicable.



To check the current idle time-out value, run the following command:



$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_delay



If properly configured, the output should be ""15"".



If it is not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Run the following command to set the idle time-out value for inactivity in the GNOME desktop to 15 minutes:



# gconftool-2 \

--direct \

--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \

--type int \

--set /apps/gnome-screensaver/idle_delay 15
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
