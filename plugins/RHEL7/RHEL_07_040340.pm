#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_040340
#
# VULN ID
#   V-72241
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000163-GPOS-00072
#
# RULE ID
#   SV-86865r2_rule
#
# STIG ID
#   RHEL-07-040340
#
# RULE TITLE
#   All network connections associated with SSH traffic must terminate after a period of inactivity.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_040340;

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
    $self->{VULN_ID} = 'V-72241';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000163-GPOS-00072';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86865r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-040340';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'All network connections associated with SSH traffic must terminate after a period of inactivity.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Terminating an idle SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.



Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.



Satisfies: SRG-OS-000163-GPOS-00072, SRG-OS-000279-GPOS-00109
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system automatically terminates a user session after inactivity time-outs have expired.



Check for the value of the ""ClientAliveCountMax"" keyword with the following command:



# grep -i clientalivecount /etc/ssh/sshd_config

ClientAliveCountMax 0



If ""ClientAliveCountMax"" is not set to ""0"" in ""/etc/ ssh/sshd_config"", this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to automatically terminate a user session after inactivity time-outs have expired or at shutdown.



Add the following line (or modify the line to have the required value) to the ""/etc/ssh/sshd_config"" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):



ClientAliveCountMax 0



The SSH service must be restarted for changes to take effect.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001133

The information system terminates the network connection associated with a communications session at the end of the session or after an organization-defined time period of inactivity.

NIST SP 800-53 :: SC-10

NIST SP 800-53A :: SC-10.1 (ii)

NIST SP 800-53 Revision 4 :: SC-10



CCI-002361

The information system automatically terminates a user session after organization-defined conditions or trigger events requiring session disconnect.

NIST SP 800-53 Revision 4 :: AC-12




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
