#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000230
#
# VULN ID
#   V-38608
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000163
#
# RULE ID
#   SV-50409r1_rule
#
# STIG ID
#   RHEL-06-000230
#
# RULE TITLE
#   The SSH daemon must set a timeout interval on idle sessions.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000230;

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
    if ( PARSE( '^ClientAliveInterval\W+900$', '/etc/ssh/sshd_config' ) ) {
        $self->{STATUS} = 'NF';
    }
    else {
        $self->{STATUS} = 'O';
    }
    return $self;
}

sub remediate {
    my ($self) = @_;

    return $self;
}

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38608';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000163';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50409r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000230';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The SSH daemon must set a timeout interval on idle sessions.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Causing idle users to be automatically logged out guards against compromises one system leading trivially to compromises on another.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Run the following command to see what the timeout interval is:



# grep ClientAliveInterval /etc/ssh/sshd_config



If properly configured, the output should be:



ClientAliveInterval 900





If it is not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
SSH allows administrators to set an idle timeout interval. After this interval has passed, the idle user will be automatically logged out.



To set an idle timeout interval, edit the following line in ""/etc/ssh/sshd_config"" as follows:



ClientAliveInterval [interval]



The timeout [interval] is given in seconds. To have a timeout of 15 minutes, set [interval] to 900.



If a shorter timeout has already been set for the login shell, that value will preempt any SSH setting made here. Keep in mind that some processes may stop SSH from correctly detecting that the user is idle.
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




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
