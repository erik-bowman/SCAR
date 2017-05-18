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

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $plugin = RHEL_06_000230->new( $parent );
#
# DESCRIPTION
#   Initializes the plugin object and returns it
#
# ARGUMENTS
#   $parent    = The SCAR::RHEL6 module object
#
# ------------------------------------------------------------------------------

sub new {
    my ( $class, $parent ) = @_;
    my $self = bless { parent => $parent }, $class;

    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $results = RHEL_06_000230->check();
#
# DESCRIPTION
#   Performs a test against the system
#
# ------------------------------------------------------------------------------

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

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $results = RHEL_06_000230->remediate();
#
# DESCRIPTION
#   Attempts remediation
#
# ------------------------------------------------------------------------------

sub remediate {
    my ($self) = @_;

    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $VULN_ID = RHEL_06_000230->VULN_ID();
#
# DESCRIPTION
#   Returns the plugins VULN ID
#
# ------------------------------------------------------------------------------

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38608';
    return $self->{VULN_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $SEVERITY = RHEL_06_000230->SEVERITY();
#
# DESCRIPTION
#   Returns the plugins SEVERITY
#
# ------------------------------------------------------------------------------

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $GROUP_TITLE = RHEL_06_000230->GROUP_TITLE();
#
# DESCRIPTION
#   Returns the plugins GROUP TITLE
#
# ------------------------------------------------------------------------------

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000163';
    return $self->{GROUP_TITLE};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $RULE_ID = RHEL_06_000230->RULE_ID();
#
# DESCRIPTION
#   Returns the plugins RULE ID
#
# ------------------------------------------------------------------------------

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50409r1_rule';
    return $self->{RULE_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $STIG_ID = RHEL_06_000230->STIG_ID();
#
# DESCRIPTION
#   Returns the plugins STIG ID
#
# ------------------------------------------------------------------------------

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000230';
    return $self->{STIG_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $RULE_TITLE = RHEL_06_000230->RULE_TITLE();
#
# DESCRIPTION
#   Returns the plugins RULE TITLE
#
# ------------------------------------------------------------------------------

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The SSH daemon must set a timeout interval on idle sessions.';
    return $self->{RULE_TITLE};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $DISCUSSION = RHEL_06_000230->DISCUSSION();
#
# DESCRIPTION
#   Returns the plugins DISCUSSION text
#
# ------------------------------------------------------------------------------

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Causing idle users to be automatically logged out guards against compromises one system leading trivially to compromises on another.
DISCUSSION
    return $self->{DISCUSSION};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $CHECK_CONTENT = RHEL_06_000230->CHECK_CONTENT();
#
# DESCRIPTION
#   Returns the plugins CHECK CONTENT text
#
# ------------------------------------------------------------------------------

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

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $FIX_CONTENT = RHEL_06_000230->FIX_CONTENT();
#
# DESCRIPTION
#   Returns the plugins FIX CONTENT text
#
# ------------------------------------------------------------------------------

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

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $CCI = RHEL_06_000230->CCI();
#
# DESCRIPTION
#   Returns the plugins CCI text
#
# ------------------------------------------------------------------------------

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
