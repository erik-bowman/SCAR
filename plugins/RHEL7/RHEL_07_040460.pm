#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_040460
#
# VULN ID
#   V-72265
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86889r2_rule
#
# STIG ID
#   RHEL-07-040460
#
# RULE TITLE
#   The SSH daemon must use privilege separation.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_040460;

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
#   $plugin = RHEL_07_040460->new( $parent );
#
# DESCRIPTION
#   Initializes the plugin object and returns it
#
# ARGUMENTS
#   $parent    = The SCAR::RHEL7 module object
#
# ------------------------------------------------------------------------------

sub new {
    my ( $class, $parent ) = @_;
    my $self = bless { parent => $parent }, $class;

    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $results = RHEL_07_040460->check();
#
# DESCRIPTION
#   Performs a test against the system
#
# ------------------------------------------------------------------------------

sub check {
    my ($self) = @_;

    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $results = RHEL_07_040460->remediate();
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
#   $VULN_ID = RHEL_07_040460->VULN_ID();
#
# DESCRIPTION
#   Returns the plugins VULN ID
#
# ------------------------------------------------------------------------------

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-72265';
    return $self->{VULN_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $SEVERITY = RHEL_07_040460->SEVERITY();
#
# DESCRIPTION
#   Returns the plugins SEVERITY
#
# ------------------------------------------------------------------------------

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $GROUP_TITLE = RHEL_07_040460->GROUP_TITLE();
#
# DESCRIPTION
#   Returns the plugins GROUP TITLE
#
# ------------------------------------------------------------------------------

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00227';
    return $self->{GROUP_TITLE};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $RULE_ID = RHEL_07_040460->RULE_ID();
#
# DESCRIPTION
#   Returns the plugins RULE ID
#
# ------------------------------------------------------------------------------

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86889r2_rule';
    return $self->{RULE_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $STIG_ID = RHEL_07_040460->STIG_ID();
#
# DESCRIPTION
#   Returns the plugins STIG ID
#
# ------------------------------------------------------------------------------

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-040460';
    return $self->{STIG_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $RULE_TITLE = RHEL_07_040460->RULE_TITLE();
#
# DESCRIPTION
#   Returns the plugins RULE TITLE
#
# ------------------------------------------------------------------------------

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'The SSH daemon must use privilege separation.';
    return $self->{RULE_TITLE};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $DISCUSSION = RHEL_07_040460->DISCUSSION();
#
# DESCRIPTION
#   Returns the plugins DISCUSSION text
#
# ------------------------------------------------------------------------------

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.
DISCUSSION
    return $self->{DISCUSSION};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $CHECK_CONTENT = RHEL_07_040460->CHECK_CONTENT();
#
# DESCRIPTION
#   Returns the plugins CHECK CONTENT text
#
# ------------------------------------------------------------------------------

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the SSH daemon performs privilege separation.



Check that the SSH daemon performs privilege separation with the following command:



# grep -i usepriv /etc/ssh/sshd_config



UsePrivilegeSeparation sandbox



If the ""UsePrivilegeSeparation"" keyword is set to ""no"", is missing, or the retuned line is commented out, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $FIX_CONTENT = RHEL_07_040460->FIX_CONTENT();
#
# DESCRIPTION
#   Returns the plugins FIX CONTENT text
#
# ------------------------------------------------------------------------------

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Uncomment the ""UsePrivilegeSeparation"" keyword in ""/etc/ssh/sshd_config"" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to ""sandbox"" or ""yes"":



UsePrivilegeSeparation sandbox



The SSH service must be restarted for changes to take effect.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $CCI = RHEL_07_040460->CCI();
#
# DESCRIPTION
#   Returns the plugins CCI text
#
# ------------------------------------------------------------------------------

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
