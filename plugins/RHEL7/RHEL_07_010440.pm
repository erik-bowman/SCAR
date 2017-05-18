#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_010440
#
# VULN ID
#   V-71953
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00229
#
# RULE ID
#   SV-86577r1_rule
#
# STIG ID
#   RHEL-07-010440
#
# RULE TITLE
#   The operating system must not allow an unattended or automatic logon to the system via a graphical user interface.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_010440;

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
#   $plugin = RHEL_07_010440->new( $parent );
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
#   $results = RHEL_07_010440->check();
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
#   $results = RHEL_07_010440->remediate();
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
#   $VULN_ID = RHEL_07_010440->VULN_ID();
#
# DESCRIPTION
#   Returns the plugins VULN ID
#
# ------------------------------------------------------------------------------

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-71953';
    return $self->{VULN_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $SEVERITY = RHEL_07_010440->SEVERITY();
#
# DESCRIPTION
#   Returns the plugins SEVERITY
#
# ------------------------------------------------------------------------------

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'high';
    return $self->{SEVERITY};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $GROUP_TITLE = RHEL_07_010440->GROUP_TITLE();
#
# DESCRIPTION
#   Returns the plugins GROUP TITLE
#
# ------------------------------------------------------------------------------

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00229';
    return $self->{GROUP_TITLE};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $RULE_ID = RHEL_07_010440->RULE_ID();
#
# DESCRIPTION
#   Returns the plugins RULE ID
#
# ------------------------------------------------------------------------------

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86577r1_rule';
    return $self->{RULE_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $STIG_ID = RHEL_07_010440->STIG_ID();
#
# DESCRIPTION
#   Returns the plugins STIG ID
#
# ------------------------------------------------------------------------------

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010440';
    return $self->{STIG_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $RULE_TITLE = RHEL_07_010440->RULE_TITLE();
#
# DESCRIPTION
#   Returns the plugins RULE TITLE
#
# ------------------------------------------------------------------------------

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must not allow an unattended or automatic logon to the system via a graphical user interface.';
    return $self->{RULE_TITLE};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $DISCUSSION = RHEL_07_010440->DISCUSSION();
#
# DESCRIPTION
#   Returns the plugins DISCUSSION text
#
# ------------------------------------------------------------------------------

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Failure to restrict system access to authenticated users negatively impacts operating system security.
DISCUSSION
    return $self->{DISCUSSION};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $CHECK_CONTENT = RHEL_07_010440->CHECK_CONTENT();
#
# DESCRIPTION
#   Returns the plugins CHECK CONTENT text
#
# ------------------------------------------------------------------------------

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system does not allow an unattended or automatic logon to the system via a graphical user interface.



Note: If the system does not have GNOME installed, this requirement is Not Applicable.



Check for the value of the ""AutomaticLoginEnable"" in the ""/etc/gdm/custom.conf"" file with the following command:



# grep -i automaticloginenable /etc/gdm/custom.conf

AutomaticLoginEnable=false



If the value of ""AutomaticLoginEnable"" is not set to ""false"", this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $FIX_CONTENT = RHEL_07_010440->FIX_CONTENT();
#
# DESCRIPTION
#   Returns the plugins FIX CONTENT text
#
# ------------------------------------------------------------------------------

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to not allow an unattended or automatic logon to the system via a graphical user interface.



Note: If the system does not have GNOME installed, this requirement is Not Applicable.



Add or edit the line for the ""AutomaticLoginEnable"" parameter in the [daemon] section of the ""/etc/gdm/custom.conf"" file to ""false"":



[daemon]

AutomaticLoginEnable=false
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $CCI = RHEL_07_010440->CCI();
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
