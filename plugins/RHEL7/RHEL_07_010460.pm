#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_010460
#
# VULN ID
#   V-71957
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00229
#
# RULE ID
#   SV-86581r2_rule
#
# STIG ID
#   RHEL-07-010460
#
# RULE TITLE
#   The operating system must not allow users to override SSH environment variables.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_010460;

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
    $self->{VULN_ID} = 'V-71957';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00229';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86581r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010460';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must not allow users to override SSH environment variables.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Failure to restrict system access to authenticated users negatively impacts operating system security.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system does not allow users to override environment variables to the SSH daemon.



Check for the value of the ""PermitUserEnvironment"" keyword with the following command:



# grep -i permituserenvironment /etc/ssh/sshd_config

PermitUserEnvironment no



If the ""PermitUserEnvironment"" keyword is not set to ""no"", is missing, or is commented out, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to not allow users to override environment variables to the SSH daemon.



Edit the ""/etc/ssh/sshd_config"" file to uncomment or add the line for ""PermitUserEnvironment"" keyword and set the value to ""no"":



PermitUserEnvironment no



The SSH service must be restarted for changes to take effect.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

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
