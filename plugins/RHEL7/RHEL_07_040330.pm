#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_040330
#
# VULN ID
#   V-72239
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86863r2_rule
#
# STIG ID
#   RHEL-07-040330
#
# RULE TITLE
#   The SSH daemon must not allow authentication using RSA rhosts authentication.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_040330;

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
    $self->{VULN_ID} = 'V-72239';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00227';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86863r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-040330';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The SSH daemon must not allow authentication using RSA rhosts authentication.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the SSH daemon does not allow authentication using RSA rhosts authentication.



To determine how the SSH daemon's ""RhostsRSAAuthentication"" option is set, run the following command:



# grep RhostsRSAAuthentication /etc/ssh/sshd_config



RhostsRSAAuthentication yes



If the value is returned as ""no"", the returned line is commented out, or no output is returned, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the SSH daemon to not allow authentication using RSA rhosts authentication.



Add the following line in ""/etc/ssh/sshd_config"", or uncomment the line and set the value to ""yes"":



RhostsRSAAuthentication yes



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
