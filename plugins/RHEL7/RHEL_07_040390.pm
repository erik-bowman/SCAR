#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_040390
#
# VULN ID
#   V-72251
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000074-GPOS-00042
#
# RULE ID
#   SV-86875r2_rule
#
# STIG ID
#   RHEL-07-040390
#
# RULE TITLE
#   The SSH daemon must be configured to only use the SSHv2 protocol.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_040390;

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
    $self->{VULN_ID} = 'V-72251';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'high';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000074-GPOS-00042';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86875r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-040390';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The SSH daemon must be configured to only use the SSHv2 protocol.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
SSHv1 is an insecure implementation of the SSH protocol and has many well-known vulnerability exploits. Exploits of the SSH daemon could provide immediate root access to the system.



Satisfies: SRG-OS-000074-GPOS-00042, SRG-OS-000480-GPOS-00227
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the SSH daemon is configured to only use the SSHv2 protocol.



Check that the SSH daemon is configured to only use the SSHv2 protocol with the following command:



# grep -i protocol /etc/ssh/sshd_config

Protocol 2

#Protocol 1,2



If any protocol line other than ""Protocol 2"" is uncommented, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Remove all Protocol lines that reference version ""1"" in ""/etc/ssh/sshd_config"" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor). The ""Protocol"" line must be as follows:



Protocol 2



The SSH service must be restarted for changes to take effect.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000197

The information system, for password-based authentication, transmits only encrypted representations of passwords.

NIST SP 800-53 :: IA-5 (1) (c)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (c)



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
