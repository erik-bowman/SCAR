#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_040400
#
# VULN ID
#   V-72253
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000250-GPOS-00093
#
# RULE ID
#   SV-86877r2_rule
#
# STIG ID
#   RHEL-07-040400
#
# RULE TITLE
#   The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_040400;

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
    $self->{VULN_ID} = 'V-72253';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000250-GPOS-00093';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86877r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-040400';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions. The only SSHv2 hash algorithm meeting this requirement is SHA.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the SSH daemon is configured to only use MACs employing FIPS 140-2-approved ciphers.



Note: If RHEL-07-021350 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes.



Check that the SSH daemon is configured to only use MACs employing FIPS 140-2-approved ciphers with the following command:



# grep -i macs /etc/ssh/sshd_config

MACs hmac-sha2-256,hmac-sha2-512



If any ciphers other than ""hmac-sha2-256"" or ""hmac-sha2-512"" are listed or the retuned line is commented out, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Edit the ""/etc/ssh/sshd_config"" file to uncomment or add the line for the ""MACs"" keyword and set its value to ""hmac-sha2-256"" and/or ""hmac-sha2-512"" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):



MACs hmac-sha2-256,hmac-sha2-512



The SSH service must be restarted for changes to take effect.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001453

The information system implements cryptographic mechanisms to protect the integrity of remote access sessions.

NIST SP 800-53 :: AC-17 (2)

NIST SP 800-53A :: AC-17 (2).1

NIST SP 800-53 Revision 4 :: AC-17 (2)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
