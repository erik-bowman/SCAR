#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000273
#
# VULN ID
#   V-38657
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50458r2_rule
#
# STIG ID
#   RHEL-06-000273
#
# RULE TITLE
#   The system must use SMB client signing for connecting to samba servers using mount.cifs.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000273;

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
    $self->{VULN_ID} = 'V-38657';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-999999';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50458r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000273';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must use SMB client signing for connecting to samba servers using mount.cifs.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If Samba is not in use, this is not applicable.



To verify that Samba clients using mount.cifs must use packet signing, run the following command:



# grep sec /etc/fstab /etc/mtab



The output should show either ""krb5i"" or ""ntlmv2i"" in use.

If it does not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Require packet signing of clients who mount Samba shares using the ""mount.cifs"" program (e.g., those who specify shares in ""/etc/fstab""). To do so, ensure signing options (either ""sec=krb5i"" or ""sec=ntlmv2i"") are used.



See the ""mount.cifs(8)"" man page for more information. A Samba client should only communicate with servers who can support SMB packet signing.
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
