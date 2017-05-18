#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_020100
#
# VULN ID
#   V-71983
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000114-GPOS-00059
#
# RULE ID
#   SV-86607r1_rule
#
# STIG ID
#   RHEL-07-020100
#
# RULE TITLE
#   USB mass storage must be disabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_020100;

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
    $self->{VULN_ID} = 'V-71983';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000114-GPOS-00059';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86607r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-020100';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'USB mass storage must be disabled.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
USB mass storage permits easy introduction of unknown devices, thereby facilitating malicious activity.



Satisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163, SRG-OS-000480-GPOS-00227
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If there is an HBSS with a Device Control Module and a Data Loss Prevention mechanism, this requirement is not applicable.



Verify the operating system disables the ability to use USB mass storage devices.



Check to see if USB mass storage is disabled with the following command:



#grep -i usb-storage /etc/modprobe.d/*



install usb-storage /bin/true



If the command does not return any output, and use of USB storage devices is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to disable the ability to use USB mass storage devices.



Create a file under ""/etc/modprobe.d"" with the following command:



#touch /etc/modprobe.d/nousbstorage



Add the following line to the created file:



install usb-storage /bin/true
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



CCI-000778

The information system uniquely identifies an organization defined list of specific and/or types of devices before establishing a local, remote, or network connection.

NIST SP 800-53 :: IA-3

NIST SP 800-53A :: IA-3.1 (ii)

NIST SP 800-53 Revision 4 :: IA-3



CCI-001958

The information system authenticates an organization defined list of specific and/or types of devices before establishing a local, remote, or network connection.

NIST SP 800-53 Revision 4 :: IA-3




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
