# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020110
#
# VULN ID
#   V-71985
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000114-GPOS-00059
#
# RULE ID
#   SV-86609r1_rule
#
# STIG ID
#   RHEL-07-020110
#
# RULE TITLE
#   File system automounter must be disabled unless required.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020110;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# Scar modules
use Scar;
use Scar::Util::Log;
use Scar::Util::Backup;

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
    $self->{VULN_ID} = 'V-71985';
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
    $self->{RULE_ID} = 'SV-86609r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-020110';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'File system automounter must be disabled unless required.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.



Satisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163, SRG-OS-000480-GPOS-00227
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system disables the ability to automount devices.



Check to see if automounter service is active with the following command:



# systemctl status autofs

autofs.service - Automounts filesystems on demand

   Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)

   Active: inactive (dead)



If the ""autofs"" status is set to ""active"" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to disable the ability to automount devices.



Turn off the automount service with the following command:



# systemctl disable autofs



If ""autofs"" is required for Network File System (NFS), it must be documented with the ISSO.
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
