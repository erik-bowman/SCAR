#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_021010
#
# VULN ID
#   V-72043
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86667r1_rule
#
# STIG ID
#   RHEL-07-021010
#
# RULE TITLE
#   File systems that are used with removable media must be mounted to prevent files with the setuid and setgid bit set from being executed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_021010;

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
    $self->{VULN_ID} = 'V-72043';
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
    $self->{RULE_ID} = 'SV-86667r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-021010';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'File systems that are used with removable media must be mounted to prevent files with the setuid and setgid bit set from being executed.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The ""nosuid"" mount option causes the system to not execute ""setuid"" and ""setgid"" files with owner privileges. This option must be used for mounting any file system not containing approved ""setuid"" and ""setguid"" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify file systems that are used for removable media are mounted with the ""nouid"" option.



Check the file systems that are mounted at boot time with the following command:



# more /etc/fstab



UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222     /mnt/usbflash      vfat   noauto,owner,ro,nosuid                        0 0



If a file system found in ""/etc/fstab"" refers to removable media and it does not have the ""nosuid"" option set, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the ""/etc/fstab"" to use the ""nosuid"" option on file systems that are associated with removable media.
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
