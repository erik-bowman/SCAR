#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_021700
#
# VULN ID
#   V-72075
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000364-GPOS-00151
#
# RULE ID
#   SV-86699r1_rule
#
# STIG ID
#   RHEL-07-021700
#
# RULE TITLE
#   The system must not allow removable media to be used as the boot loader unless approved.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_021700;

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
    $self->{VULN_ID} = 'V-72075';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000364-GPOS-00151';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86699r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-021700';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must not allow removable media to be used as the boot loader unless approved.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader. If removable media is designed to be used as the boot loader, the requirement must be documented with the Information System Security Officer (ISSO).
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the system is not configured to use a boot loader on removable media.



Note: GRUB 2 reads its configuration from the ""/boot/grub2/grub.cfg"" file on traditional BIOS-based machines and from the ""/boot/efi/EFI/redhat/grub.cfg"" file on UEFI machines.



Check for the existence of alternate boot loader configuration files with the following command:



# find / -name grub.cfg

/boot/grub2/grub.cfg



If a ""grub.cfg"" is found in any subdirectories other than ""/boot/grub2"" and ""/boot/efi/EFI/redhat"", ask the System Administrator if there is documentation signed by the ISSO to approve the use of removable media as a boot loader.



Check that the grub configuration file has the set root command in each menu entry with the following commands:



# grep -c menuentry /boot/grub2/grub.cfg

1

# grep ‘set root’ /boot/grub2/grub.cfg

set root=(hd0,1)



If the system is using an alternate boot loader on removable media, and documentation does not exist approving the alternate configuration, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Remove alternate methods of booting the system from removable media or document the configuration to boot from removable media with the ISSO.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000318

The organization audits and reviews activities associated with configuration controlled changes to the system.

NIST SP 800-53 :: CM-3 e

NIST SP 800-53A :: CM-3.1 (v)

NIST SP 800-53 Revision 4 :: CM-3 f



CCI-000368

The organization documents any deviations from the established configuration settings for organization-defined information system components based on organization-defined operational requirements.

NIST SP 800-53 :: CM-6 c

NIST SP 800-53A :: CM-6.1 (v)

NIST SP 800-53 Revision 4 :: CM-6 c



CCI-001812

The information system prohibits user installation of software without explicit privileged status.

NIST SP 800-53 Revision 4 :: CM-11 (2)



CCI-001813

The information system enforces access restrictions.

NIST SP 800-53 Revision 4 :: CM-5 (1)



CCI-001814

The Information system supports auditing of the enforcement actions.

NIST SP 800-53 Revision 4 :: CM-5 (1)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
