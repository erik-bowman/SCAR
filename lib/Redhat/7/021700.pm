# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021700
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

package Redhat::7::021700;

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

sub _set_finding_status {
    my ( $self, $finding_status ) = @_;
    $self->{finding_status} = $finding_status;
    return $self->{finding_status};
}

sub get_finding_status {
    my ($self) = @_;
    return defined $self->{finding_status} ? $self->{finding_status} : undef;
}

sub get_vuln_id {
    return 'V-72075';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000364-GPOS-00151';
}

sub get_rule_id {
    return 'SV-86699r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-021700';
}

sub get_rule_title {
    return
        'The system must not allow removable media to be used as the boot loader unless approved.';
}

sub get_discussion {
    return <<'DISCUSSION';
Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader. If removable media is designed to be used as the boot loader, the requirement must be documented with the Information System Security Officer (ISSO).
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
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
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Remove alternate methods of booting the system from removable media or document the configuration to boot from removable media with the ISSO.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
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
}

# ------------------------------------------------------------------------------

1;

__END__
