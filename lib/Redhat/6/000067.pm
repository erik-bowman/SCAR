# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000067
#
# VULN ID
#   V-38583
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50384r3_rule
#
# STIG ID
#   RHEL-06-000067
#
# RULE TITLE
#   The system boot loader configuration file(s) must have mode 0600 or less permissive.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000067;

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
    return 'V-38583';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50384r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000067';
}

sub get_rule_title {
    return
        'The system boot loader configuration file(s) must have mode 0600 or less permissive.';
}

sub get_discussion {
    return <<'DISCUSSION';
Proper permissions ensure that only the root user can modify important boot parameters.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check the permissions of ""/boot/grub/grub.conf"", run the command:



$ sudo ls -lL /boot/grub/grub.conf



If properly configured, the output should indicate the following permissions: ""-rw-------""

If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
File permissions for ""/boot/grub/grub.conf"" should be set to 600, which is the default. To properly set the permissions of ""/boot/grub/grub.conf"", run the command:



# chmod 600 /boot/grub/grub.conf



Boot partitions based on VFAT, NTFS, or other non-standard configurations may require alternative measures.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
