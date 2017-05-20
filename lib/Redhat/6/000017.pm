# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000017
#
# VULN ID
#   V-51337
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-65547r2_rule
#
# STIG ID
#   RHEL-06-000017
#
# RULE TITLE
#   The system must use a Linux Security Module at boot time.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000017;

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
    return 'V-51337';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-65547r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000017';
}

sub get_rule_title {
    return 'The system must use a Linux Security Module at boot time.';
}

sub get_discussion {
    return <<'DISCUSSION';
Disabling a major host protection feature, such as SELinux, at boot time prevents it from confining system services at boot time. Further, it increases the chances that it will remain off during system operation.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect ""/boot/grub/grub.conf"" for any instances of ""selinux=0"" in the kernel boot arguments. Presence of ""selinux=0"" indicates that SELinux is disabled at boot time. If SELinux is disabled at boot time, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
SELinux can be disabled at boot time by an argument in ""/boot/grub/grub.conf"". Remove any instances of ""selinux=0"" from the kernel arguments in that file to prevent SELinux from being disabled at boot.
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
