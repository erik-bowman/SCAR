# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000525
#
# VULN ID
#   V-38438
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000062
#
# RULE ID
#   SV-50238r3_rule
#
# STIG ID
#   RHEL-06-000525
#
# RULE TITLE
#   Auditing must be enabled at boot by setting a kernel parameter.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000525;

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
    return 'V-38438';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000062';
}

sub get_rule_id {
    return 'SV-50238r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000525';
}

sub get_rule_title {
    return 'Auditing must be enabled at boot by setting a kernel parameter.';
}

sub get_discussion {
    return <<'DISCUSSION';
Each process on the system carries an ""auditable"" flag which indicates whether its activities can be audited. Although ""auditd"" takes care of enabling this for all processes which launch after it does, adding the kernel argument ensures it is set for every process during boot.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect the kernel boot arguments (which follow the word ""kernel"") in ""/boot/grub/grub.conf"". If they include ""audit=1"", then auditing is enabled at boot time.



If auditing is not enabled at boot time, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To ensure all processes can be audited, even those which start prior to the audit daemon, add the argument ""audit=1"" to the kernel line in ""/boot/grub/grub.conf"", in the manner below:



kernel /vmlinuz-version ro vga=ext root=/dev/VolGroup00/LogVol00 rhgb quiet audit=1



UEFI systems may prepend ""/boot"" to the ""/vmlinuz-version"" argument.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000169

The information system provides audit record generation capability for the auditable events defined in AU-2 a at organization-defined information system components.

NIST SP 800-53 :: AU-12 a

NIST SP 800-53A :: AU-12.1 (ii)

NIST SP 800-53 Revision 4 :: AU-12 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
