# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000315
#
# VULN ID
#   V-38682
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000034
#
# RULE ID
#   SV-50483r4_rule
#
# STIG ID
#   RHEL-06-000315
#
# RULE TITLE
#   The Bluetooth kernel module must be disabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000315;

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
    return 'V-38682';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000034';
}

sub get_rule_id {
    return 'SV-50483r4_rule';
}

sub get_stig_id {
    return 'RHEL-06-000315';
}

sub get_rule_title {
    return 'The Bluetooth kernel module must be disabled.';
}

sub get_discussion {
    return <<'DISCUSSION';
If Bluetooth functionality must be disabled, preventing the kernel from loading the kernel module provides an additional safeguard against its activation.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the system is configured to prevent the loading of the ""bluetooth"" kernel module, it will contain lines inside any file in ""/etc/modprobe.d"" or the deprecated""/etc/modprobe.conf"". These lines instruct the module loading system to run another program (such as ""/bin/true"") upon a module ""install"" event. Run the following command to search for such lines in all files in ""/etc/modprobe.d"" and the deprecated ""/etc/modprobe.conf"":



$ grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d | grep -i ""/bin/true""



If no line is returned, this is a finding.



If the system is configured to prevent the loading of the ""net-pf-31"" kernel module, it will contain lines inside any file in ""/etc/modprobe.d"" or the deprecated""/etc/modprobe.conf"". These lines instruct the module loading system to run another program (such as ""/bin/true"") upon a module ""install"" event. Run the following command to search for such lines in all files in ""/etc/modprobe.d"" and the deprecated ""/etc/modprobe.conf"":



$ grep -r net-pf-31 /etc/modprobe.conf /etc/modprobe.d | grep -i ""/bin/true""



If no line is returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The kernel's module loading system can be configured to prevent loading of the Bluetooth module. Add the following to the appropriate ""/etc/modprobe.d"" configuration file to prevent the loading of the Bluetooth module:



install net-pf-31 /bin/true

install bluetooth /bin/true
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000085

The organization monitors for unauthorized connections of mobile devices to organizational information systems.

NIST SP 800-53 :: AC-19 c

NIST SP 800-53A :: AC-19.1 (iii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
