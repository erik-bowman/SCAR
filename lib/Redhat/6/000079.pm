# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000079
#
# VULN ID
#   V-38597
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50398r2_rule
#
# STIG ID
#   RHEL-06-000079
#
# RULE TITLE
#   The system must limit the ability of processes to have simultaneous write and execute access to memory.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000079;

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
    return 'V-38597';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50398r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000079';
}

sub get_rule_title {
    return
        'The system must limit the ability of processes to have simultaneous write and execute access to memory.';
}

sub get_discussion {
    return <<'DISCUSSION';
ExecShield uses the segmentation feature on all x86 systems to prevent execution in memory higher than a certain address. It writes an address as a limit in the code segment descriptor, to control where code can be executed, on a per-process basis. When the kernel places a process's memory regions such as the stack and heap higher than this address, the hardware prevents execution in that address range.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
The status of the ""kernel.exec-shield"" kernel parameter can be queried by running the following command:



$ sysctl kernel.exec-shield

$ grep kernel.exec-shield /etc/sysctl.conf



The output of the command should indicate a value of ""1"". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in ""/etc/sysctl.conf"".

If the correct value is not returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To set the runtime status of the ""kernel.exec-shield"" kernel parameter, run the following command:



# sysctl -w kernel.exec-shield=1



If this is not the system's default value, add the following line to ""/etc/sysctl.conf"":



kernel.exec-shield = 1
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
