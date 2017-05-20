# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000202
#
# VULN ID
#   V-38580
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000064
#
# RULE ID
#   SV-50381r2_rule
#
# STIG ID
#   RHEL-06-000202
#
# RULE TITLE
#   The audit system must be configured to audit the loading and unloading of dynamic kernel modules.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000202;

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
    return 'V-38580';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000064';
}

sub get_rule_id {
    return 'SV-50381r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000202';
}

sub get_rule_title {
    return
        'The audit system must be configured to audit the loading and unloading of dynamic kernel modules.';
}

sub get_discussion {
    return <<'DISCUSSION';
The addition/removal of kernel modules can be used to alter the behavior of the kernel and potentially introduce malicious code into kernel space. It is important to have an audit trail of modules that have been introduced into the kernel.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine if the system is configured to audit execution of module management programs, run the following commands:



$ sudo egrep -e ""(-w |-F path=)/sbin/insmod"" /etc/audit/audit.rules

$ sudo egrep -e ""(-w |-F path=)/sbin/rmmod"" /etc/audit/audit.rules

$ sudo egrep -e ""(-w |-F path=)/sbin/modprobe"" /etc/audit/audit.rules



If the system is configured to audit this activity, it will return a line.



To determine if the system is configured to audit calls to the ""init_module"" system call, run the following command:



$ sudo grep -w ""init_module"" /etc/audit/audit.rules



If the system is configured to audit this activity, it will return a line.



To determine if the system is configured to audit calls to the ""delete_module"" system call, run the following command:



$ sudo grep -w ""delete_module"" /etc/audit/audit.rules



If the system is configured to audit this activity, it will return a line.



If no line is returned for any of these commands, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Add the following to ""/etc/audit/audit.rules"" in order to capture kernel module loading and unloading events, setting ARCH to either b32 or b64 as appropriate for your system:



-w /sbin/insmod -p x -k modules

-w /sbin/rmmod -p x -k modules

-w /sbin/modprobe -p x -k modules

-a always,exit -F arch=[ARCH] -S init_module -S delete_module -k modules
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000172

The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.

NIST SP 800-53 :: AU-12 c

NIST SP 800-53A :: AU-12.1 (iv)

NIST SP 800-53 Revision 4 :: AU-12 c




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
