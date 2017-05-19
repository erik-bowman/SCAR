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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38580';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000064';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50381r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000202';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The addition/removal of kernel modules can be used to alter the behavior of the kernel and potentially introduce malicious code into kernel space. It is important to have an audit trail of modules that have been introduced into the kernel.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
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
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Add the following to ""/etc/audit/audit.rules"" in order to capture kernel module loading and unloading events, setting ARCH to either b32 or b64 as appropriate for your system:



-w /sbin/insmod -p x -k modules

-w /sbin/rmmod -p x -k modules

-w /sbin/modprobe -p x -k modules

-a always,exit -F arch=[ARCH] -S init_module -S delete_module -k modules
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000172

The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.

NIST SP 800-53 :: AU-12 c

NIST SP 800-53A :: AU-12.1 (iv)

NIST SP 800-53 Revision 4 :: AU-12 c




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
