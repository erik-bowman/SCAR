# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000182
#
# VULN ID
#   V-38540
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50341r4_rule
#
# STIG ID
#   RHEL-06-000182
#
# RULE TITLE
#   The audit system must be configured to audit modifications to the systems network configuration.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000182;

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
    $self->{VULN_ID} = 'V-38540';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-999999';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50341r4_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000182';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The audit system must be configured to audit modifications to the systems network configuration.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The network environment should not be modified by anything other than administrator action. Any change to network parameters should be audited.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If you are running x86_64 architecture, determine the values for sethostname:

$ uname -m; ausyscall i386 sethostname; ausyscall x86_64 sethostname



If the values returned are not identical verify that the system is configured to monitor network configuration changes for the i386 and x86_64 architectures:



$ sudo egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules



-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_network_modifications

-w /etc/issue -p wa -k audit_network_modifications

-w /etc/issue.net -p wa -k audit_network_modifications

-w /etc/hosts -p wa -k audit_network_modifications

-w /etc/sysconfig/network -p wa -k audit_network_modifications



-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications

-w /etc/issue -p wa -k audit_network_modifications

-w /etc/issue.net -p wa -k audit_network_modifications

-w /etc/hosts -p wa -k audit_network_modifications

-w /etc/sysconfig/network -p wa -k audit_network_modifications



If the system is configured to watch for network configuration changes, a line should be returned for each file specified for both (and ""-p wa"" should be indicated for each).



If the system is not configured to audit changes of the network configuration, this is a finding.


CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Add the following to ""/etc/audit/audit.rules"", setting ARCH to either b32 or b64 as appropriate for your system:



# audit_network_modifications

-a always,exit -F arch=ARCH -S sethostname -S setdomainname -k audit_network_modifications

-w /etc/issue -p wa -k audit_network_modifications

-w /etc/issue.net -p wa -k audit_network_modifications

-w /etc/hosts -p wa -k audit_network_modifications

-w /etc/sysconfig/network -p wa -k audit_network_modifications
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
