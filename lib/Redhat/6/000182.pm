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
    return 'V-38540';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50341r4_rule';
}

sub get_stig_id {
    return 'RHEL-06-000182';
}

sub get_rule_title {
    return
        'The audit system must be configured to audit modifications to the systems network configuration.';
}

sub get_discussion {
    return <<'DISCUSSION';
The network environment should not be modified by anything other than administrator action. Any change to network parameters should be audited.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
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
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Add the following to ""/etc/audit/audit.rules"", setting ARCH to either b32 or b64 as appropriate for your system:



# audit_network_modifications

-a always,exit -F arch=ARCH -S sethostname -S setdomainname -k audit_network_modifications

-w /etc/issue -p wa -k audit_network_modifications

-w /etc/issue.net -p wa -k audit_network_modifications

-w /etc/hosts -p wa -k audit_network_modifications

-w /etc/sysconfig/network -p wa -k audit_network_modifications
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
