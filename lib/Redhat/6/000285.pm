# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000285
#
# VULN ID
#   V-38667
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000196
#
# RULE ID
#   SV-50468r3_rule
#
# STIG ID
#   RHEL-06-000285
#
# RULE TITLE
#   The system must have a host-based intrusion detection tool installed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000285;

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
    return 'V-38667';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000196';
}

sub get_rule_id {
    return 'SV-50468r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000285';
}

sub get_rule_title {
    return
        'The system must have a host-based intrusion detection tool installed.';
}

sub get_discussion {
    return <<'DISCUSSION';
Adding host-based intrusion detection tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of system, which may not otherwise exist in an organization's systems management regime.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Ask the SA or ISSO if a host-based intrusion detection application is loaded on the system. Per OPORD 16-0080 the preferred intrusion detection system is McAfee HBSS available through Cybercom.



If another host-based intrusion detection application is in use, such as SELinux, this must be documented and approved by the local Authorizing Official.



Procedure:

Examine the system to see if the Host Intrusion Prevention System (HIPS) is installed:



# rpm -qa | grep MFEhiplsm



Verify that the McAfee HIPS module is active on the system:



# ps -ef | grep -i ""hipclient""



If the MFEhiplsm package is not installed, check for another intrusion detection system:



# find / -name <daemon name>



Where <daemon name> is the name of the primary application daemon to determine if the application is loaded on the system.



Determine if the application is active on the system:



# ps -ef | grep -i <daemon name>



If the MFEhiplsm package is not installed and an alternate host-based intrusion detection application has not been documented for use, this is a finding.



If no host-based intrusion detection system is installed and running on the system, this is a finding.


CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Install and enable the latest McAfee HIPS package, available from Cybercom.



If the system does not support the McAfee HIPS package, install and enable a supported intrusion detection system application and document its use with the Authorizing Official.


FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001263

The information system provides near real-time alerts when any of the  organization defined list of compromise or potential compromise indicators occurs.

NIST SP 800-53 :: SI-4 (5)

NIST SP 800-53A :: SI-4 (5).1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
