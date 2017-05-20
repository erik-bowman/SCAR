# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040100
#
# VULN ID
#   V-72219
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000096-GPOS-00050
#
# RULE ID
#   SV-86843r1_rule
#
# STIG ID
#   RHEL-07-040100
#
# RULE TITLE
#   The host must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA) and vulnerability assessments.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040100;

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
    return 'V-72219';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000096-GPOS-00050';
}

sub get_rule_id {
    return 'SV-86843r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040100';
}

sub get_rule_title {
    return
        'The host must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA) and vulnerability assessments.';
}

sub get_discussion {
    return <<'DISCUSSION';
In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.



Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.



To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.



Satisfies: SRG-OS-000096-GPOS-00050, SRG-OS-000297-GPOS-00115
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect the firewall configuration and running services to verify that it is configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited.



Check which services are currently active with the following command:



# firewall-cmd --list-all

public (default, active)

  interfaces: enp0s3

  sources:

  services: dhcpv6-client dns http https ldaps rpc-bind ssh

  ports:

  masquerade: no

  forward-ports:

  icmp-blocks:

  rich rules:



Ask the System Administrator for the site or program PPSM CLSA. Verify the services allowed by the firewall match the PPSM CLSA.



If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Update the host's firewall settings and/or running services to comply with the PPSM CLSA for the site or program and the PPSM CAL.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000382

The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.

NIST SP 800-53 :: CM-7

NIST SP 800-53A :: CM-7.1 (iii)

NIST SP 800-53 Revision 4 :: CM-7 b



CCI-002314

The information system controls remote access methods.

NIST SP 800-53 Revision 4 :: AC-17 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
