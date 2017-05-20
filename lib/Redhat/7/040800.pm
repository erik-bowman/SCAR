# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040800
#
# VULN ID
#   V-72313
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86937r1_rule
#
# STIG ID
#   RHEL-07-040800
#
# RULE TITLE
#   SNMP community strings must be changed from the default.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040800;

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
    return 'V-72313';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86937r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040800';
}

sub get_rule_title {
    return 'SNMP community strings must be changed from the default.';
}

sub get_discussion {
    return <<'DISCUSSION';
Whether active or not, default Simple Network Management Protocol (SNMP) community strings must be changed to maintain security. If the service is running with the default authenticators, anyone can gather data about the system and the network and use the information to potentially compromise the integrity of the system or network(s). It is highly recommended that SNMP version 3 user authentication and message encryption be used in place of the version 2 community strings.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that a system using SNMP is not using default community strings.



Check to see if the ""/etc/snmp/snmpd.conf"" file exists with the following command:



# ls -al /etc/snmp/snmpd.conf

 -rw-------   1 root root      52640 Mar 12 11:08 snmpd.conf



If the file does not exist, this is Not Applicable.



If the file does exist, check for the default community strings with the following commands:



# grep public /etc/snmp/snmpd.conf

# grep private /etc/snmp/snmpd.conf



If either of these commands returns any output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
If the ""/etc/snmp/snmpd.conf"" file exists, modify any lines that contain a community string value of ""public"" or ""private"" to another string value.
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
