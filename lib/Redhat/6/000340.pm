# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000340
#
# VULN ID
#   V-38660
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50461r1_rule
#
# STIG ID
#   RHEL-06-000340
#
# RULE TITLE
#   The snmpd service must use only SNMP protocol version 3 or newer.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000340;

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
    return 'V-38660';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50461r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000340';
}

sub get_rule_title {
    return
        'The snmpd service must use only SNMP protocol version 3 or newer.';
}

sub get_discussion {
    return <<'DISCUSSION';
Earlier versions of SNMP are considered insecure, as they potentially allow unauthorized access to detailed system management information.


DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To ensure only SNMPv3 or newer is used, run the following command:



# grep 'v1\|v2c\|com2sec' /etc/snmp/snmpd.conf | grep -v '^#'



There should be no output.

If there is output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Edit ""/etc/snmp/snmpd.conf"", removing any references to ""v1"", ""v2c"", or ""com2sec"". Upon doing that, restart the SNMP service:



# service snmpd restart
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
