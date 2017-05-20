# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000341
#
# VULN ID
#   V-38653
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50454r1_rule
#
# STIG ID
#   RHEL-06-000341
#
# RULE TITLE
#   The snmpd service must not use a default password.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000341;

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
    return 'V-38653';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50454r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000341';
}

sub get_rule_title {
    return 'The snmpd service must not use a default password.';
}

sub get_discussion {
    return <<'DISCUSSION';
Presence of the default SNMP password enables querying of different system aspects and could result in unauthorized knowledge of the system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To ensure the default password is not set, run the following command:



# grep -v ""^#"" /etc/snmp/snmpd.conf| grep public



There should be no output.

If there is output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Edit ""/etc/snmp/snmpd.conf"", remove default community string ""public"". Upon doing that, restart the SNMP service:



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
