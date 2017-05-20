# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000256
#
# VULN ID
#   V-38627
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50428r2_rule
#
# STIG ID
#   RHEL-06-000256
#
# RULE TITLE
#   The openldap-servers package must not be installed unless required.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000256;

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
    return 'V-38627';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50428r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000256';
}

sub get_rule_title {
    return
        'The openldap-servers package must not be installed unless required.';
}

sub get_discussion {
    return <<'DISCUSSION';
Unnecessary packages should not be installed to decrease the attack surface of the system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify the ""openldap-servers"" package is not installed, run the following command:



$ rpm -q openldap-servers



The output should show the following.



package openldap-servers is not installed





If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""openldap-servers"" package should be removed if not in use.



# yum erase openldap-servers



The openldap-servers RPM is not installed by default on RHEL6 machines. It is needed only by the OpenLDAP server, not by the clients which use LDAP for authentication. If the system is not intended for use as an LDAP Server it should be removed.
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
