# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000206
#
# VULN ID
#   V-38587
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000095
#
# RULE ID
#   SV-50388r1_rule
#
# STIG ID
#   RHEL-06-000206
#
# RULE TITLE
#   The telnet-server package must not be installed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000206;

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
    return 'V-38587';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000095';
}

sub get_rule_id {
    return 'SV-50388r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000206';
}

sub get_rule_title {
    return 'The telnet-server package must not be installed.';
}

sub get_discussion {
    return <<'DISCUSSION';
Removing the ""telnet-server"" package decreases the risk of the unencrypted telnet service's accidental (or intentional) activation.



Mitigation:  If the telnet-server package is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to determine if the ""telnet-server"" package is installed:



# rpm -q telnet-server





If the package is installed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""telnet-server"" package can be uninstalled with the following command:



# yum erase telnet-server
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000381

The organization configures the information system to provide only essential capabilities.

NIST SP 800-53 :: CM-7

NIST SP 800-53A :: CM-7.1 (ii)

NIST SP 800-53 Revision 4 :: CM-7 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
