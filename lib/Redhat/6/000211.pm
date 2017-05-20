# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000211
#
# VULN ID
#   V-38589
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000129
#
# RULE ID
#   SV-50390r2_rule
#
# STIG ID
#   RHEL-06-000211
#
# RULE TITLE
#   The telnet daemon must not be running.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000211;

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
    return 'V-38589';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000129';
}

sub get_rule_id {
    return 'SV-50390r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000211';
}

sub get_rule_title {
    return 'The telnet daemon must not be running.';
}

sub get_discussion {
    return <<'DISCUSSION';
The telnet protocol uses unencrypted network communication, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network. The telnet protocol is also subject to man-in-the-middle attacks.



Mitigation:  If an enabled telnet daemon is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check that the ""telnet"" service is disabled in system boot configuration, run the following command:



# chkconfig ""telnet"" --list



Output should indicate the ""telnet"" service has either not been installed, or has been disabled, as shown in the example below:



# chkconfig ""telnet"" --list

telnet         off

OR

error reading information on service telnet: No such file or directory





If the service is running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""telnet"" service can be disabled with the following command:



# chkconfig telnet off
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000888

The organization employs cryptographic mechanisms to protect the integrity and confidentiality of non-local maintenance and diagnostic communications.

NIST SP 800-53 :: MA-4 (6)

NIST SP 800-53A :: MA-4 (6).1




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
