# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000214
#
# VULN ID
#   V-38594
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000033
#
# RULE ID
#   SV-50395r2_rule
#
# STIG ID
#   RHEL-06-000214
#
# RULE TITLE
#   The rshd service must not be running.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000214;

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
    return 'V-38594';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000033';
}

sub get_rule_id {
    return 'SV-50395r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000214';
}

sub get_rule_title {
    return 'The rshd service must not be running.';
}

sub get_discussion {
    return <<'DISCUSSION';
The rsh service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check that the ""rsh"" service is disabled in system boot configuration, run the following command:



# chkconfig ""rsh"" --list



Output should indicate the ""rsh"" service has either not been installed, or has been disabled, as shown in the example below:



# chkconfig ""rsh"" --list

rsh off

OR

error reading information on service rsh: No such file or directory





If the service is running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""rsh"" service, which is available with the ""rsh-server"" package and runs as a service through xinetd, should be disabled. The ""rsh"" service can be disabled with the following command:



# chkconfig rsh off
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000068

The information system implements cryptographic mechanisms to protect the confidentiality of remote access sessions.

NIST SP 800-53 :: AC-17 (2)

NIST SP 800-53A :: AC-17 (2).1

NIST SP 800-53 Revision 4 :: AC-17 (2)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
