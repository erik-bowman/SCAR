# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000247
#
# VULN ID
#   V-38620
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000056
#
# RULE ID
#   SV-50421r1_rule
#
# STIG ID
#   RHEL-06-000247
#
# RULE TITLE
#   The system clock must be synchronized continuously, or at least daily.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000247;

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
    return 'V-38620';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000056';
}

sub get_rule_id {
    return 'SV-50421r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000247';
}

sub get_rule_title {
    return
        'The system clock must be synchronized continuously, or at least daily.';
}

sub get_discussion {
    return <<'DISCUSSION';
Enabling the ""ntpd"" service ensures that the ""ntpd"" service will be running and that the system will synchronize its time to any servers specified. This is important whether the system is configured to be a client (and synchronize only its own clock) or it is also acting as an NTP server to other systems. Synchronizing time is essential for authentication services such as Kerberos, but it is also important for maintaining accurate logs and auditing possible security breaches.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to determine the current status of the ""ntpd"" service:



# service ntpd status



If the service is enabled, it should return the following:



ntpd is running...





If the service is not running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""ntpd"" service can be enabled with the following command:



# chkconfig ntpd on

# service ntpd start
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000160

The information system synchronizes internal information system clocks on an organization defined frequency with an organization defined authoritative time source.

NIST SP 800-53 :: AU-8 (1)

NIST SP 800-53A :: AU-8 (1).1 (iii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
