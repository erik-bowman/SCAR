# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000267
#
# VULN ID
#   V-38648
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50449r2_rule
#
# STIG ID
#   RHEL-06-000267
#
# RULE TITLE
#   The qpidd service must not be running.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000267;

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
    return 'V-38648';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000096';
}

sub get_rule_id {
    return 'SV-50449r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000267';
}

sub get_rule_title {
    return 'The qpidd service must not be running.';
}

sub get_discussion {
    return <<'DISCUSSION';
The qpidd service is automatically installed when the ""base"" package selection is selected during installation. The qpidd service listens for network connections which increases the attack surface of the system. If the system is not intended to receive AMQP traffic then the ""qpidd"" service is not needed and should be disabled or removed.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check that the ""qpidd"" service is disabled in system boot configuration, run the following command:



# chkconfig ""qpidd"" --list



Output should indicate the ""qpidd"" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:



# chkconfig ""qpidd"" --list

""qpidd"" 0:off 1:off 2:off 3:off 4:off 5:off 6:off



Run the following command to verify ""qpidd"" is disabled through current runtime configuration:



# service qpidd status



If the service is disabled the command will return the following output:



qpidd is stopped





If the service is running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""qpidd"" service provides high speed, secure, guaranteed delivery services. It is an implementation of the Advanced Message Queuing Protocol. By default the qpidd service will bind to port 5672 and listen for connection attempts. The ""qpidd"" service can be disabled with the following commands:



# chkconfig qpidd off

# service qpidd stop
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000382

The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.

NIST SP 800-53 :: CM-7

NIST SP 800-53A :: CM-7.1 (iii)

NIST SP 800-53 Revision 4 :: CM-7 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
