# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000262
#
# VULN ID
#   V-38641
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50442r3_rule
#
# STIG ID
#   RHEL-06-000262
#
# RULE TITLE
#   The atd service must be disabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000262;

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
    return 'V-38641';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000096';
}

sub get_rule_id {
    return 'SV-50442r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000262';
}

sub get_rule_title {
    return 'The atd service must be disabled.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ""atd"" service could be used by an unsophisticated insider to carry out activities outside of a normal login session, which could complicate accountability. Furthermore, the need to schedule tasks with ""at"" or ""batch"" is not common.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the system requires the use of the ""atd"" service to support an organizational requirement, this is not applicable.



To check that the ""atd"" service is disabled in system boot configuration, run the following command:



# chkconfig ""atd"" --list



Output should indicate the ""atd"" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:



# chkconfig ""atd"" --list

""atd"" 0:off 1:off 2:off 3:off 4:off 5:off 6:off



Run the following command to verify ""atd"" is disabled through current runtime configuration:



# service atd status



If the service is disabled the command will return the following output:



atd is stopped





If the service is running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""at"" and ""batch"" commands can be used to schedule tasks that are meant to be executed only once. This allows delayed execution in a manner similar to cron, except that it is not recurring. The daemon ""atd"" keeps track of tasks scheduled via ""at"" and ""batch"", and executes them at the specified time. The ""atd"" service can be disabled with the following commands:



# chkconfig atd off

# service atd stop
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
