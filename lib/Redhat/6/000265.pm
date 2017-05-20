# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000265
#
# VULN ID
#   V-38644
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50445r2_rule
#
# STIG ID
#   RHEL-06-000265
#
# RULE TITLE
#   The ntpdate service must not be running.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000265;

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
    return 'V-38644';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000096';
}

sub get_rule_id {
    return 'SV-50445r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000265';
}

sub get_rule_title {
    return 'The ntpdate service must not be running.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ""ntpdate"" service may only be suitable for systems which are rebooted frequently enough that clock drift does not cause problems between reboots. In any event, the functionality of the ntpdate service is now available in the ntpd program and should be considered deprecated.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check that the ""ntpdate"" service is disabled in system boot configuration, run the following command:



# chkconfig ""ntpdate"" --list



Output should indicate the ""ntpdate"" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:



# chkconfig ""ntpdate"" --list

""ntpdate"" 0:off 1:off 2:off 3:off 4:off 5:off 6:off



Run the following command to verify ""ntpdate"" is disabled through current runtime configuration:



# service ntpdate status



If the service is disabled the command will return the following output:



ntpdate is stopped





If the service is running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ntpdate service sets the local hardware clock by polling NTP servers when the system boots. It synchronizes to the NTP servers listed in ""/etc/ntp/step-tickers"" or ""/etc/ntp.conf"" and then sets the local hardware clock to the newly synchronized system time. The ""ntpdate"" service can be disabled with the following commands:



# chkconfig ntpdate off

# service ntpdate stop
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
