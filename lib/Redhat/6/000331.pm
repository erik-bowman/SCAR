# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000331
#
# VULN ID
#   V-38691
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000034
#
# RULE ID
#   SV-50492r2_rule
#
# STIG ID
#   RHEL-06-000331
#
# RULE TITLE
#   The Bluetooth service must be disabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000331;

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
    return 'V-38691';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000034';
}

sub get_rule_id {
    return 'SV-50492r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000331';
}

sub get_rule_title {
    return 'The Bluetooth service must be disabled.';
}

sub get_discussion {
    return <<'DISCUSSION';
Disabling the ""bluetooth"" service prevents the system from attempting connections to Bluetooth devices, which entails some security risk. Nevertheless, variation in this risk decision may be expected due to the utility of Bluetooth connectivity and its limited range.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check that the ""bluetooth"" service is disabled in system boot configuration, run the following command:



# chkconfig ""bluetooth"" --list



Output should indicate the ""bluetooth"" service has either not been installed or has been disabled at all runlevels, as shown in the example below:



# chkconfig ""bluetooth"" --list

""bluetooth"" 0:off 1:off 2:off 3:off 4:off 5:off 6:off





If the service is configured to run, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""bluetooth"" service can be disabled with the following command:



# chkconfig bluetooth off







# service bluetooth stop
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000085

The organization monitors for unauthorized connections of mobile devices to organizational information systems.

NIST SP 800-53 :: AC-19 c

NIST SP 800-53A :: AC-19.1 (iii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
