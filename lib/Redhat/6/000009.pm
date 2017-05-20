# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000009
#
# VULN ID
#   V-38478
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50278r2_rule
#
# STIG ID
#   RHEL-06-000009
#
# RULE TITLE
#   The Red Hat Network Service (rhnsd) service must not be running, unless using RHN or an RHN Satellite.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000009;

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
    return 'V-38478';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000096';
}

sub get_rule_id {
    return 'SV-50278r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000009';
}

sub get_rule_title {
    return
        'The Red Hat Network Service (rhnsd) service must not be running, unless using RHN or an RHN Satellite.';
}

sub get_discussion {
    return <<'DISCUSSION';
Although systems management and patching is extremely important to system security, management by a system outside the enterprise enclave is not desirable for some environments. However, if the system is being managed by RHN or RHN Satellite Server the ""rhnsd"" daemon can remain on.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the system uses RHN or an RHN Satellite, this is not applicable.



To check that the ""rhnsd"" service is disabled in system boot configuration, run the following command:



# chkconfig ""rhnsd"" --list



Output should indicate the ""rhnsd"" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:



# chkconfig ""rhnsd"" --list

""rhnsd"" 0:off 1:off 2:off 3:off 4:off 5:off 6:off



Run the following command to verify ""rhnsd"" is disabled through current runtime configuration:



# service rhnsd status



If the service is disabled the command will return the following output:



rhnsd is stopped





If the service is running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The Red Hat Network service automatically queries Red Hat Network servers to determine whether there are any actions that should be executed, such as package updates. This only occurs if the system was registered to an RHN server or satellite and managed as such. The ""rhnsd"" service can be disabled with the following commands:



# chkconfig rhnsd off

# service rhnsd stop
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
