# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000246
#
# VULN ID
#   V-38618
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50419r2_rule
#
# STIG ID
#   RHEL-06-000246
#
# RULE TITLE
#   The avahi service must be disabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000246;

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
    return 'V-38618';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50419r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000246';
}

sub get_rule_title {
    return 'The avahi service must be disabled.';
}

sub get_discussion {
    return <<'DISCUSSION';
Because the Avahi daemon service keeps an open network port, it is subject to network attacks. Its functionality is convenient but is only appropriate if the local network can be trusted.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check that the ""avahi-daemon"" service is disabled in system boot configuration, run the following command:



# chkconfig ""avahi-daemon"" --list



Output should indicate the ""avahi-daemon"" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:



# chkconfig ""avahi-daemon"" --list

""avahi-daemon"" 0:off 1:off 2:off 3:off 4:off 5:off 6:off



Run the following command to verify ""avahi-daemon"" is disabled through current runtime configuration:



# service avahi-daemon status



If the service is disabled the command will return the following output:



avahi-daemon is stopped





If the service is running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""avahi-daemon"" service can be disabled with the following commands:



# chkconfig avahi-daemon off

# service avahi-daemon stop
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
