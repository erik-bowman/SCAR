# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000138
#
# VULN ID
#   V-38624
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50425r1_rule
#
# STIG ID
#   RHEL-06-000138
#
# RULE TITLE
#   System logs must be rotated daily.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000138;

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
    return 'V-38624';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50425r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000138';
}

sub get_rule_title {
    return 'System logs must be rotated daily.';
}

sub get_discussion {
    return <<'DISCUSSION';
Log files that are not properly rotated run the risk of growing so large that they fill up the /var/log partition. Valuable logging information could be lost if the /var/log partition becomes full.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following commands to determine the current status of the ""logrotate"" service:



# grep logrotate /var/log/cron*



If the logrotate service is not run on a daily basis by cron, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""logrotate"" service should be installed or reinstalled if it is not installed and operating properly, by running the following command:



# yum reinstall logrotate
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
