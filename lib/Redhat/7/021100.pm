# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021100
#
# VULN ID
#   V-72051
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86675r1_rule
#
# STIG ID
#   RHEL-07-021100
#
# RULE TITLE
#   Cron logging must be implemented.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::021100;

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
    return 'V-72051';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86675r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-021100';
}

sub get_rule_title {
    return 'Cron logging must be implemented.';
}

sub get_discussion {
    return <<'DISCUSSION';
Cron logging can be used to trace the successful or unsuccessful execution of cron jobs. It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that ""rsyslog"" is configured to log cron events.



Check the configuration of ""/etc/rsyslog.conf"" for the cron facility with the following command:



Note: If another logging package is used, substitute the utility configuration file for ""/etc/rsyslog.conf"".



# grep cron /etc/rsyslog.conf

cron.* /var/log/cron.log



If the command does not return a response, check for cron logging all facilities by inspecting the ""/etc/rsyslog.conf"" file:



# more /etc/rsyslog.conf



Look for the following entry:



*.* /var/log/messages



If ""rsyslog"" is not logging messages for the cron facility or all facilities, this is a finding.



If the entry is in the ""/etc/rsyslog.conf"" file but is after the entry ""*.*"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure ""rsyslog"" to log all cron messages by adding or updating the following line to ""/etc/rsyslog.conf"":



cron.* /var/log/cron.log



Note: The line must be added before the following entry if it exists in ""/etc/rsyslog.conf"":



*.* ~ # discards everything
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
