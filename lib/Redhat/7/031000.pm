# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::031000
#
# VULN ID
#   V-72209
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86833r1_rule
#
# STIG ID
#   RHEL-07-031000
#
# RULE TITLE
#   The system must send rsyslog output to a log aggregation server.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::031000;

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
    return 'V-72209';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86833r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-031000';
}

sub get_rule_title {
    return 'The system must send rsyslog output to a log aggregation server.';
}

sub get_discussion {
    return <<'DISCUSSION';
Sending rsyslog output to another system ensures that the logs cannot be removed or modified in the event that the system is compromised or has a hardware failure.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify ""rsyslog"" is configured to send all messages to a log aggregation server.



Check the configuration of ""rsyslog"" with the following command:



Note: If another logging package is used, substitute the utility configuration file for ""/etc/rsyslog.conf"".



# grep @ /etc/rsyslog.conf

*.* @@logagg.site.mil



If there are no lines in the ""/etc/rsyslog.conf"" file that contain the ""@"" or ""@@"" symbol(s), and the lines with the correct symbol(s) to send output to another system do not cover all ""rsyslog"" output, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.



If there is no evidence that the audit logs are being sent to another system, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Modify the ""/etc/rsyslog.conf"" file to contain a configuration line to send all ""rsyslog"" output to a log aggregation system:



*.* @@<log aggregation system name>
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
