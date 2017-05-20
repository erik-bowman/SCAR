# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000161
#
# VULN ID
#   V-38634
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50435r2_rule
#
# STIG ID
#   RHEL-06-000161
#
# RULE TITLE
#   The system must rotate audit log files that reach the maximum file size.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000161;

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
    return 'V-38634';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50435r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000161';
}

sub get_rule_title {
    return
        'The system must rotate audit log files that reach the maximum file size.';
}

sub get_discussion {
    return <<'DISCUSSION';
Automatically rotating logs (by setting this to ""rotate"") minimizes the chances of the system unexpectedly running out of disk space by being overwhelmed with log data. However, for systems that must never discard log data, or which use external processes to transfer it and reclaim space, ""keep_logs"" can be employed.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect ""/etc/audit/auditd.conf"" and locate the following line to determine if the system is configured to rotate logs when they reach their maximum size:



# grep max_log_file_action /etc/audit/auditd.conf

max_log_file_action = rotate



If the ""keep_logs"" option is configured for the ""max_log_file_action"" line in ""/etc/audit/auditd.conf"" and an alternate process is in place to ensure audit data does not overwhelm local audit storage, this is not a finding.



If the system has not been properly set up to rotate audit logs, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The default action to take when the logs reach their maximum size is to rotate the log files, discarding the oldest one. To configure the action taken by ""auditd"", add or correct the line in ""/etc/audit/auditd.conf"":



max_log_file_action = [ACTION]



Possible values for [ACTION] are described in the ""auditd.conf"" man page. These include:



""ignore""

""syslog""

""suspend""

""rotate""

""keep_logs""





Set the ""[ACTION]"" to ""rotate"" to ensure log rotation occurs. This is the default. The setting is case-insensitive.
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
