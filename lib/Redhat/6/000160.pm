# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000160
#
# VULN ID
#   V-38633
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50434r1_rule
#
# STIG ID
#   RHEL-06-000160
#
# RULE TITLE
#   The system must set a maximum audit log file size.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000160;

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
    return 'V-38633';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50434r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000160';
}

sub get_rule_title {
    return 'The system must set a maximum audit log file size.';
}

sub get_discussion {
    return <<'DISCUSSION';
The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect ""/etc/audit/auditd.conf"" and locate the following line to determine how much data the system will retain in each audit log file: ""# grep max_log_file /etc/audit/auditd.conf""



max_log_file = 6





If the system audit data threshold hasn't been properly set up, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Determine the amount of audit data (in megabytes) which should be retained in each log file. Edit the file ""/etc/audit/auditd.conf"". Add or modify the following line, substituting the correct value for [STOREMB]:



max_log_file = [STOREMB]



Set the value to ""6"" (MB) or higher for general-purpose systems. Larger values, of course, support retention of even more audit data.
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
