# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000163
#
# VULN ID
#   V-54381
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-68627r3_rule
#
# STIG ID
#   RHEL-06-000163
#
# RULE TITLE
#   The audit system must switch the system to single-user mode when available audit storage volume becomes dangerously low.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000163;

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
    return 'V-54381';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-68627r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000163';
}

sub get_rule_title {
    return
        'The audit system must switch the system to single-user mode when available audit storage volume becomes dangerously low.';
}

sub get_discussion {
    return <<'DISCUSSION';
Administrators should be made aware of an inability to record audit records. If a separate partition or logical volume of adequate size is used, running low on space for audit records should never occur.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect ""/etc/audit/auditd.conf"" and locate the following line to determine if the system is configured to either suspend, switch to single-user mode, or halt when disk space has run low:



admin_space_left_action = single



If the system is not configured to switch to single-user mode, suspend, or halt for corrective action, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""auditd"" service can be configured to take an action when disk space is running low but prior to running out of space completely. Edit the file ""/etc/audit/auditd.conf"". Add or modify the following line, substituting [ACTION] appropriately:



admin_space_left_action = [ACTION]



Set this value to ""single"" to cause the system to switch to single-user mode for corrective action. Acceptable values also include ""suspend"" and ""halt"". For certain systems, the need for availability outweighs the need to log all actions, and a different setting should be determined. Details regarding all possible values for [ACTION] are described in the ""auditd.conf"" man page.
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
