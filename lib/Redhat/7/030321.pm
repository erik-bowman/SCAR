# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030321
#
# VULN ID
#   V-73163
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000342-GPOS-00133
#
# RULE ID
#   SV-87815r2_rule
#
# STIG ID
#   RHEL-07-030321
#
# RULE TITLE
#   The audit system must take appropriate action when there is an error sending audit records to a remote system.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030321;

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
    return 'V-73163';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000342-GPOS-00133';
}

sub get_rule_id {
    return 'SV-87815r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-030321';
}

sub get_rule_title {
    return
        'The audit system must take appropriate action when there is an error sending audit records to a remote system.';
}

sub get_discussion {
    return <<'DISCUSSION';
Taking appropriate action when there is an error sending audit records to a remote system will minimize the possibility of losing audit records.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the action the operating system takes if there is an error sending audit records to a remote system.



Check the action that takes place if there is an error sending audit records to a remote system with the following command:



# grep -i network_failure_action /etc/audisp/audisp-remote.conf

network_failure_action = stop



If the value of the ""network_failure_action"" option is not ""syslog"", ""single"", or ""halt"", or the line is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the action the operating system takes if there is an error sending audit records to a remote system.



Uncomment the ""network_failure_action"" option in ""/etc/audisp/audisp-remote.conf"" and set it to ""syslog"", ""single"", or ""halt"".



network_failure_action = single
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001851

The information system off-loads audit records per organization-defined frequency onto a different system or media than the system being audited.

NIST SP 800-53 Revision 4 :: AU-4 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
