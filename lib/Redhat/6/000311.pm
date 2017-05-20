# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000311
#
# VULN ID
#   V-38678
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000048
#
# RULE ID
#   SV-50479r2_rule
#
# STIG ID
#   RHEL-06-000311
#
# RULE TITLE
#   The audit system must provide a warning when allocated audit record storage volume reaches a documented percentage of maximum audit record storage capacity.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000311;

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
    return 'V-38678';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000048';
}

sub get_rule_id {
    return 'SV-50479r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000311';
}

sub get_rule_title {
    return
        'The audit system must provide a warning when allocated audit record storage volume reaches a documented percentage of maximum audit record storage capacity.';
}

sub get_discussion {
    return <<'DISCUSSION';
Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect ""/etc/audit/auditd.conf"" and locate the following line to determine whether the system is configured to email the administrator when disk space is starting to run low:



# grep space_left /etc/audit/auditd.conf



space_left = [num_megabytes]





If the ""num_megabytes"" value does not correspond to a documented value for remaining audit partition capacity or if there is no locally documented value for remaining audit partition capacity, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""auditd"" service can be configured to take an action when disk space starts to run low. Edit the file ""/etc/audit/auditd.conf"". Modify the following line, substituting [num_megabytes] appropriately:



space_left = [num_megabytes]



The ""num_megabytes"" value should be set to a fraction of the total audit storage capacity available that will allow a system administrator to be notified with enough time to respond to the situation causing the capacity issues.  This value must also be documented locally.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000143

The information system provides a warning when allocated audit record storage volume reaches an organization defined percentage of maximum audit record storage capacity.

NIST SP 800-53 :: AU-5 (1)

NIST SP 800-53A :: AU-5 (1).1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
