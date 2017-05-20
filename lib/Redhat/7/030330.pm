# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030330
#
# VULN ID
#   V-72089
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000343-GPOS-00134
#
# RULE ID
#   SV-86713r1_rule
#
# STIG ID
#   RHEL-07-030330
#
# RULE TITLE
#   The operating system must immediately notify the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030330;

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
    return 'V-72089';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000343-GPOS-00134';
}

sub get_rule_id {
    return 'SV-86713r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-030330';
}

sub get_rule_title {
    return
        'The operating system must immediately notify the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.';
}

sub get_discussion {
    return <<'DISCUSSION';
If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system immediately notifies the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.



Check the system configuration to determine the partition the audit records are being written to with the following command:



# grep log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log



Check the size of the partition that audit records are written to (with the example being ""/var/log/audit/""):



# df -h /var/log/audit/

0.9G /var/log/audit



If the audit records are not being written to a partition specifically created for audit records (in this example ""/var/log/audit"" is a separate partition), determine the amount of space other files in the partition are currently occupying with the following command:



# du -sh <partition>

1.8G /var



Determine what the threshold is for the system to take action when 75 percent of the repository maximum audit record storage capacity is reached:



# grep -i space_left /etc/audit/auditd.conf

space_left = 225



If the value of the ""space_left"" keyword is not set to 25 percent of the total partition size, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to immediately notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.



Check the system configuration to determine the partition the audit records are being written to:



# grep log_file /etc/audit/auditd.conf



Determine the size of the partition that audit records are written to (with the example being ""/var/log/audit/""):



# df -h /var/log/audit/



Set the value of the ""space_left"" keyword in ""/etc/audit/auditd.conf"" to 75 percent of the partition size.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001855

The information system provides a warning to organization-defined personnel, roles, and/or locations within organization-defined time period when allocated audit record storage volume reaches organization-defined percentage of repository maximum audit record storage capacity.

NIST SP 800-53 Revision 4 :: AU-5 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
