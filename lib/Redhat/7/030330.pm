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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-72089';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000343-GPOS-00134';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86713r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-030330';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must immediately notify the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
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
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to immediately notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.



Check the system configuration to determine the partition the audit records are being written to:



# grep log_file /etc/audit/auditd.conf



Determine the size of the partition that audit records are written to (with the example being ""/var/log/audit/""):



# df -h /var/log/audit/



Set the value of the ""space_left"" keyword in ""/etc/audit/auditd.conf"" to 75 percent of the partition size.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001855

The information system provides a warning to organization-defined personnel, roles, and/or locations within organization-defined time period when allocated audit record storage volume reaches organization-defined percentage of repository maximum audit record storage capacity.

NIST SP 800-53 Revision 4 :: AU-5 (1)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
