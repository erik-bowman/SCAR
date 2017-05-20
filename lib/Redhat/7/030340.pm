# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030340
#
# VULN ID
#   V-72091
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000343-GPOS-00134
#
# RULE ID
#   SV-86715r1_rule
#
# STIG ID
#   RHEL-07-030340
#
# RULE TITLE
#   The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030340;

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
    return 'V-72091';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000343-GPOS-00134';
}

sub get_rule_id {
    return 'SV-86715r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-030340';
}

sub get_rule_title {
    return
        'The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached.';
}

sub get_discussion {
    return <<'DISCUSSION';
If security personnel are not notified immediately when the threshold for the repository maximum audit record storage capacity is reached, they are unable to expand the audit record storage capacity before records are lost.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system immediately notifies the SA and ISSO (at a minimum) via email when the allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.



Check what action the operating system takes when the threshold for the repository maximum audit record storage capacity is reached with the following command:



# grep -i space_left_action  /etc/audit/auditd.conf

space_left_action = email



If the value of the ""space_left_action"" keyword is not set to ""email"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to immediately notify the SA and ISSO (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.



Uncomment or edit the ""space_left_action"" keyword in ""/etc/audit/auditd.conf"" and set it to ""email"".



space_left_action = email
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
