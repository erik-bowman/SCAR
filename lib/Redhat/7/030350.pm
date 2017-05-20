# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030350
#
# VULN ID
#   V-72093
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000343-GPOS-00134
#
# RULE ID
#   SV-86717r2_rule
#
# STIG ID
#   RHEL-07-030350
#
# RULE TITLE
#   The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030350;

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
    return 'V-72093';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000343-GPOS-00134';
}

sub get_rule_id {
    return 'SV-86717r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-030350';
}

sub get_rule_title {
    return
        'The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.';
}

sub get_discussion {
    return <<'DISCUSSION';
If security personnel are not notified immediately when the threshold for the repository maximum audit record storage capacity is reached, they are unable to expand the audit record storage capacity before records are lost.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system immediately notifies the SA and ISSO (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached.



Check what account the operating system emails when the threshold for the repository maximum audit record storage capacity is reached with the following command:



# grep -i action_mail_acct  /etc/audit/auditd.conf

action_mail_acct = root



If the value of the ""action_mail_acct"" keyword is not set to ""root"" and other accounts for security personnel, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to immediately notify the SA and ISSO (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.



Uncomment or edit the ""action_mail_acct"" keyword in ""/etc/audit/auditd.conf"" and set it to root and any other accounts associated with security personnel.



action_mail_acct = root
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
