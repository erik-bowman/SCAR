# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030700
#
# VULN ID
#   V-72163
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000037-GPOS-00015
#
# RULE ID
#   SV-86787r3_rule
#
# STIG ID
#   RHEL-07-030700
#
# RULE TITLE
#   All uses of the sudoers command must be audited.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030700;

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
    return 'V-72163';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000037-GPOS-00015';
}

sub get_rule_id {
    return 'SV-86787r3_rule';
}

sub get_stig_id {
    return 'RHEL-07-030700';
}

sub get_rule_title {
    return 'All uses of the sudoers command must be audited.';
}

sub get_discussion {
    return <<'DISCUSSION';
Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.



At a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.



Satisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system generates audit records when successful/unsuccessful attempts to use the ""sudoer"" command occur.



Check for modification of the following files being audited by performing the following commands to check the file system rules in ""/etc/audit/audit.rules"":



# grep /etc/sudoers /etc/audit/audit.rules



-w /etc/sudoers -p wa -k privileged-actions



# grep /etc/sudoers.d /etc/audit/audit.rules



-w /etc/sudoers.d -p wa -k privileged-actions



If the commands do not return output that does not match the examples, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to generate audit records when successful/unsuccessful attempts to use the ""sudoer"" command occur.



Add or update the following rule in ""/etc/audit/rules.d/audit.rules"":



-w /etc/sudoers -p wa -k privileged-actions



-w /etc/sudoers.d -p wa -k privileged-actions



The audit daemon must be restarted for the changes to take effect.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000130

The information system generates audit records containing information that establishes what type of event occurred.

NIST SP 800-53 :: AU-3

NIST SP 800-53A :: AU-3.1

NIST SP 800-53 Revision 4 :: AU-3



CCI-000135

The information system generates audit records containing the organization-defined additional, more detailed information that is to be included in the audit records.

NIST SP 800-53 :: AU-3 (1)

NIST SP 800-53A :: AU-3 (1).1 (ii)

NIST SP 800-53 Revision 4 :: AU-3 (1)



CCI-000172

The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.

NIST SP 800-53 :: AU-12 c

NIST SP 800-53A :: AU-12.1 (iv)

NIST SP 800-53 Revision 4 :: AU-12 c



CCI-002884

The organization audits nonlocal maintenance and diagnostic sessions' organization-defined audit events.

NIST SP 800-53 Revision 4 :: MA-4 (1) (a)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
