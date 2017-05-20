# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030870
#
# VULN ID
#   V-72197
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000004-GPOS-00004
#
# RULE ID
#   SV-86821r3_rule
#
# STIG ID
#   RHEL-07-030870
#
# RULE TITLE
#   The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030870;

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
    return 'V-72197';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000004-GPOS-00004';
}

sub get_rule_id {
    return 'SV-86821r3_rule';
}

sub get_stig_id {
    return 'RHEL-07-030870';
}

sub get_rule_title {
    return
        'The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.';
}

sub get_discussion {
    return <<'DISCUSSION';
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.



Audit records can be generated from various components within the information system (e.g., module or policy filter).



Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000476-GPOS-00221
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect ""/etc/passwd"".



Check the auditing rules in ""/etc/audit/audit.rules"" with the following command:



# grep /etc/passwd /etc/audit/audit.rules



-w /etc/passwd -p wa -k audit_rules_usergroup_modification



If the command does not return a line, or the line is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to generate audit records for all account creations, modifications, disabling, and termination events that affect ""/etc/passwd"".



Add or update the following rule ""/etc/audit/rules.d/audit.rules"":



-w /etc/passwd -p wa -k identity



The audit daemon must be restarted for the changes to take effect.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000018

The information system automatically audits account creation actions.

NIST SP 800-53 :: AC-2 (4)

NIST SP 800-53A :: AC-2 (4).1 (i&ii)

NIST SP 800-53 Revision 4 :: AC-2 (4)



CCI-000172

The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.

NIST SP 800-53 :: AU-12 c

NIST SP 800-53A :: AU-12.1 (iv)

NIST SP 800-53 Revision 4 :: AU-12 c



CCI-001403

The information system automatically audits account modification actions.

NIST SP 800-53 :: AC-2 (4)

NIST SP 800-53A :: AC-2 (4).1 (i&ii)

NIST SP 800-53 Revision 4 :: AC-2 (4)



CCI-002130

The information system automatically audits account enabling actions.

NIST SP 800-53 Revision 4 :: AC-2 (4)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__