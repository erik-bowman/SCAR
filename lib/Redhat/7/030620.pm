# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030620
#
# VULN ID
#   V-72147
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000392-GPOS-00172
#
# RULE ID
#   SV-86771r2_rule
#
# STIG ID
#   RHEL-07-030620
#
# RULE TITLE
#   The operating system must generate audit records for all successful account access events.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030620;

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
    return 'V-72147';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000392-GPOS-00172';
}

sub get_rule_id {
    return 'SV-86771r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-030620';
}

sub get_rule_title {
    return
        'The operating system must generate audit records for all successful account access events.';
}

sub get_discussion {
    return <<'DISCUSSION';
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.



Audit records can be generated from various components within the information system (e.g., module or policy filter).



Satisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000470-GPOS-00214, SRG-OS-000473-GPOS-00218
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system generates audit records when successful account access events occur.



Check the file system rules in ""/etc/audit/audit.rules"" with the following commands:



# grep -i /var/log/lastlog /etc/audit/audit.rules



-w /var/log/lastlog -p wa -k logins



If the command does not return any output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to generate audit records when successful account access events occur.



Add or update the following rule in ""/etc/audit/rules.d/audit.rules"":



-w /var/log/lastlog -p wa -k logins



The audit daemon must be restarted for the changes to take effect.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000126

The organization determines that the organization-defined subset of the auditable events defined in AU-2 are to be audited within the information system.

NIST SP 800-53 :: AU-2 d

NIST SP 800-53A :: AU-2.1 (v)

NIST SP 800-53 Revision 4 :: AU-2 d



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
