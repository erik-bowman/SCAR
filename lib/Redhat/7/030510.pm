# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030510
#
# VULN ID
#   V-72125
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000064-GPOS-00033
#
# RULE ID
#   SV-86749r2_rule
#
# STIG ID
#   RHEL-07-030510
#
# RULE TITLE
#   All uses of the open command must be audited.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030510;

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
    return 'V-72125';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000064-GPOS-00033';
}

sub get_rule_id {
    return 'SV-86749r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-030510';
}

sub get_rule_title {
    return 'All uses of the open command must be audited.';
}

sub get_discussion {
    return <<'DISCUSSION';
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.



Audit records can be generated from various components within the information system (e.g., module or policy filter).



Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000458-GPOS-00203, SRG-OS-000461-GPOS-00205, SRG-OS-000392-GPOS-00172
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system generates audit records when successful/unsuccessful attempts to use the ""open"" command occur.



Check the file system rules in ""/etc/audit/audit.rules"" with the following commands:



Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.



# grep -i open /etc/audit/audit.rules



-a always,exit -F arch=b32 -S open -Fexit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access



-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access



If the command does not return any output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to generate audit records when successful/unsuccessful attempts to use the ""open"" command occur.



Add or update the following rule in ""/etc/audit/rules.d/audit.rules"" (removing those that do not match the CPU architecture):



-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access



-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access



The audit daemon must be restarted for the changes to take effect.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
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
