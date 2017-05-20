# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030920
#
# VULN ID
#   V-72207
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000466-GPOS-00210
#
# RULE ID
#   SV-86831r2_rule
#
# STIG ID
#   RHEL-07-030920
#
# RULE TITLE
#   All uses of the unlinkat command must be audited.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030920;

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
    return 'V-72207';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000466-GPOS-00210';
}

sub get_rule_id {
    return 'SV-86831r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-030920';
}

sub get_rule_title {
    return 'All uses of the unlinkat command must be audited.';
}

sub get_discussion {
    return <<'DISCUSSION';
If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.



Satisfies: SRG-OS-000466-GPOS-00210, SRG-OS-000467-GPOS-00210, SRG-OS-000468-GPOS-00212, SRG-OS-000392-GPOS-00172
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system generates audit records when successful/unsuccessful attempts to use the ""unlinkat"" command occur.



Check the file system rules in ""/etc/audit/audit.rules"" with the following commands:



Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.



# grep -i unlinkat/etc/audit/audit.rules

-a always,exit -F arch=b32 -S unlinkat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete

-a always,exit -F arch=b64 -S unlinkat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete



If the command does not return any output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to generate audit records when successful/unsuccessful attempts to use the ""unlinkat"" command occur.



Add the following rules in ""/etc/audit/rules.d/audit.rules"" (removing those that do not match the CPU architecture):



-a always,exit -F arch=b32 -S unlinkat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete

-a always,exit -F arch=b64 -S unlinkat  -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete



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
