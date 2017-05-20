# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000165
#
# VULN ID
#   V-38635
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000062
#
# RULE ID
#   SV-50436r3_rule
#
# STIG ID
#   RHEL-06-000165
#
# RULE TITLE
#   The audit system must be configured to audit all attempts to alter system time through adjtimex.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000165;

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
    return 'V-38635';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000062';
}

sub get_rule_id {
    return 'SV-50436r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000165';
}

sub get_rule_title {
    return
        'The audit system must be configured to audit all attempts to alter system time through adjtimex.';
}

sub get_discussion {
    return <<'DISCUSSION';
Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine if the system is configured to audit calls to the ""adjtimex"" system call, run the following command:



$ sudo grep -w ""adjtimex"" /etc/audit/audit.rules



If the system is configured to audit this activity, it will return a line.



If the system is not configured to audit time changes, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
On a 32-bit system, add the following to ""/etc/audit/audit.rules"":



# audit_time_rules

-a always,exit -F arch=b32 -S adjtimex -k audit_time_rules



On a 64-bit system, add the following to ""/etc/audit/audit.rules"":



# audit_time_rules

-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules



The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls:



-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000169

The information system provides audit record generation capability for the auditable events defined in AU-2 a at organization-defined information system components.

NIST SP 800-53 :: AU-12 a

NIST SP 800-53A :: AU-12.1 (ii)

NIST SP 800-53 Revision 4 :: AU-12 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
