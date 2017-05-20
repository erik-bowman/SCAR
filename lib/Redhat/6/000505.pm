# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000505
#
# VULN ID
#   V-38486
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000100
#
# RULE ID
#   SV-50287r1_rule
#
# STIG ID
#   RHEL-06-000505
#
# RULE TITLE
#   The operating system must conduct backups of system-level information contained in the information system per organization defined frequency to conduct backups that are consistent with recovery time and recovery point objectives.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000505;

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
    return 'V-38486';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000100';
}

sub get_rule_id {
    return 'SV-50287r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000505';
}

sub get_rule_title {
    return
        'The operating system must conduct backups of system-level information contained in the information system per organization defined frequency to conduct backups that are consistent with recovery time and recovery point objectives.';
}

sub get_discussion {
    return <<'DISCUSSION';
Operating system backup is a critical step in maintaining data assurance and availability. System-level information includes system-state information, operating system and application software, and licenses. Backups must be consistent with organizational recovery time and recovery point objectives.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Ask an administrator if a process exists to back up OS data from the system, including configuration data.



If such a process does not exist, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Procedures to back up OS data from the system must be established and executed. The Red Hat operating system provides utilities for automating such a process.  Commercial and open-source products are also available.



Implement a process whereby OS data is backed up from the system in accordance with local policies.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000537

The organization conducts backups of system-level information contained in the information system per organization-defined frequency that is consistent with recovery time and recovery point objectives.

NIST SP 800-53 :: CP-9 (b)

NIST SP 800-53A :: CP-9.1 (v)

NIST SP 800-53 Revision 4 :: CP-9 (b)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
