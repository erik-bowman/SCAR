# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000522
#
# VULN ID
#   V-38445
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000057
#
# RULE ID
#   SV-50245r2_rule
#
# STIG ID
#   RHEL-06-000522
#
# RULE TITLE
#   Audit log files must be group-owned by root.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000522;

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
    return 'V-38445';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000057';
}

sub get_rule_id {
    return 'SV-50245r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000522';
}

sub get_rule_title {
    return 'Audit log files must be group-owned by root.';
}

sub get_discussion {
    return <<'DISCUSSION';
If non-privileged users can write to audit logs, audit trails can be modified or destroyed.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to check the group owner of the system audit logs:



grep ""^log_file"" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %G:%n



Audit logs must be group-owned by root.

If they are not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Change the group owner of the audit log files with the following command:



# chgrp root [audit_file]
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000162

The information system protects audit information from unauthorized access.

NIST SP 800-53 :: AU-9

NIST SP 800-53A :: AU-9.1

NIST SP 800-53 Revision 4 :: AU-9




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
