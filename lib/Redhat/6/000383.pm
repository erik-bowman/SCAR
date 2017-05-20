# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000383
#
# VULN ID
#   V-38498
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000058
#
# RULE ID
#   SV-50299r1_rule
#
# STIG ID
#   RHEL-06-000383
#
# RULE TITLE
#   Audit log files must have mode 0640 or less permissive.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000383;

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
    return 'V-38498';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000058';
}

sub get_rule_id {
    return 'SV-50299r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000383';
}

sub get_rule_title {
    return 'Audit log files must have mode 0640 or less permissive.';
}

sub get_discussion {
    return <<'DISCUSSION';
If users can write to audit logs, audit trails can be modified or destroyed.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to check the mode of the system audit logs:



grep ""^log_file"" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %a:%n



Audit logs must be mode 0640 or less permissive.

If any are more permissive, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Change the mode of the audit log files with the following command:



# chmod 0640 [audit_file]
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000163

The information system protects audit information from unauthorized modification.

NIST SP 800-53 :: AU-9

NIST SP 800-53A :: AU-9.1

NIST SP 800-53 Revision 4 :: AU-9




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
