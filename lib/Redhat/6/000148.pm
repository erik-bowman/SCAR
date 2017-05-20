# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000148
#
# VULN ID
#   V-38631
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000032
#
# RULE ID
#   SV-50432r2_rule
#
# STIG ID
#   RHEL-06-000148
#
# RULE TITLE
#   The operating system must employ automated mechanisms to facilitate the monitoring and control of remote access methods.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000148;

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
    return 'V-38631';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000032';
}

sub get_rule_id {
    return 'SV-50432r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000148';
}

sub get_rule_title {
    return
        'The operating system must employ automated mechanisms to facilitate the monitoring and control of remote access methods.';
}

sub get_discussion {
    return <<'DISCUSSION';
Ensuring the ""auditd"" service is active ensures audit records generated by the kernel can be written to disk, or that appropriate actions will be taken if other obstacles exist.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to determine the current status of the ""auditd"" service:



# service auditd status



If the service is enabled, it should return the following:



auditd is running...





If the service is not running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""auditd"" service is an essential userspace component of the Linux Auditing System, as it is responsible for writing audit records to disk. The ""auditd"" service can be enabled with the following commands:



# chkconfig auditd on

# service auditd start
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000067

The information system monitors remote access methods.

NIST SP 800-53 :: AC-17 (1)

NIST SP 800-53A :: AC-17 (1).1

NIST SP 800-53 Revision 4 :: AC-17 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
