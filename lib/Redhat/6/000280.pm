# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000280
#
# VULN ID
#   V-38665
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000258
#
# RULE ID
#   SV-50466r1_rule
#
# STIG ID
#   RHEL-06-000280
#
# RULE TITLE
#   The system package management tool must verify group-ownership on all files and directories associated with the audit package.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000280;

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
    return 'V-38665';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000258';
}

sub get_rule_id {
    return 'SV-50466r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000280';
}

sub get_rule_title {
    return
        'The system package management tool must verify group-ownership on all files and directories associated with the audit package.';
}

sub get_discussion {
    return <<'DISCUSSION';
Group-ownership of audit binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The group-ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
The following command will list which audit files on the system have group-ownership different from what is expected by the RPM database:



# rpm -V audit | grep '^......G'





If there is output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The RPM package management system can restore file group-ownership of the audit package files and directories. The following command will update audit files with group-ownership different from what is expected by the RPM database:



# rpm --setugids audit
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001495

The information system protects audit tools from unauthorized deletion.

NIST SP 800-53 :: AU-9

NIST SP 800-53A :: AU-9.1

NIST SP 800-53 Revision 4 :: AU-9




CCI
}

# ------------------------------------------------------------------------------

1;

__END__