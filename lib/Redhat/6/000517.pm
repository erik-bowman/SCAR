# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000517
#
# VULN ID
#   V-38453
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50253r2_rule
#
# STIG ID
#   RHEL-06-000517
#
# RULE TITLE
#   The system package management tool must verify group-ownership on all files and directories associated with packages.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000517;

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
    return 'V-38453';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50253r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000517';
}

sub get_rule_title {
    return
        'The system package management tool must verify group-ownership on all files and directories associated with packages.';
}

sub get_discussion {
    return <<'DISCUSSION';
Group-ownership of system binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The group-ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
The following command will list which files on the system have group-ownership different from what is expected by the RPM database:



# rpm -Va | grep '^......G'





If any output is produced, verify that the changes were due to STIG application and have been documented with the ISSO.



If any output has not been documented with the ISSO, this is a finding.


CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The RPM package management system can restore group-ownership of the package files and directories. The following command will update files and directories with group-ownership different from what is expected by the RPM database:



# rpm -qf [file or directory name]

# rpm --setugids [package]
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
