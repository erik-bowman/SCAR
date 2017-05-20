# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000270
#
# VULN ID
#   V-38654
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50455r2_rule
#
# STIG ID
#   RHEL-06-000270
#
# RULE TITLE
#   Remote file systems must be mounted with the nosuid option.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000270;

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
    return 'V-38654';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50455r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000270';
}

sub get_rule_title {
    return 'Remote file systems must be mounted with the nosuid option.';
}

sub get_discussion {
    return <<'DISCUSSION';
NFS mounts should not present suid binaries to users. Only vendor-supplied suid executables should be installed to their default location on the local filesystem.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify the ""nosuid"" option is configured for all NFS mounts, run the following command:



$ mount | grep nfs



All NFS mounts should show the ""nosuid"" setting in parentheses, along with other mount options.

If the setting does not show, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Add the ""nosuid"" option to the fourth column of ""/etc/fstab"" for the line which controls mounting of any NFS mounts.
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
