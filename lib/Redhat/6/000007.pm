# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000007
#
# VULN ID
#   V-38473
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50273r1_rule
#
# STIG ID
#   RHEL-06-000007
#
# RULE TITLE
#   The system must use a separate file system for user home directories.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000007;

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
    if ( defined $self->{parent}->{fstab}->{'/home'} ) {
        $self->_set_finding_status('NF');
    }
    else {
        $self->_set_finding_status('O');
    }
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
    return 'V-38473';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50273r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000007';
}

sub get_rule_title {
    return
        'The system must use a separate file system for user home directories.';
}

sub get_discussion {
    return <<'DISCUSSION';
Ensuring that ""/home"" is mounted on its own partition enables the setting of more restrictive mount options, and also helps ensure that users cannot trivially fill partitions used for log or audit data storage.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to determine if ""/home"" is on its own partition or logical volume:



$ mount | grep ""on /home ""



If ""/home"" has its own partition or volume group, a line will be returned.

If no line is returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
If user home directories will be stored locally, create a separate partition for ""/home"" at installation time (or migrate it later using LVM). If ""/home"" will be mounted from another system such as an NFS server, then creating a separate partition is not necessary at installation time, and the mountpoint can instead be configured later.
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

1;

__END__
