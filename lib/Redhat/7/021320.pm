# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021320
#
# VULN ID
#   V-72061
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86685r1_rule
#
# STIG ID
#   RHEL-07-021320
#
# RULE TITLE
#   The system must use a separate file system for /var.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::021320;

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
    return 'V-72061';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86685r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-021320';
}

sub get_rule_title {
    return 'The system must use a separate file system for /var.';
}

sub get_discussion {
    return <<'DISCUSSION';
The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that a separate file system/partition has been created for ""/var"".



Check that a file system/partition has been created for ""/var"" with the following command:



# grep /var /etc/fstab

UUID=c274f65f    /var                    ext4    noatime,nobarrier        1 2



If a separate entry for ""/var"" is not in use, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Migrate the ""/var"" path onto a separate file system.
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
