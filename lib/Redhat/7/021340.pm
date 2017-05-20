# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021340
#
# VULN ID
#   V-72065
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86689r1_rule
#
# STIG ID
#   RHEL-07-021340
#
# RULE TITLE
#   The system must use a separate file system for /tmp (or equivalent).
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::021340;

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
    return 'V-72065';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86689r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-021340';
}

sub get_rule_title {
    return
        'The system must use a separate file system for /tmp (or equivalent).';
}

sub get_discussion {
    return <<'DISCUSSION';
The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that a separate file system/partition has been created for ""/tmp"".



Check that a file system/partition has been created for ""/tmp"" with the following command:



# systemctl is-enabled tmp.mount

enabled



If the ""tmp.mount"" service is not enabled, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Start the ""tmp.mount"" service with the following command:



# systemctl enable tmp.mount
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
