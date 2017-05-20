# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021110
#
# VULN ID
#   V-72053
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86677r1_rule
#
# STIG ID
#   RHEL-07-021110
#
# RULE TITLE
#   If the cron.allow file exists it must be owned by root.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::021110;

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
    return 'V-72053';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86677r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-021110';
}

sub get_rule_title {
    return 'If the cron.allow file exists it must be owned by root.';
}

sub get_discussion {
    return <<'DISCUSSION';
If the owner of the ""cron.allow"" file is not set to root, the possibility exists for an unauthorized user to view or to edit sensitive information.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that the ""cron.allow"" file is owned by root.



Check the owner of the ""cron.allow"" file with the following command:



# l s -al /etc/cron.allow

-rw------- 1 root root 6 Mar  5  2011 /etc/cron.allow



If the ""cron.allow"" file exists and has an owner other than root, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Set the owner on the ""/etc/cron.allow"" file to root with the following command:



# chown root /etc/cron.allow
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
