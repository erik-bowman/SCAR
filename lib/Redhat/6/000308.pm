# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000308
#
# VULN ID
#   V-38675
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50476r2_rule
#
# STIG ID
#   RHEL-06-000308
#
# RULE TITLE
#   Process core dumps must be disabled unless needed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000308;

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
    return 'V-38675';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50476r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000308';
}

sub get_rule_title {
    return 'Process core dumps must be disabled unless needed.';
}

sub get_discussion {
    return <<'DISCUSSION';
A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify that core dumps are disabled for all users, run the following command:



$ grep core /etc/security/limits.conf /etc/security/limits.d/*.conf



The output should be:



* hard core 0



If it is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To disable core dumps for all users, add the following line to ""/etc/security/limits.conf"":



* hard core 0
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
