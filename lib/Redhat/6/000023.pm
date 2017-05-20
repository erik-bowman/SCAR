# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000023
#
# VULN ID
#   V-51369
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-65579r1_rule
#
# STIG ID
#   RHEL-06-000023
#
# RULE TITLE
#   The system must use a Linux Security Module configured to limit the privileges of system services.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000023;

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
    return 'V-51369';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-65579r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000023';
}

sub get_rule_title {
    return
        'The system must use a Linux Security Module configured to limit the privileges of system services.';
}

sub get_discussion {
    return <<'DISCUSSION';
Setting the SELinux policy to ""targeted"" or a more specialized policy ensures the system will confine processes that are likely to be targeted for exploitation, such as network or system services.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Check the file ""/etc/selinux/config"" and ensure the following line appears:



SELINUXTYPE=targeted



If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The SELinux ""targeted"" policy is appropriate for general-purpose desktops and servers, as well as systems in many other roles. To configure the system to use this policy, add or correct the following line in ""/etc/selinux/config"":



SELINUXTYPE=targeted



Other policies, such as ""mls"", provide additional security labeling and greater confinement but are not compatible with many general-purpose use cases.
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
