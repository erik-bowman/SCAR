# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000240
#
# VULN ID
#   V-38615
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000023
#
# RULE ID
#   SV-50416r1_rule
#
# STIG ID
#   RHEL-06-000240
#
# RULE TITLE
#   The SSH daemon must be configured with the Department of Defense (DoD) login banner.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000240;

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
    return 'V-38615';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000023';
}

sub get_rule_id {
    return 'SV-50416r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000240';
}

sub get_rule_title {
    return
        'The SSH daemon must be configured with the Department of Defense (DoD) login banner.';
}

sub get_discussion {
    return <<'DISCUSSION';
The warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure usage of a banner that does not provide easy attribution.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine how the SSH daemon's ""Banner"" option is set, run the following command:



# grep -i Banner /etc/ssh/sshd_config



If a line indicating /etc/issue is returned, then the required value is set.

If the required value is not set, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To enable the warning banner and ensure it is consistent across the system, add or correct the following line in ""/etc/ssh/sshd_config"":



Banner /etc/issue



Another section contains information on how to create an appropriate system-wide warning banner.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000048

The information system displays an organization-defined system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

NIST SP 800-53 :: AC-8 a

NIST SP 800-53A :: AC-8.1 (ii)

NIST SP 800-53 Revision 4 :: AC-8 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
