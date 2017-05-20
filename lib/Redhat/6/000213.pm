# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000213
#
# VULN ID
#   V-38591
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000095
#
# RULE ID
#   SV-50392r1_rule
#
# STIG ID
#   RHEL-06-000213
#
# RULE TITLE
#   The rsh-server package must not be installed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000213;

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
    return 'V-38591';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000095';
}

sub get_rule_id {
    return 'SV-50392r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000213';
}

sub get_rule_title {
    return 'The rsh-server package must not be installed.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ""rsh-server"" package provides several obsolete and insecure network services. Removing it decreases the risk of those services' accidental (or intentional) activation.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to determine if the ""rsh-server"" package is installed:



# rpm -q rsh-server





If the package is installed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""rsh-server"" package can be uninstalled with the following command:



# yum erase rsh-server
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000381

The organization configures the information system to provide only essential capabilities.

NIST SP 800-53 :: CM-7

NIST SP 800-53A :: CM-7.1 (ii)

NIST SP 800-53 Revision 4 :: CM-7 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
