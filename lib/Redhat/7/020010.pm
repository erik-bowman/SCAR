# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020010
#
# VULN ID
#   V-71969
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000095-GPOS-00049
#
# RULE ID
#   SV-86593r1_rule
#
# STIG ID
#   RHEL-07-020010
#
# RULE TITLE
#   The ypserv package must not be installed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020010;

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
    return 'V-71969';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000095-GPOS-00049';
}

sub get_rule_id {
    return 'SV-86593r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020010';
}

sub get_rule_title {
    return 'The ypserv package must not be installed.';
}

sub get_discussion {
    return <<'DISCUSSION';
Removing the ""ypserv"" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
The NIS service provides an unencrypted authentication service that does not provide for the confidentiality and integrity of user passwords or the remote session.



Check to see if the ""ypserve"" package is installed with the following command:



# yum list installed ypserv



If the ""ypserv"" package is installed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to disable non-essential capabilities by removing the ""ypserv"" package from the system with the following command:



# yum remove ypserv
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
