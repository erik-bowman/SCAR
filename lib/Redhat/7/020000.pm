# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020000
#
# VULN ID
#   V-71967
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000095-GPOS-00049
#
# RULE ID
#   SV-86591r1_rule
#
# STIG ID
#   RHEL-07-020000
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

package Redhat::7::020000;

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
    return 'V-71967';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000095-GPOS-00049';
}

sub get_rule_id {
    return 'SV-86591r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020000';
}

sub get_rule_title {
    return 'The rsh-server package must not be installed.';
}

sub get_discussion {
    return <<'DISCUSSION';
It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.



Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).



The rsh-server service provides an unencrypted remote access service that does not provide for the confidentiality and integrity of user passwords or the remote session and has very weak authentication.



If a privileged user were to log on using this service, the privileged user password could be compromised.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Check to see if the rsh-server package is installed with the following command:



# yum list installed rsh-server



If the rsh-server package is installed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to disable non-essential capabilities by removing the rsh-server package from the system with the following command:



# yum remove rsh-server
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
