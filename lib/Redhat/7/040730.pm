# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040730
#
# VULN ID
#   V-72307
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86931r2_rule
#
# STIG ID
#   RHEL-07-040730
#
# RULE TITLE
#   An X Windows display manager must not be installed unless approved.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040730;

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
    return 'V-72307';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86931r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040730';
}

sub get_rule_title {
    return
        'An X Windows display manager must not be installed unless approved.';
}

sub get_discussion {
    return <<'DISCUSSION';
Internet services that are not required for system or application processes must not be active to decrease the attack surface of the system. X Windows has a long history of security vulnerabilities and will not be used unless approved and documented.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that if the system has X Windows System installed, it is authorized.



Check for the X11 package with the following command:



# yum group list installed ""X Window System""



Ask the System Administrator if use of the X Windows System is an operational requirement.



If the use of X Windows on the system is not documented with the Information System Security Officer (ISSO), this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Document the requirement for an X Windows server with the ISSO or remove the related packages with the following commands:



#yum groupremove ""X Window System""



#yum remove xorg-x11-server-common
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
