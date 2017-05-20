# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000291
#
# VULN ID
#   V-38676
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50477r2_rule
#
# STIG ID
#   RHEL-06-000291
#
# RULE TITLE
#   The xorg-x11-server-common (X Windows) package must not be installed, unless required.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000291;

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
    return 'V-38676';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50477r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000291';
}

sub get_rule_title {
    return
        'The xorg-x11-server-common (X Windows) package must not be installed, unless required.';
}

sub get_discussion {
    return <<'DISCUSSION';
Unnecessary packages should not be installed to decrease the attack surface of the system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To ensure the X Windows package group is removed, run the following command:



$ rpm -qi xorg-x11-server-common



The output should be:



package xorg-x11-server-common is not installed





If it is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Removing all packages which constitute the X Window System ensures users or malicious software cannot start X. To do so, run the following command:



# yum groupremove ""X Window System""
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
