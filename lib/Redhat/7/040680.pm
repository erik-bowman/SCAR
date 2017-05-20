# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040680
#
# VULN ID
#   V-72297
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86921r2_rule
#
# STIG ID
#   RHEL-07-040680
#
# RULE TITLE
#   The system must be configured to prevent unrestricted mail relaying.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040680;

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
    return 'V-72297';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86921r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040680';
}

sub get_rule_title {
    return
        'The system must be configured to prevent unrestricted mail relaying.';
}

sub get_discussion {
    return <<'DISCUSSION';
If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay for the purpose of sending spam or other unauthorized activity.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the system is configured to prevent unrestricted mail relaying.



Determine if ""postfix"" is installed with the following commands:



# yum list installed postfix

postfix-2.6.6-6.el7.x86_64.rpm



If postfix is not installed, this is Not Applicable.



If postfix is installed, determine if it is configured to reject connections from unknown or untrusted networks with the following command:



# postconf -n smtpd_client_restrictions

smtpd_client_restrictions = permit_mynetworks, reject



If the ""smtpd_client_restrictions"" parameter contains any entries other than ""permit_mynetworks"" and ""reject"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
If ""postfix"" is installed, modify the ""/etc/postfix/main.cf"" file to restrict client connections to the local network with the following command:



# postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject'
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
