# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040530
#
# VULN ID
#   V-72275
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86899r1_rule
#
# STIG ID
#   RHEL-07-040530
#
# RULE TITLE
#   The system must display the date and time of the last successful account logon upon logon.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040530;

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
    return 'V-72275';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86899r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040530';
}

sub get_rule_title {
    return
        'The system must display the date and time of the last successful account logon upon logon.';
}

sub get_discussion {
    return <<'DISCUSSION';
Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify users are provided with feedback on when account accesses last occurred.



Check that ""pam_lastlog"" is used and not silent with the following command:



# grep pam_lastlog /etc/pam.d/postlogin-ac



session     required      pam_lastlog.so showfailed silent



If ""pam_lastlog"" is missing from ""/etc/pam.d/postlogin-ac"" file, or the silent option is present on the line check for the ""PrintLastLog"" keyword in the sshd daemon configuration file, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to provide users with feedback on when account accesses last occurred by setting the required configuration options in ""/etc/pam.d/postlogin-ac"".



Add the following line to the top of ""/etc/pam.d/postlogin-ac"":



session     required      pam_lastlog.so showfailed
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
