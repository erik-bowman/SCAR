# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040360
#
# VULN ID
#   V-72245
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86869r2_rule
#
# STIG ID
#   RHEL-07-040360
#
# RULE TITLE
#   The system must display the date and time of the last successful account logon upon an SSH logon.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040360;

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
    return 'V-72245';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86869r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040360';
}

sub get_rule_title {
    return
        'The system must display the date and time of the last successful account logon upon an SSH logon.';
}

sub get_discussion {
    return <<'DISCUSSION';
Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition and reporting of unauthorized account use.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify SSH provides users with feedback on when account accesses last occurred.



Check that ""PrintLastLog"" keyword in the sshd daemon configuration file is used and set to ""yes"" with the following command:



# grep -i printlastlog /etc/ssh/sshd_config

PrintLastLog yes



If the ""PrintLastLog"" keyword is set to ""no"", is missing, or is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure SSH to provide users with feedback on when account accesses last occurred by setting the required configuration options in ""/etc/pam.d/sshd"" or in the ""sshd_config"" file used by the system (""/etc/ssh/sshd_config"" will be used in the example) (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).



Add the following line to the top of ""/etc/pam.d/sshd"":



session     required      pam_lastlog.so showfailed



Or modify the ""PrintLastLog"" line in ""/etc/ssh/sshd_config"" to match the following:



PrintLastLog yes



The SSH service must be restarted for changes to ""sshd_config"" to take effect.
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
