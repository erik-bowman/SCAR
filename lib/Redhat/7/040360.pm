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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-72245';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00227';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86869r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-040360';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must display the date and time of the last successful account logon upon an SSH logon.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition and reporting of unauthorized account use.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify SSH provides users with feedback on when account accesses last occurred.



Check that ""PrintLastLog"" keyword in the sshd daemon configuration file is used and set to ""yes"" with the following command:



# grep -i printlastlog /etc/ssh/sshd_config

PrintLastLog yes



If the ""PrintLastLog"" keyword is set to ""no"", is missing, or is commented out, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure SSH to provide users with feedback on when account accesses last occurred by setting the required configuration options in ""/etc/pam.d/sshd"" or in the ""sshd_config"" file used by the system (""/etc/ssh/sshd_config"" will be used in the example) (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).



Add the following line to the top of ""/etc/pam.d/sshd"":



session     required      pam_lastlog.so showfailed



Or modify the ""PrintLastLog"" line in ""/etc/ssh/sshd_config"" to match the following:



PrintLastLog yes



The SSH service must be restarted for changes to ""sshd_config"" to take effect.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
