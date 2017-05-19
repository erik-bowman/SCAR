# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010270
#
# VULN ID
#   V-71933
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000077-GPOS-00045
#
# RULE ID
#   SV-86557r1_rule
#
# STIG ID
#   RHEL-07-010270
#
# RULE TITLE
#   Passwords must be prohibited from reuse for a minimum of five generations.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010270;

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
    $self->{VULN_ID} = 'V-71933';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000077-GPOS-00045';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86557r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010270';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'Passwords must be prohibited from reuse for a minimum of five generations.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system prohibits password reuse for a minimum of five generations.



Check for the value of the ""remember"" argument in ""/etc/pam.d/system-auth-ac"" with the following command:



# grep -i remember /etc/pam.d/system-auth-ac

password sufficient pam_unix.so use_authtok sha512 shadow remember=5



If the line containing the ""pam_unix.so"" line does not have the ""remember"" module argument set, or the value of the ""remember"" module argument is set to less than ""5"", this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to prohibit password reuse for a minimum of five generations.



Add the following line in ""/etc/pam.d/system-auth-ac"" (or modify the line to have the required value):



password sufficient pam_unix.so use_authtok sha512 shadow remember=5



and run the ""authconfig"" command.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000200

The information system prohibits password reuse for the organization defined number of generations.

NIST SP 800-53 :: IA-5 (1) (e)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (e)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
