# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010280
#
# VULN ID
#   V-71935
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000078-GPOS-00046
#
# RULE ID
#   SV-86559r1_rule
#
# STIG ID
#   RHEL-07-010280
#
# RULE TITLE
#   Passwords must be a minimum of 15 characters in length.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010280;

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
    $self->{VULN_ID} = 'V-71935';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000078-GPOS-00046';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86559r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010280';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'Passwords must be a minimum of 15 characters in length.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.



Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system enforces a minimum 15-character password length. The ""minlen"" option sets the minimum number of characters in a new password.



Check for the value of the ""minlen"" option in ""/etc/security/pwquality.conf"" with the following command:



# grep minlen /etc/security/pwquality.conf

minlen = 15



If the command does not return a ""minlen"" value of 15 or greater, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure operating system to enforce a minimum 15-character password length.



Add the following line to ""/etc/security/pwquality.conf"" (or modify the line to have the required value):



minlen = 15
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000205

The information system enforces minimum password length.

NIST SP 800-53 :: IA-5 (1) (a)

NIST SP 800-53A :: IA-5 (1).1 (i)

NIST SP 800-53 Revision 4 :: IA-5 (1) (a)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
