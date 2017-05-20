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
    return 'V-71935';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000078-GPOS-00046';
}

sub get_rule_id {
    return 'SV-86559r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010280';
}

sub get_rule_title {
    return 'Passwords must be a minimum of 15 characters in length.';
}

sub get_discussion {
    return <<'DISCUSSION';
The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.



Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system enforces a minimum 15-character password length. The ""minlen"" option sets the minimum number of characters in a new password.



Check for the value of the ""minlen"" option in ""/etc/security/pwquality.conf"" with the following command:



# grep minlen /etc/security/pwquality.conf

minlen = 15



If the command does not return a ""minlen"" value of 15 or greater, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure operating system to enforce a minimum 15-character password length.



Add the following line to ""/etc/security/pwquality.conf"" (or modify the line to have the required value):



minlen = 15
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000205

The information system enforces minimum password length.

NIST SP 800-53 :: IA-5 (1) (a)

NIST SP 800-53A :: IA-5 (1).1 (i)

NIST SP 800-53 Revision 4 :: IA-5 (1) (a)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
