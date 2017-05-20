# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010150
#
# VULN ID
#   V-71909
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000266-GPOS-00101
#
# RULE ID
#   SV-86533r1_rule
#
# STIG ID
#   RHEL-07-010150
#
# RULE TITLE
#   When passwords are changed or new passwords are assigned, the new password must contain at least one special character.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010150;

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
    return 'V-71909';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000266-GPOS-00101';
}

sub get_rule_id {
    return 'SV-86533r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010150';
}

sub get_rule_title {
    return
        'When passwords are changed or new passwords are assigned, the new password must contain at least one special character.';
}

sub get_discussion {
    return <<'DISCUSSION';
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.



Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system enforces password complexity by requiring that at least one special character be used.



Note: The value to require a number of special characters to be set is expressed as a negative number in ""/etc/security/pwquality.conf"".



Check the value for ""ocredit"" in ""/etc/security/pwquality.conf"" with the following command:



# grep ocredit /etc/security/pwquality.conf

ocredit=-1



If the value of ""ocredit"" is not set to a negative value, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to enforce password complexity by requiring that at least one special character be used by setting the ""dcredit"" option.



Add the following line to ""/etc/security/pwquality.conf"" (or modify the line to have the required value):



ocredit = -1
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001619

The information system enforces password complexity by the minimum number of special characters used.

NIST SP 800-53 :: IA-5 (1) (a)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (a)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
