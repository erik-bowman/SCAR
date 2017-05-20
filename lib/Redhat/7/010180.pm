# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010180
#
# VULN ID
#   V-71915
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000072-GPOS-00040
#
# RULE ID
#   SV-86539r1_rule
#
# STIG ID
#   RHEL-07-010180
#
# RULE TITLE
#   When passwords are changed the number of repeating consecutive characters must not be more than four characters.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010180;

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
    return 'V-71915';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000072-GPOS-00040';
}

sub get_rule_id {
    return 'SV-86539r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010180';
}

sub get_rule_title {
    return
        'When passwords are changed the number of repeating consecutive characters must not be more than four characters.';
}

sub get_discussion {
    return <<'DISCUSSION';
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.



Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
The ""maxrepeat"" option sets the maximum number of allowed same consecutive characters in a new password.



Check for the value of the ""maxrepeat"" option in ""/etc/security/pwquality.conf"" with the following command:



# grep maxrepeat /etc/security/pwquality.conf

maxrepeat = 2



If the value of ""maxrepeat"" is set to more than ""2"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to require the change of the number of repeating consecutive characters when passwords are changed by setting the ""maxrepeat"" option.



Add the following line to ""/etc/security/pwquality.conf conf"" (or modify the line to have the required value):



maxrepeat = 2
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000195

The information system, for password-based authentication, when new passwords are created, enforces that at least an organization-defined number of characters are changed.

NIST SP 800-53 :: IA-5 (1) (b)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (b)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
