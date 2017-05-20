# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010119
#
# VULN ID
#   V-73159
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000069-GPOS-00037
#
# RULE ID
#   SV-87811r2_rule
#
# STIG ID
#   RHEL-07-010119
#
# RULE TITLE
#   When passwords are changed or new passwords are established, pwquality must be used.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010119;

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
    return 'V-73159';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000069-GPOS-00037';
}

sub get_rule_id {
    return 'SV-87811r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-010119';
}

sub get_rule_title {
    return
        'When passwords are changed or new passwords are established, pwquality must be used.';
}

sub get_discussion {
    return <<'DISCUSSION';
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. ""Pwquality"" enforces complex password construction configuration on the system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system uses ""pwquality"" to enforce the password complexity rules.



Check for the use of ""pwquality"" with the following command:



# grep pwquality /etc/pam.d/passwd



password    required    pam_pwquality.so retry=3



If the command does not return a line containing the value ""pam_pwquality.so"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to use ""pwquality"" to enforce password complexity rules.



Add the following line to ""/etc/pam.d/passwd"" (or modify the line to have the required value):



password    required    pam_pwquality.so retry=3
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000192

The information system enforces password complexity by the minimum number of upper case characters used.

NIST SP 800-53 :: IA-5 (1) (a)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (a)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
