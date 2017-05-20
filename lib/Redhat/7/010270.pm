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
    return 'V-71933';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000077-GPOS-00045';
}

sub get_rule_id {
    return 'SV-86557r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010270';
}

sub get_rule_title {
    return
        'Passwords must be prohibited from reuse for a minimum of five generations.';
}

sub get_discussion {
    return <<'DISCUSSION';
Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system prohibits password reuse for a minimum of five generations.



Check for the value of the ""remember"" argument in ""/etc/pam.d/system-auth-ac"" with the following command:



# grep -i remember /etc/pam.d/system-auth-ac

password sufficient pam_unix.so use_authtok sha512 shadow remember=5



If the line containing the ""pam_unix.so"" line does not have the ""remember"" module argument set, or the value of the ""remember"" module argument is set to less than ""5"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to prohibit password reuse for a minimum of five generations.



Add the following line in ""/etc/pam.d/system-auth-ac"" (or modify the line to have the required value):



password sufficient pam_unix.so use_authtok sha512 shadow remember=5



and run the ""authconfig"" command.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000200

The information system prohibits password reuse for the organization defined number of generations.

NIST SP 800-53 :: IA-5 (1) (e)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (e)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
