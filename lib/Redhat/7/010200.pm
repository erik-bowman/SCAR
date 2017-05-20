# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010200
#
# VULN ID
#   V-71919
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000073-GPOS-00041
#
# RULE ID
#   SV-86543r1_rule
#
# STIG ID
#   RHEL-07-010200
#
# RULE TITLE
#   The PAM system service must be configured to store only encrypted representations of passwords.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010200;

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
    return 'V-71919';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000073-GPOS-00041';
}

sub get_rule_id {
    return 'SV-86543r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010200';
}

sub get_rule_title {
    return
        'The PAM system service must be configured to store only encrypted representations of passwords.';
}

sub get_discussion {
    return <<'DISCUSSION';
Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the PAM system service is configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512.



Check that the system is configured to create SHA512 hashed passwords with the following command:



# grep password /etc/pam.d/system-auth-ac

password sufficient pam_unix.so sha512



If the ""/etc/pam.d/system-auth-ac"" configuration files allow for password hashes other than SHA512 to be used, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to store only SHA512 encrypted representations of passwords.



Add the following line in ""/etc/pam.d/system-auth-ac"":



password sufficient pam_unix.so sha512



and run the ""authconfig"" command.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000196

The information system, for password-based authentication, stores only encrypted representations of passwords.

NIST SP 800-53 :: IA-5 (1) (c)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (c)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
