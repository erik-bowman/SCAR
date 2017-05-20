# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000062
#
# VULN ID
#   V-38574
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000120
#
# RULE ID
#   SV-50375r3_rule
#
# STIG ID
#   RHEL-06-000062
#
# RULE TITLE
#   The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth).
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000062;

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
    return 'V-38574';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000120';
}

sub get_rule_id {
    return 'SV-50375r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000062';
}

sub get_rule_title {
    return
        'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth).';
}

sub get_discussion {
    return <<'DISCUSSION';
Using a stronger hashing algorithm makes password cracking attacks more difficult.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect the ""password"" section of ""/etc/pam.d/system-auth"", ""/etc/pam.d/system-auth-ac"", and other files in ""/etc/pam.d"" to identify the number of occurrences where the ""pam_unix.so"" module is used in the ""password"" section.

$ grep -E -c 'password.*pam_unix.so' /etc/pam.d/*



/etc/pam.d/atd:0

/etc/pam.d/config-util:0

/etc/pam.d/crond:0

/etc/pam.d/login:0

/etc/pam.d/other:0

/etc/pam.d/passwd:0

/etc/pam.d/password-auth:1

/etc/pam.d/password-auth-ac:1

/etc/pam.d/sshd:0

/etc/pam.d/su:0

/etc/pam.d/sudo:0

/etc/pam.d/system-auth:1

/etc/pam.d/system-auth-ac:1

/etc/pam.d/vlock:0



Note: The number adjacent to the file name indicates how many occurrences of the ""pam_unix.so"" module are found in the password section.



If the ""pam_unix.so"" module is not defined in the ""password"" section of ""/etc/pam.d/system-auth"", ""/etc/pam.d/system-auth-ac"", ""/etc/pam.d/password-auth"", and ""/etc/pam.d/password-auth-ac"" at a minimum, this is a finding.



Verify that the ""sha512"" variable is used with each instance of the ""pam_unix.so"" module in the ""password"" section:



$ grep password /etc/pam.d/* | grep pam_unix.so | grep sha512



/etc/pam.d/password-auth:password    	sufficient    pam_unix.so sha512 [other arguments…]

/etc/pam.d/password-auth-ac:password    sufficient    pam_unix.so sha512 [other arguments…]

/etc/pam.d/system-auth:password    	sufficient    pam_unix.so sha512 [other arguments…]

/etc/pam.d/system-auth-ac:password    	sufficient    pam_unix.so sha512 [other arguments…]



If this list of files does not coincide with the previous command, this is a finding.



If any of the identified ""pam_unix.so"" modules do not use the ""sha512"" variable, this is a finding.


CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
In ""/etc/pam.d/system-auth"", ""/etc/pam.d/system-auth-ac"", ""/etc/pam.d/password-auth"", and ""/etc/pam.d/password-auth-ac"", among potentially other files, the ""password"" section of the files controls which PAM modules execute during a password change. Set the ""pam_unix.so"" module in the ""password"" section to include the argument ""sha512"", as shown below:



password sufficient pam_unix.so sha512 [other arguments...]



This will help ensure when local users change their passwords, hashes for the new passwords will be generated using the SHA-512 algorithm. This is the default.



Note that any updates made to ""/etc/pam.d/system-auth"" will be overwritten by the ""authconfig"" program. The ""authconfig"" program should not be used.


FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000803

The information system implements mechanisms for authentication to a cryptographic module that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.

NIST SP 800-53 :: IA-7

NIST SP 800-53A :: IA-7.1

NIST SP 800-53 Revision 4 :: IA-7




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
