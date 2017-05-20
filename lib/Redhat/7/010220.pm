# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010220
#
# VULN ID
#   V-71923
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000073-GPOS-00041
#
# RULE ID
#   SV-86547r2_rule
#
# STIG ID
#   RHEL-07-010220
#
# RULE TITLE
#   User and group account administration utilities must be configured to store only encrypted representations of passwords.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010220;

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
    return 'V-71923';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000073-GPOS-00041';
}

sub get_rule_id {
    return 'SV-86547r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-010220';
}

sub get_rule_title {
    return
        'User and group account administration utilities must be configured to store only encrypted representations of passwords.';
}

sub get_discussion {
    return <<'DISCUSSION';
Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the user and group account administration utilities are configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is ""SHA512"".



Check that the system is configured to create ""SHA512"" hashed passwords with the following command:



# cat /etc/libuser.conf | grep -i sha512



crypt_style = sha512



If the ""crypt_style"" variable is not set to ""sha512"", is not in the defaults section, or does not exist, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to store only SHA512 encrypted representations of passwords.



Add or update the following line in ""/etc/libuser.conf"" in the [defaults] section:



crypt_style = sha512
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
