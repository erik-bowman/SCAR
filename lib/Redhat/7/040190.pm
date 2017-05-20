# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040190
#
# VULN ID
#   V-72229
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000250-GPOS-00093
#
# RULE ID
#   SV-86853r2_rule
#
# STIG ID
#   RHEL-07-040190
#
# RULE TITLE
#   The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040190;

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
    return 'V-72229';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000250-GPOS-00093';
}

sub get_rule_id {
    return 'SV-86853r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040190';
}

sub get_rule_title {
    return
        'The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.';
}

sub get_discussion {
    return <<'DISCUSSION';
Without cryptographic integrity protections, information can be altered by unauthorized users without detection.



Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the key used to generate the hash.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system implements cryptography to protect the integrity of remote LDAP access sessions.



To determine if LDAP is being used for authentication, use the following command:



# grep -i useldapauth /etc/sysconfig/authconfig

USELDAPAUTH=yes



If USELDAPAUTH=yes, then LDAP is being used.



Check for the directory containing X.509 certificates for peer authentication with the following command:



# grep -i cacertdir /etc/pam_ldap.conf

tls_cacertdir /etc/openldap/certs



Verify the directory set with the ""tls_cacertdir"" option exists.



If the directory does not exist or the option is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to implement cryptography to protect the integrity of LDAP remote access sessions.



Set the ""tls_cacertdir"" option in ""/etc/pam_ldap.conf"" to point to the directory that will contain the X.509 certificates for peer authentication.



Set the ""tls_cacertfile"" option in ""/etc/pam_ldap.conf"" to point to the path for the X.509 certificates used for peer authentication.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001453

The information system implements cryptographic mechanisms to protect the integrity of remote access sessions.

NIST SP 800-53 :: AC-17 (2)

NIST SP 800-53A :: AC-17 (2).1

NIST SP 800-53 Revision 4 :: AC-17 (2)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
