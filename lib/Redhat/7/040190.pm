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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-72229';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000250-GPOS-00093';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86853r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-040190';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Without cryptographic integrity protections, information can be altered by unauthorized users without detection.



Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the key used to generate the hash.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
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
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to implement cryptography to protect the integrity of LDAP remote access sessions.



Set the ""tls_cacertdir"" option in ""/etc/pam_ldap.conf"" to point to the directory that will contain the X.509 certificates for peer authentication.



Set the ""tls_cacertfile"" option in ""/etc/pam_ldap.conf"" to point to the path for the X.509 certificates used for peer authentication.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001453

The information system implements cryptographic mechanisms to protect the integrity of remote access sessions.

NIST SP 800-53 :: AC-17 (2)

NIST SP 800-53A :: AC-17 (2).1

NIST SP 800-53 Revision 4 :: AC-17 (2)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
