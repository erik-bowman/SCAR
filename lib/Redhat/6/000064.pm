# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000064
#
# VULN ID
#   V-38577
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000120
#
# RULE ID
#   SV-50378r1_rule
#
# STIG ID
#   RHEL-06-000064
#
# RULE TITLE
#   The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf).
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000064;

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
    $self->{VULN_ID} = 'V-38577';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000120';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50378r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000064';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf).';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Using a stronger hashing algorithm makes password cracking attacks more difficult.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Inspect ""/etc/libuser.conf"" and ensure the following line appears in the ""[default]"" section:



crypt_style = sha512





If it does not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
In ""/etc/libuser.conf"", add or correct the following line in its ""[defaults]"" section to ensure the system will use the SHA-512 algorithm for password hashing:



crypt_style = sha512
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000803

The information system implements mechanisms for authentication to a cryptographic module that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.

NIST SP 800-53 :: IA-7

NIST SP 800-53A :: IA-7.1

NIST SP 800-53 Revision 4 :: IA-7




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
