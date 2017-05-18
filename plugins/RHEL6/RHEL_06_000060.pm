#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000060
#
# VULN ID
#   V-38572
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000072
#
# RULE ID
#   SV-50373r2_rule
#
# STIG ID
#   RHEL-06-000060
#
# RULE TITLE
#   The system must require at least eight characters be changed between the old and new passwords during a password change.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000060;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# SCAR modules
use SCAR;
use SCAR::Log;
use SCAR::Backup;

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
    $self->{VULN_ID} = 'V-38572';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000072';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50373r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000060';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must require at least eight characters be changed between the old and new passwords during a password change.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Requiring a minimum number of different characters during password changes ensures that newly changed passwords should not resemble previously compromised ones. Note that passwords which are changed on compromised systems will still be compromised, however.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To check how many characters must differ during a password change, run the following command:



$ grep pam_cracklib /etc/pam.d/system-auth



The ""difok"" parameter will indicate how many characters must differ. The DoD requires eight characters differ during a password change. This would appear as ""difok=8"".



If difok is not found or not set to the required value, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The pam_cracklib module's ""difok"" parameter controls requirements for usage of different characters during a password change. Add ""difok=[NUM]"" after pam_cracklib.so to require differing characters when changing passwords, substituting [NUM] appropriately. The DoD requirement is 8.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000195

The information system, for password-based authentication, when new passwords are created, enforces that at least an organization-defined number of characters are changed.

NIST SP 800-53 :: IA-5 (1) (b)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (b)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
