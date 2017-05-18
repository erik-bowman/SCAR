#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000062
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

package RHEL_06_000062;

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

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $plugin = RHEL_06_000062->new( $parent );
#
# DESCRIPTION
#   Initializes the plugin object and returns it
#
# ARGUMENTS
#   $parent    = The SCAR::RHEL6 module object
#
# ------------------------------------------------------------------------------

sub new {
    my ( $class, $parent ) = @_;
    my $self = bless { parent => $parent }, $class;

    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $results = RHEL_06_000062->check();
#
# DESCRIPTION
#   Performs a test against the system
#
# ------------------------------------------------------------------------------

sub check {
    my ($self) = @_;

    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $results = RHEL_06_000062->remediate();
#
# DESCRIPTION
#   Attempts remediation
#
# ------------------------------------------------------------------------------

sub remediate {
    my ($self) = @_;

    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $VULN_ID = RHEL_06_000062->VULN_ID();
#
# DESCRIPTION
#   Returns the plugins VULN ID
#
# ------------------------------------------------------------------------------

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38574';
    return $self->{VULN_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $SEVERITY = RHEL_06_000062->SEVERITY();
#
# DESCRIPTION
#   Returns the plugins SEVERITY
#
# ------------------------------------------------------------------------------

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $GROUP_TITLE = RHEL_06_000062->GROUP_TITLE();
#
# DESCRIPTION
#   Returns the plugins GROUP TITLE
#
# ------------------------------------------------------------------------------

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000120';
    return $self->{GROUP_TITLE};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $RULE_ID = RHEL_06_000062->RULE_ID();
#
# DESCRIPTION
#   Returns the plugins RULE ID
#
# ------------------------------------------------------------------------------

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50375r3_rule';
    return $self->{RULE_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $STIG_ID = RHEL_06_000062->STIG_ID();
#
# DESCRIPTION
#   Returns the plugins STIG ID
#
# ------------------------------------------------------------------------------

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000062';
    return $self->{STIG_ID};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $RULE_TITLE = RHEL_06_000062->RULE_TITLE();
#
# DESCRIPTION
#   Returns the plugins RULE TITLE
#
# ------------------------------------------------------------------------------

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth).';
    return $self->{RULE_TITLE};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $DISCUSSION = RHEL_06_000062->DISCUSSION();
#
# DESCRIPTION
#   Returns the plugins DISCUSSION text
#
# ------------------------------------------------------------------------------

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Using a stronger hashing algorithm makes password cracking attacks more difficult.
DISCUSSION
    return $self->{DISCUSSION};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $CHECK_CONTENT = RHEL_06_000062->CHECK_CONTENT();
#
# DESCRIPTION
#   Returns the plugins CHECK CONTENT text
#
# ------------------------------------------------------------------------------

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
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
    return $self->{CHECK_CONTENT};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $FIX_CONTENT = RHEL_06_000062->FIX_CONTENT();
#
# DESCRIPTION
#   Returns the plugins FIX CONTENT text
#
# ------------------------------------------------------------------------------

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
In ""/etc/pam.d/system-auth"", ""/etc/pam.d/system-auth-ac"", ""/etc/pam.d/password-auth"", and ""/etc/pam.d/password-auth-ac"", among potentially other files, the ""password"" section of the files controls which PAM modules execute during a password change. Set the ""pam_unix.so"" module in the ""password"" section to include the argument ""sha512"", as shown below:



password sufficient pam_unix.so sha512 [other arguments...]



This will help ensure when local users change their passwords, hashes for the new passwords will be generated using the SHA-512 algorithm. This is the default.



Note that any updates made to ""/etc/pam.d/system-auth"" will be overwritten by the ""authconfig"" program. The ""authconfig"" program should not be used.


FIX_CONTENT
    return $self->{FIX_CONTENT};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $CCI = RHEL_06_000062->CCI();
#
# DESCRIPTION
#   Returns the plugins CCI text
#
# ------------------------------------------------------------------------------

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
