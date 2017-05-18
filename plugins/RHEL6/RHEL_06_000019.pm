#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000019
#
# VULN ID
#   V-38491
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000248
#
# RULE ID
#   SV-50292r1_rule
#
# STIG ID
#   RHEL-06-000019
#
# RULE TITLE
#   There must be no .rhosts or hosts.equiv files on the system.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000019;

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
    $self->{VULN_ID} = 'V-38491';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'high';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000248';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50292r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000019';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'There must be no .rhosts or hosts.equiv files on the system.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Trust files are convenient, but when used in conjunction with the R-services, they can allow unauthenticated access to a system.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
The existence of the file ""/etc/hosts.equiv"" or a file named "".rhosts"" inside a user home directory indicates the presence of an Rsh trust relationship.

If these files exist, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The files ""/etc/hosts.equiv"" and ""~/.rhosts"" (in each user's home directory) list remote hosts and users that are trusted by the local system when using the rshd daemon. To remove these files, run the following command to delete them from any location.



# rm /etc/hosts.equiv







$ rm ~/.rhosts
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001436

The organization disables organization defined networking protocols within the information system deemed to be nonsecure except for explicitly identified components in support of specific operational requirements.

NIST SP 800-53 :: AC-17 (8)

NIST SP 800-53A :: AC-17 (8).1 (ii)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
