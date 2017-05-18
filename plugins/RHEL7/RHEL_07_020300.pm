#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_020300
#
# VULN ID
#   V-72003
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000104-GPOS-00051
#
# RULE ID
#   SV-86627r1_rule
#
# STIG ID
#   RHEL-07-020300
#
# RULE TITLE
#   All Group Identifiers (GIDs) referenced in the /etc/passwd file must be defined in the /etc/group file.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_020300;

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
    $self->{VULN_ID} = 'V-72003';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000104-GPOS-00051';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86627r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-020300';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'All Group Identifiers (GIDs) referenced in the /etc/passwd file must be defined in the /etc/group file.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
If a user is assigned the GID of a group not existing on the system, and a group with the GID is subsequently created, the user may have unintended rights to any files associated with the group.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify all GIDs referenced in the ""/etc/passwd"" file are defined in the ""/etc/group"" file.



Check that all referenced GIDs exist with the following command:



# pwck -r



If GIDs referenced in ""/etc/passwd"" file are returned as not defined in ""/etc/group"" file, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the system to define all GIDs found in the ""/etc/passwd"" file by modifying the ""/etc/group"" file to add any non-existent group referenced in the ""/etc/passwd"" file, or change the GIDs referenced in the ""/etc/passwd"" file to a group that exists in ""/etc/group"".
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000764

The information system uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users).

NIST SP 800-53 :: IA-2

NIST SP 800-53A :: IA-2.1

NIST SP 800-53 Revision 4 :: IA-2




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
