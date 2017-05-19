# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020330
#
# VULN ID
#   V-72009
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86633r1_rule
#
# STIG ID
#   RHEL-07-020330
#
# RULE TITLE
#   All files and directories must have a valid group owner.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020330;

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
    $self->{VULN_ID} = 'V-72009';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00227';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86633r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-020330';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'All files and directories must have a valid group owner.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify all files and directories on the system have a valid group.



Check the owner of all files and directories with the following command:



Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.



# find / -xdev -fstype xfs -nogroup



If any files on the system do not have an assigned group, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Either remove all files and directories from the system that do not have a valid group, or assign a valid group to all files and directories on the system with the ""chgrp"" command:



# chgrp <group> <file>
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-002165

The information system enforces organization-defined discretionary access control policies over defined subjects and objects.

NIST SP 800-53 Revision 4 :: AC-3 (4)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
