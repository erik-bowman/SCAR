#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000045
#
# VULN ID
#   V-38465
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000259
#
# RULE ID
#   SV-50265r3_rule
#
# STIG ID
#   RHEL-06-000045
#
# RULE TITLE
#   Library files must have mode 0755 or less permissive.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000045;

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
    $self->{VULN_ID} = 'V-38465';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000259';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50265r3_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000045';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'Library files must have mode 0755 or less permissive.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Restrictive permissions are necessary to protect the integrity of the system.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default:



/lib

/lib64

/usr/lib

/usr/lib64





Kernel modules, which can be added to the kernel during runtime, are stored in ""/lib/modules"". All files in these directories should not be group-writable or world-writable. To find shared libraries that are group-writable or world-writable, run the following command for each directory [DIR] which contains shared libraries:



$ find -L [DIR] -perm /022 -type f





If any of these files (excluding broken symlinks) are group-writable or world-writable, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default:



/lib

/lib64

/usr/lib

/usr/lib64



If any file in these directories is found to be group-writable or world-writable, correct its permission with the following command:



# chmod go-w [FILE]
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001499

The organization limits privileges to change software resident within software libraries.

NIST SP 800-53 :: CM-5 (6)

NIST SP 800-53A :: CM-5 (6).1

NIST SP 800-53 Revision 4 :: CM-5 (6)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
