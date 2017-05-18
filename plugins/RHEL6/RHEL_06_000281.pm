#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000281
#
# VULN ID
#   V-38637
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000278
#
# RULE ID
#   SV-50438r2_rule
#
# STIG ID
#   RHEL-06-000281
#
# RULE TITLE
#   The system package management tool must verify contents of all files associated with the audit package.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000281;

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
    $self->{VULN_ID} = 'V-38637';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000278';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50438r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000281';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system package management tool must verify contents of all files associated with the audit package.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The hash on important files like audit system executables should match the information given by the RPM database. Audit executables  with erroneous hashes could be a sign of nefarious activity on the system.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
The following command will list which audit files on the system have file hashes different from what is expected by the RPM database.



# rpm -V audit | awk '$1 ~ /..5/ && $2 != ""c""'





If there is output, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The RPM package management system can check the hashes of audit system package files. Run the following command to list which audit files on the system have hashes that differ from what is expected by the RPM database:



# rpm -V audit | grep '^..5'



A ""c"" in the second column indicates that a file is a configuration file, which may appropriately be expected to change. If the file that has changed was not expected to then refresh from distribution media or online repositories.



rpm -Uvh [affected_package]



OR



yum reinstall [affected_package]
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001496

The information system implements cryptographic mechanisms to protect the integrity of audit tools.

NIST SP 800-53 :: AU-9 (3)

NIST SP 800-53A :: AU-9 (3).1

NIST SP 800-53 Revision 4 :: AU-9 (3)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
