#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000275
#
# VULN ID
#   V-38659
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000131
#
# RULE ID
#   SV-50460r2_rule
#
# STIG ID
#   RHEL-06-000275
#
# RULE TITLE
#   The operating system must employ cryptographic mechanisms to protect information in storage.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000275;

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
    $self->{VULN_ID} = 'V-38659';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000131';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50460r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000275';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must employ cryptographic mechanisms to protect information in storage.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The risk of a system's physical compromise, particularly mobile systems such as laptops, places its data at risk of compromise. Encrypting this data mitigates the risk of its loss if the system is lost.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Determine if encryption must be used to protect data on the system.

If encryption must be used and is not employed, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Red Hat Enterprise Linux 6 natively supports partition encryption through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to encrypt a partition is during installation time.



For manual installations, select the ""Encrypt"" checkbox during partition creation to encrypt the partition. When this option is selected the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots.



For automated/unattended installations, it is possible to use Kickstart by adding the ""--encrypted"" and ""--passphrase="" options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition:



part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted --passphrase=[PASSPHRASE]



Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the ""--passphrase="" option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation.



Detailed information on encrypting partitions using LUKS can be found on the Red Hat Documentation web site:



https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-LUKS_Disk_Encryption.html
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001019

The organization employs cryptographic mechanisms to protect information in storage.

NIST SP 800-53 :: MP-4 (1)

NIST SP 800-53A :: MP-4 (1).1




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
