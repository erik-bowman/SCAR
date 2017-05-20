# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000275
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

package Redhat::6::000275;

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

sub _set_finding_status {
    my ( $self, $finding_status ) = @_;
    $self->{finding_status} = $finding_status;
    return $self->{finding_status};
}

sub get_finding_status {
    my ($self) = @_;
    return defined $self->{finding_status} ? $self->{finding_status} : undef;
}

sub get_vuln_id {
    return 'V-38659';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000131';
}

sub get_rule_id {
    return 'SV-50460r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000275';
}

sub get_rule_title {
    return
        'The operating system must employ cryptographic mechanisms to protect information in storage.';
}

sub get_discussion {
    return <<'DISCUSSION';
The risk of a system's physical compromise, particularly mobile systems such as laptops, places its data at risk of compromise. Encrypting this data mitigates the risk of its loss if the system is lost.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Determine if encryption must be used to protect data on the system.

If encryption must be used and is not employed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Red Hat Enterprise Linux 6 natively supports partition encryption through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to encrypt a partition is during installation time.



For manual installations, select the ""Encrypt"" checkbox during partition creation to encrypt the partition. When this option is selected the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots.



For automated/unattended installations, it is possible to use Kickstart by adding the ""--encrypted"" and ""--passphrase="" options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition:



part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted --passphrase=[PASSPHRASE]



Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the ""--passphrase="" option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation.



Detailed information on encrypting partitions using LUKS can be found on the Red Hat Documentation web site:



https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-LUKS_Disk_Encryption.html
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001019

The organization employs cryptographic mechanisms to protect information in storage.

NIST SP 800-53 :: MP-4 (1)

NIST SP 800-53A :: MP-4 (1).1




CCI
}

# ------------------------------------------------------------------------------

1;

__END__