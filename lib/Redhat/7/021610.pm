# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021610
#
# VULN ID
#   V-72071
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86695r2_rule
#
# STIG ID
#   RHEL-07-021610
#
# RULE TITLE
#   The file integrity tool must be configured to verify extended attributes.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::021610;

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
    $self->{VULN_ID} = 'V-72071';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00227';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86695r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-021610';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The file integrity tool must be configured to verify extended attributes.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Extended attributes in file systems are used to contain arbitrary data and file metadata with security implications.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the file integrity tool is configured to verify extended attributes.



Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:



# yum list installed aide



If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.



If there is no application installed to perform file integrity checks, this is a finding.



Note: AIDE is highly configurable at install time. These commands assume the ""aide.conf"" file is under the ""/etc"" directory.



Use the following command to determine if the file is in another location:



# find / -name aide.conf



Check the ""aide.conf"" file to determine if the ""xattrs"" rule has been added to the rule list being applied to the files and directories selection lists.



An example rule that includes the ""xattrs"" rule follows:



All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux

/bin All            # apply the custom rule to the files in bin

/sbin All          # apply the same custom rule to the files in sbin



If the ""xattrs"" rule is not being used on all selection lines in the ""/etc/aide.conf"" file, or extended attributes are not being checked by another file integrity tool, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the file integrity tool to check file and directory extended attributes.



If AIDE is installed, ensure the ""xattrs"" rule is present on all file and directory selection lists.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
