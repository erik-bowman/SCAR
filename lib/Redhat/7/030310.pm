# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030310
#
# VULN ID
#   V-72085
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000342-GPOS-00133
#
# RULE ID
#   SV-86709r1_rule
#
# STIG ID
#   RHEL-07-030310
#
# RULE TITLE
#   The operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030310;

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
    $self->{VULN_ID} = 'V-72085';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000342-GPOS-00133';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86709r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-030310';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Information stored in one location is vulnerable to accidental or incidental deletion or alteration.



Off-loading is a common process in information systems with limited audit storage capacity.



Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system encrypts audit records off-loaded onto a different system or media from the system being audited.



To determine if the transfer is encrypted, use the following command:



# grep -i enable_krb5 /etc/audisp/audisp-remote.conf

enable_krb5 = yes



If the value of the ""enable_krb5"" option is not set to ""yes"" or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.



If there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to encrypt the transfer of off-loaded audit records onto a different system or media from the system being audited.



Uncomment the ""enable_krb5"" option in ""/etc/audisp/audisp-remote.conf"" and set it with the following line:



enable_krb5 = yes
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001851

The information system off-loads audit records per organization-defined frequency onto a different system or media than the system being audited.

NIST SP 800-53 Revision 4 :: AU-4 (1)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
