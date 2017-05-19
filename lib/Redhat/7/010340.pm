# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010340
#
# VULN ID
#   V-71947
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000373-GPOS-00156
#
# RULE ID
#   SV-86571r1_rule
#
# STIG ID
#   RHEL-07-010340
#
# RULE TITLE
#   Users must provide a password for privilege escalation.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010340;

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
    $self->{VULN_ID} = 'V-71947';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000373-GPOS-00156';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86571r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010340';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'Users must provide a password for privilege escalation.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Without re-authentication, users may access resources or perform tasks for which they do not have authorization.



When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.



Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system requires users to supply a password for privilege escalation.



Check the configuration of the ""/etc/sudoers"" and ""/etc/sudoers.d/*"" files with the following command:



# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*



If any uncommented line is found with a ""NOPASSWD"" tag, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to require users to supply a password for privilege escalation.



Check the configuration of the ""/etc/sudoers"" and ""/etc/sudoers.d/*"" files with the following command:



# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*



Remove any occurrences of ""NOPASSWD"" tags in the file.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-002038

The organization requires users to reauthenticate when organization-defined circumstances or situations requiring reauthentication.

NIST SP 800-53 Revision 4 :: IA-11




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
