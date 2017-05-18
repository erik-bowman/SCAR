#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_040300
#
# VULN ID
#   V-72233
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000423-GPOS-00187
#
# RULE ID
#   SV-86857r1_rule
#
# STIG ID
#   RHEL-07-040300
#
# RULE TITLE
#   All networked systems must have SSH installed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_040300;

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
    $self->{VULN_ID} = 'V-72233';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000423-GPOS-00187';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86857r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-040300';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'All networked systems must have SSH installed.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.



This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.



Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa.



Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188, SRG-OS-000425-GPOS-00189, SRG-OS-000426-GPOS-00190
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Check to see if sshd is installed with the following command:



# yum list installed ssh

libssh2.x86_64                           1.4.3-8.el7               @anaconda/7.1

openssh.x86_64                           6.6.1p1-11.el7            @anaconda/7.1

openssh-clients.x86_64                   6.6.1p1-11.el7            @anaconda/7.1

openssh-server.x86_64                    6.6.1p1-11.el7            @anaconda/7.1



If the ""SSH server"" package is not installed, this is a finding.



If the ""SSH client"" package is not installed, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Install SSH packages onto the host with the following commands:



# yum install openssh-clients.x86_64

# yum install openssh-server.x86_64



Note: 32-bit versions will require different packages.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-002418

The information system protects the confidentiality and/or integrity of transmitted information.

NIST SP 800-53 Revision 4 :: SC-8



CCI-002420

The information system maintains the confidentiality and/or integrity of information during preparation for transmission.

NIST SP 800-53 Revision 4 :: SC-8 (2)



CCI-002421

The information system implements cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by organization-defined alternative physical safeguards.

NIST SP 800-53 Revision 4 :: SC-8 (1)



CCI-002422

The information system maintains the confidentiality and/or integrity of information during reception.

NIST SP 800-53 Revision 4 :: SC-8 (2)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
