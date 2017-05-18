#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_032000
#
# VULN ID
#   V-72213
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86837r1_rule
#
# STIG ID
#   RHEL-07-032000
#
# RULE TITLE
#   The system must use a DoD-approved virus scan program.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_032000;

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
    $self->{VULN_ID} = 'V-72213';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'high';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00227';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86837r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-032000';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must use a DoD-approved virus scan program.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.



The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.



If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the system is using a DoD-approved virus scan program.



Check for the presence of ""McAfee VirusScan Enterprise for Linux"" with the following command:



# systemctl status nails

nails - service for McAfee VirusScan Enterprise for Linux

>  Loaded: loaded /opt/NAI/package/McAfeeVSEForLinux/McAfeeVSEForLinux-2.0.2.<build_number>; enabled)

>  Active: active (running) since Mon 2015-09-27 04:11:22 UTC;21 min ago



If the ""nails"" service is not active, check for the presence of ""clamav"" on the system with the following command:



# systemctl status clamav-daemon.socket

 systemctl status clamav-daemon.socket

  clamav-daemon.socket - Socket for Clam AntiVirus userspace daemon

     Loaded: loaded (/lib/systemd/system/clamav-daemon.socket; enabled)

     Active: active (running) since Mon 2015-01-12 09:32:59 UTC; 7min ago



If neither of these applications are loaded and active, ask the System Administrator if there is an antivirus package installed and active on the system.



If no antivirus scan program is active on the system, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Install an approved DoD antivirus solution on the system.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001668

The organization employs malicious code protection mechanisms at workstations, servers, or mobile computing devices on the network to detect and eradicate malicious code transported by electronic mail, electronic mail attachments, web accesses, removable media, or other common means or inserted through the exploitation of information system vulnerabilities.

NIST SP 800-53 :: SI-3 a

NIST SP 800-53A :: SI-3.1 (ii)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
