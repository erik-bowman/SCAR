# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::032000
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

package Redhat::7::032000;

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
    return 'V-72213';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86837r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-032000';
}

sub get_rule_title {
    return 'The system must use a DoD-approved virus scan program.';
}

sub get_discussion {
    return <<'DISCUSSION';
Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.



The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.



If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
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
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Install an approved DoD antivirus solution on the system.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001668

The organization employs malicious code protection mechanisms at workstations, servers, or mobile computing devices on the network to detect and eradicate malicious code transported by electronic mail, electronic mail attachments, web accesses, removable media, or other common means or inserted through the exploitation of information system vulnerabilities.

NIST SP 800-53 :: SI-3 a

NIST SP 800-53A :: SI-3.1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
