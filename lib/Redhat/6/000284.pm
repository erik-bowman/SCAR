# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000284
#
# VULN ID
#   V-38666
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000270
#
# RULE ID
#   SV-50467r2_rule
#
# STIG ID
#   RHEL-06-000284
#
# RULE TITLE
#   The system must use and update a DoD-approved virus scan program.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000284;

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
    return 'V-38666';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000270';
}

sub get_rule_id {
    return 'SV-50467r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000284';
}

sub get_rule_title {
    return
        'The system must use and update a DoD-approved virus scan program.';
}

sub get_discussion {
    return <<'DISCUSSION';
Virus scanning software can be used to detect if a system has been compromised by computer viruses, as well as to limit their spread to other systems.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect the system for a cron job or system service which executes a virus scanning tool regularly.

To verify the McAfee VSEL system service is operational, run the following command:



# /etc/init.d/nails status



To check on the age of uvscan virus definition files, run the following command:



# cd /opt/NAI/LinuxShield/engine/dat

# ls -la avvscan.dat avvnames.dat avvclean.dat



If virus scanning software does not run continuously, or at least daily, or has signatures that are out of date, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Install virus scanning software, which uses signatures to search for the presence of viruses on the filesystem.



The McAfee VirusScan Enterprise for Linux virus scanning tool is provided for DoD systems. Ensure virus definition files are no older than 7 days, or their last release.



Configure the virus scanning software to perform scans dynamically on all accessed files. If this is not possible, configure the system to scan all altered files on the system on a daily basis. If the system processes inbound SMTP mail, configure the virus scanner to scan all received mail.
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
