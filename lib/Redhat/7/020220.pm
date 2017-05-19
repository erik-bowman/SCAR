# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020220
#
# VULN ID
#   V-71991
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000445-GPOS-00199
#
# RULE ID
#   SV-86615r2_rule
#
# STIG ID
#   RHEL-07-020220
#
# RULE TITLE
#   The operating system must enable the SELinux targeted policy.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020220;

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
    $self->{VULN_ID} = 'V-71991';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'high';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000445-GPOS-00199';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86615r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-020220';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must enable the SELinux targeted policy.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.



This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system verifies correct operation of all security functions.



Check if ""SELinux"" is active and is enforcing the targeted policy with the following command:



# sestatus

SELinux status:                 enabled

SELinuxfs mount:                /selinu

XCurrent mode:                   enforcing

Mode from config file:          enforcing

Policy version:                 24

Policy from config file:        targeted



If the ""Policy from config file"" is not set to ""targeted"", or the ""Loaded policy name"" is not set to ""targeted"", this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to verify correct operation of all security functions.



Set the ""SELinuxtype"" to the ""targeted"" policy by modifying the ""/etc/selinux/config"" file to have the following line:



SELINUXTYPE=targeted



A reboot is required for the changes to take effect.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-002165

The information system enforces organization-defined discretionary access control policies over defined subjects and objects.

NIST SP 800-53 Revision 4 :: AC-3 (4)



CCI-002696

The information system verifies correct operation of organization-defined security functions.

NIST SP 800-53 Revision 4 :: SI-6 a




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
