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
    return 'V-71991';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000445-GPOS-00199';
}

sub get_rule_id {
    return 'SV-86615r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-020220';
}

sub get_rule_title {
    return 'The operating system must enable the SELinux targeted policy.';
}

sub get_discussion {
    return <<'DISCUSSION';
Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.



This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
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
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to verify correct operation of all security functions.



Set the ""SELinuxtype"" to the ""targeted"" policy by modifying the ""/etc/selinux/config"" file to have the following line:



SELINUXTYPE=targeted



A reboot is required for the changes to take effect.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-002165

The information system enforces organization-defined discretionary access control policies over defined subjects and objects.

NIST SP 800-53 Revision 4 :: AC-3 (4)



CCI-002696

The information system verifies correct operation of organization-defined security functions.

NIST SP 800-53 Revision 4 :: SI-6 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
