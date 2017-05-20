# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020210
#
# VULN ID
#   V-71989
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000445-GPOS-00199
#
# RULE ID
#   SV-86613r2_rule
#
# STIG ID
#   RHEL-07-020210
#
# RULE TITLE
#   The operating system must enable SELinux.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020210;

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
    return 'V-71989';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000445-GPOS-00199';
}

sub get_rule_id {
    return 'SV-86613r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-020210';
}

sub get_rule_title {
    return 'The operating system must enable SELinux.';
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



Check if ""SELinux"" is active and in ""Enforcing"" mode with the following command:



# getenforce

Enforcing



If ""SELinux"" is not active and not in ""Enforcing"" mode, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to verify correct operation of all security functions.



Set the ""SELinux"" status and the ""Enforcing"" mode by modifying the ""/etc/selinux/config"" file to have the following line:



SELINUX=enforcing



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
