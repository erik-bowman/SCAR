# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040340
#
# VULN ID
#   V-72241
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000163-GPOS-00072
#
# RULE ID
#   SV-86865r2_rule
#
# STIG ID
#   RHEL-07-040340
#
# RULE TITLE
#   All network connections associated with SSH traffic must terminate after a period of inactivity.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040340;

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
    return 'V-72241';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000163-GPOS-00072';
}

sub get_rule_id {
    return 'SV-86865r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040340';
}

sub get_rule_title {
    return
        'All network connections associated with SSH traffic must terminate after a period of inactivity.';
}

sub get_discussion {
    return <<'DISCUSSION';
Terminating an idle SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.



Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.



Satisfies: SRG-OS-000163-GPOS-00072, SRG-OS-000279-GPOS-00109
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system automatically terminates a user session after inactivity time-outs have expired.



Check for the value of the ""ClientAliveCountMax"" keyword with the following command:



# grep -i clientalivecount /etc/ssh/sshd_config

ClientAliveCountMax 0



If ""ClientAliveCountMax"" is not set to ""0"" in ""/etc/ ssh/sshd_config"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to automatically terminate a user session after inactivity time-outs have expired or at shutdown.



Add the following line (or modify the line to have the required value) to the ""/etc/ssh/sshd_config"" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):



ClientAliveCountMax 0



The SSH service must be restarted for changes to take effect.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001133

The information system terminates the network connection associated with a communications session at the end of the session or after an organization-defined time period of inactivity.

NIST SP 800-53 :: SC-10

NIST SP 800-53A :: SC-10.1 (ii)

NIST SP 800-53 Revision 4 :: SC-10



CCI-002361

The information system automatically terminates a user session after organization-defined conditions or trigger events requiring session disconnect.

NIST SP 800-53 Revision 4 :: AC-12




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
