# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010430
#
# VULN ID
#   V-71951
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00226
#
# RULE ID
#   SV-86575r1_rule
#
# STIG ID
#   RHEL-07-010430
#
# RULE TITLE
#   The delay between logon prompts following a failed console logon attempt must be at least four seconds.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010430;

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
    return 'V-71951';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00226';
}

sub get_rule_id {
    return 'SV-86575r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010430';
}

sub get_rule_title {
    return
        'The delay between logon prompts following a failed console logon attempt must be at least four seconds.';
}

sub get_discussion {
    return <<'DISCUSSION';
Configuring the operating system to implement organization-wide security implementation guides and security checklists verifies compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.



Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, and directory permission settings; and settings for functions, ports, protocols, services, and remote connections.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system enforces a delay of at least four seconds between console logon prompts following a failed logon attempt.



Check the value of the ""fail_delay"" parameter in the ""/etc/login.defs"" file with the following command:



# grep -i fail_delay /etc/login.defs

FAIL_DELAY 4



If the value of ""FAIL_DELAY"" is not set to ""4"" or greater, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to enforce a delay of at least four seconds between logon prompts following a failed console logon attempt.



Modify the ""/etc/login.defs"" file to set the ""FAIL_DELAY"" parameter to ""4"" or greater:



FAIL_DELAY 4
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
