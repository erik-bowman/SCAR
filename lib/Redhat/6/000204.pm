# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000204
#
# VULN ID
#   V-38584
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50385r1_rule
#
# STIG ID
#   RHEL-06-000204
#
# RULE TITLE
#   The xinetd service must be uninstalled if no network services utilizing it are enabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000204;

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
    return 'V-38584';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000096';
}

sub get_rule_id {
    return 'SV-50385r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000204';
}

sub get_rule_title {
    return
        'The xinetd service must be uninstalled if no network services utilizing it are enabled.';
}

sub get_discussion {
    return <<'DISCUSSION';
Removing the ""xinetd"" package decreases the risk of the xinetd service's accidental (or intentional) activation.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If network services are using the xinetd service, this is not applicable.



Run the following command to determine if the ""xinetd"" package is installed:



# rpm -q xinetd





If the package is installed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""xinetd"" package can be uninstalled with the following command:



# yum erase xinetd
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000382

The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.

NIST SP 800-53 :: CM-7

NIST SP 800-53A :: CM-7.1 (iii)

NIST SP 800-53 Revision 4 :: CM-7 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
