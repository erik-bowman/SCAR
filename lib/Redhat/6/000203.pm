# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000203
#
# VULN ID
#   V-38582
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50383r2_rule
#
# STIG ID
#   RHEL-06-000203
#
# RULE TITLE
#   The xinetd service must be disabled if no network services utilizing it are enabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000203;

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
    return 'V-38582';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000096';
}

sub get_rule_id {
    return 'SV-50383r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000203';
}

sub get_rule_title {
    return
        'The xinetd service must be disabled if no network services utilizing it are enabled.';
}

sub get_discussion {
    return <<'DISCUSSION';
The xinetd service provides a dedicated listener service for some programs, which is no longer necessary for commonly-used network services. Disabling it ensures that these uncommon services are not running, and also prevents attacks against xinetd itself.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If network services are using the xinetd service, this is not applicable.



To check that the ""xinetd"" service is disabled in system boot configuration, run the following command:



# chkconfig ""xinetd"" --list



Output should indicate the ""xinetd"" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:



# chkconfig ""xinetd"" --list

""xinetd"" 0:off 1:off 2:off 3:off 4:off 5:off 6:off



Run the following command to verify ""xinetd"" is disabled through current runtime configuration:



# service xinetd status



If the service is disabled the command will return the following output:



xinetd is stopped





If the service is running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""xinetd"" service can be disabled with the following commands:



# chkconfig xinetd off

# service xinetd stop
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
