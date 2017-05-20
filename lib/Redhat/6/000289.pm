# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000289
#
# VULN ID
#   V-38672
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50473r2_rule
#
# STIG ID
#   RHEL-06-000289
#
# RULE TITLE
#   The netconsole service must be disabled unless required.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000289;

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
    return 'V-38672';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000096';
}

sub get_rule_id {
    return 'SV-50473r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000289';
}

sub get_rule_title {
    return 'The netconsole service must be disabled unless required.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ""netconsole"" service is not necessary unless there is a need to debug kernel panics, which is not common.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check that the ""netconsole"" service is disabled in system boot configuration, run the following command:



# chkconfig ""netconsole"" --list



Output should indicate the ""netconsole"" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:



# chkconfig ""netconsole"" --list

""netconsole"" 0:off 1:off 2:off 3:off 4:off 5:off 6:off



Run the following command to verify ""netconsole"" is disabled through current runtime configuration:



# service netconsole status



If the service is disabled the command will return the following output:



netconsole is stopped





If the service is running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""netconsole"" service is responsible for loading the netconsole kernel module, which logs kernel printk messages over UDP to a syslog server. This allows debugging of problems where disk logging fails and serial consoles are impractical. The ""netconsole"" service can be disabled with the following commands:



# chkconfig netconsole off

# service netconsole stop
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
