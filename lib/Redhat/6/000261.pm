# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000261
#
# VULN ID
#   V-38640
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50441r2_rule
#
# STIG ID
#   RHEL-06-000261
#
# RULE TITLE
#   The Automatic Bug Reporting Tool (abrtd) service must not be running.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000261;

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
    return 'V-38640';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000096';
}

sub get_rule_id {
    return 'SV-50441r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000261';
}

sub get_rule_title {
    return
        'The Automatic Bug Reporting Tool (abrtd) service must not be running.';
}

sub get_discussion {
    return <<'DISCUSSION';
Mishandling crash data could expose sensitive information about vulnerabilities in software executing on the local machine, as well as sensitive information from within a process's address space or registers.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check that the ""abrtd"" service is disabled in system boot configuration, run the following command:



# chkconfig ""abrtd"" --list



Output should indicate the ""abrtd"" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:



# chkconfig ""abrtd"" --list

""abrtd"" 0:off 1:off 2:off 3:off 4:off 5:off 6:off



Run the following command to verify ""abrtd"" is disabled through current runtime configuration:



# service abrtd status



If the service is disabled the command will return the following output:



abrtd is stopped





If the service is running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The Automatic Bug Reporting Tool (""abrtd"") daemon collects and reports crash data when an application crash is detected. Using a variety of plugins, abrtd can email crash reports to system administrators, log crash reports to files, or forward crash reports to a centralized issue tracking system such as RHTSupport. The ""abrtd"" service can be disabled with the following commands:



# chkconfig abrtd off

# service abrtd stop
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
