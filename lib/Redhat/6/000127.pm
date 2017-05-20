# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000127
#
# VULN ID
#   V-38517
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50318r4_rule
#
# STIG ID
#   RHEL-06-000127
#
# RULE TITLE
#   The Transparent Inter-Process Communication (TIPC) protocol must be disabled unless required.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000127;

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
    return 'V-38517';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000096';
}

sub get_rule_id {
    return 'SV-50318r4_rule';
}

sub get_stig_id {
    return 'RHEL-06-000127';
}

sub get_rule_title {
    return
        'The Transparent Inter-Process Communication (TIPC) protocol must be disabled unless required.';
}

sub get_discussion {
    return <<'DISCUSSION';
Disabling TIPC protects the system against exploitation of any flaws in its implementation.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the system is configured to prevent the loading of the ""tipc"" kernel module, it will contain lines inside any file in ""/etc/modprobe.d"" or the deprecated""/etc/modprobe.conf"". These lines instruct the module loading system to run another program (such as ""/bin/true"") upon a module ""install"" event. Run the following command to search for such lines in all files in ""/etc/modprobe.d"" and the deprecated ""/etc/modprobe.conf"":



$ grep -r tipc /etc/modprobe.conf /etc/modprobe.d | grep -i ""/bin/true""



If no line is returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communications between nodes in a cluster. To configure the system to prevent the ""tipc"" kernel module from being loaded, add the following line to a file in the directory ""/etc/modprobe.d"":



install tipc /bin/true
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
