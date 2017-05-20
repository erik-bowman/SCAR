# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000249
#
# VULN ID
#   V-38622
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50423r2_rule
#
# STIG ID
#   RHEL-06-000249
#
# RULE TITLE
#   Mail relaying must be restricted.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000249;

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
    return 'V-38622';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000096';
}

sub get_rule_id {
    return 'SV-50423r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000249';
}

sub get_rule_title {
    return 'Mail relaying must be restricted.';
}

sub get_discussion {
    return <<'DISCUSSION';
This ensures ""postfix"" accepts mail messages (such as cron job reports) from the local system only, and not from the network, which protects it from network attack.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the system is an authorized mail relay host, this is not applicable.



Run the following command to ensure postfix accepts mail messages from only the local system:



$ grep inet_interfaces /etc/postfix/main.cf



If properly configured, the output should show only ""localhost"".

If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Edit the file ""/etc/postfix/main.cf"" to ensure that only the following ""inet_interfaces"" line appears:



inet_interfaces = localhost
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
