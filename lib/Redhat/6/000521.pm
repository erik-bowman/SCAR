# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000521
#
# VULN ID
#   V-38446
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50246r2_rule
#
# STIG ID
#   RHEL-06-000521
#
# RULE TITLE
#   The mail system must forward all mail for root to one or more system administrators.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000521;

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
    return 'V-38446';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50246r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000521';
}

sub get_rule_title {
    return
        'The mail system must forward all mail for root to one or more system administrators.';
}

sub get_discussion {
    return <<'DISCUSSION';
A number of system services utilize email messages sent to the root user to notify system administrators of active or impending issues.  These messages must be forwarded to at least one monitored email address.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Find the list of alias maps used by the Postfix mail server:



# postconf alias_maps



Query the Postfix alias maps for an alias for ""root"":



# postmap -q root hash:/etc/aliases



If there are no aliases configured for root that forward to a monitored email address, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Set up an alias for root that forwards to a monitored email address:



# echo ""root: <system.administrator>@mail.mil"" >> /etc/aliases

# newaliases
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
