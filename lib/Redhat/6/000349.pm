# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000349
#
# VULN ID
#   V-38595
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000105
#
# RULE ID
#   SV-50396r3_rule
#
# STIG ID
#   RHEL-06-000349
#
# RULE TITLE
#   The system must be configured to require the use of a CAC, PIV compliant hardware token, or Alternate Logon Token (ALT) for authentication.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000349;

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
    return 'V-38595';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000105';
}

sub get_rule_id {
    return 'SV-50396r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000349';
}

sub get_rule_title {
    return
        'The system must be configured to require the use of a CAC, PIV compliant hardware token, or Alternate Logon Token (ALT) for authentication.';
}

sub get_discussion {
    return <<'DISCUSSION';
Smart card login provides two-factor authentication stronger than that provided by a username/password combination. Smart cards leverage a PKI (public key infrastructure) in order to provide and verify credentials.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Interview the SA to determine if all accounts not exempted by policy are using CAC authentication. For DoD systems, the following systems and accounts are exempt from using smart card (CAC) authentication:



Standalone systems

Application accounts

Temporary employee accounts, such as students or interns, who cannot easily receive a CAC or PIV

Operational tactical locations that are not collocated with RAPIDS workstations to issue CAC or ALT

Test systems, such as those with an Interim Approval to Test (IATT) and use a separate VPN, firewall, or security measure preventing access to network and system components from outside the protection boundary documented in the IATT.







If non-exempt accounts are not using CAC authentication, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To enable smart card authentication, consult the documentation at:



https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Managing_Smart_Cards/enabling-smart-card-login.html



For guidance on enabling SSH to authenticate against a Common Access Card (CAC), consult documentation at:



https://access.redhat.com/solutions/82273
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000765

The information system implements multifactor authentication for network access to privileged accounts.

NIST SP 800-53 :: IA-2 (1)

NIST SP 800-53A :: IA-2 (1).1

NIST SP 800-53 Revision 4 :: IA-2 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
