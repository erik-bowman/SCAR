# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040440
#
# VULN ID
#   V-72261
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000364-GPOS-00151
#
# RULE ID
#   SV-86885r2_rule
#
# STIG ID
#   RHEL-07-040440
#
# RULE TITLE
#   The SSH daemon must not permit Kerberos authentication unless needed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040440;

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
    return 'V-72261';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000364-GPOS-00151';
}

sub get_rule_id {
    return 'SV-86885r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040440';
}

sub get_rule_title {
    return
        'The SSH daemon must not permit Kerberos authentication unless needed.';
}

sub get_discussion {
    return <<'DISCUSSION';
Kerberos authentication for SSH is often implemented using Generic Security Service Application Program Interface (GSSAPI). If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation. Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation. To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for systems not using this capability.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the SSH daemon does not permit Kerberos to authenticate passwords unless approved.



Check that the SSH daemon does not permit Kerberos to authenticate passwords with the following command:



# grep -i kerberosauth /etc/ssh/sshd_config

KerberosAuthentication no



If the ""KerberosAuthentication"" keyword is missing, or is set to ""yes"" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Uncomment the ""KerberosAuthentication"" keyword in ""/etc/ssh/sshd_config"" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to ""no"":



KerberosAuthentication no



The SSH service must be restarted for changes to take effect.



If Kerberos authentication is required, it must be documented, to include the location of the configuration file, with the ISSO.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000318

The organization audits and reviews activities associated with configuration controlled changes to the system.

NIST SP 800-53 :: CM-3 e

NIST SP 800-53A :: CM-3.1 (v)

NIST SP 800-53 Revision 4 :: CM-3 f



CCI-000368

The organization documents any deviations from the established configuration settings for organization-defined information system components based on organization-defined operational requirements.

NIST SP 800-53 :: CM-6 c

NIST SP 800-53A :: CM-6.1 (v)

NIST SP 800-53 Revision 4 :: CM-6 c



CCI-001812

The information system prohibits user installation of software without explicit privileged status.

NIST SP 800-53 Revision 4 :: CM-11 (2)



CCI-001813

The information system enforces access restrictions.

NIST SP 800-53 Revision 4 :: CM-5 (1)



CCI-001814

The Information system supports auditing of the enforcement actions.

NIST SP 800-53 Revision 4 :: CM-5 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
