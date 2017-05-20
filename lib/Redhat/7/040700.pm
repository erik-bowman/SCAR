# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040700
#
# VULN ID
#   V-72301
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86925r1_rule
#
# STIG ID
#   RHEL-07-040700
#
# RULE TITLE
#   The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for operational support.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040700;

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
    return 'V-72301';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86925r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040700';
}

sub get_rule_title {
    return
        'The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for operational support.';
}

sub get_discussion {
    return <<'DISCUSSION';
If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Officer (ISSO), restricted to only authorized personnel, and have access control rules established.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify a TFTP server has not been installed on the system.



Check to see if a TFTP server has been installed with the following command:



# yum list installed tftp-server

tftp-server-0.49-9.el7.x86_64.rpm



If TFTP is installed and the requirement for TFTP is not documented with the ISSO, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Remove the TFTP package from the system with the following command:



# yum remove tftp
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
