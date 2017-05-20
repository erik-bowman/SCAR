# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040300
#
# VULN ID
#   V-72233
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000423-GPOS-00187
#
# RULE ID
#   SV-86857r1_rule
#
# STIG ID
#   RHEL-07-040300
#
# RULE TITLE
#   All networked systems must have SSH installed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040300;

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
    return 'V-72233';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000423-GPOS-00187';
}

sub get_rule_id {
    return 'SV-86857r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040300';
}

sub get_rule_title {
    return 'All networked systems must have SSH installed.';
}

sub get_discussion {
    return <<'DISCUSSION';
Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.



This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.



Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa.



Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000424-GPOS-00188, SRG-OS-000425-GPOS-00189, SRG-OS-000426-GPOS-00190
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Check to see if sshd is installed with the following command:



# yum list installed ssh

libssh2.x86_64                           1.4.3-8.el7               @anaconda/7.1

openssh.x86_64                           6.6.1p1-11.el7            @anaconda/7.1

openssh-clients.x86_64                   6.6.1p1-11.el7            @anaconda/7.1

openssh-server.x86_64                    6.6.1p1-11.el7            @anaconda/7.1



If the ""SSH server"" package is not installed, this is a finding.



If the ""SSH client"" package is not installed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Install SSH packages onto the host with the following commands:



# yum install openssh-clients.x86_64

# yum install openssh-server.x86_64



Note: 32-bit versions will require different packages.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-002418

The information system protects the confidentiality and/or integrity of transmitted information.

NIST SP 800-53 Revision 4 :: SC-8



CCI-002420

The information system maintains the confidentiality and/or integrity of information during preparation for transmission.

NIST SP 800-53 Revision 4 :: SC-8 (2)



CCI-002421

The information system implements cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by organization-defined alternative physical safeguards.

NIST SP 800-53 Revision 4 :: SC-8 (1)



CCI-002422

The information system maintains the confidentiality and/or integrity of information during reception.

NIST SP 800-53 Revision 4 :: SC-8 (2)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
