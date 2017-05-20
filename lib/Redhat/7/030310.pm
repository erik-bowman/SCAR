# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030310
#
# VULN ID
#   V-72085
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000342-GPOS-00133
#
# RULE ID
#   SV-86709r1_rule
#
# STIG ID
#   RHEL-07-030310
#
# RULE TITLE
#   The operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030310;

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
    return 'V-72085';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000342-GPOS-00133';
}

sub get_rule_id {
    return 'SV-86709r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-030310';
}

sub get_rule_title {
    return
        'The operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited.';
}

sub get_discussion {
    return <<'DISCUSSION';
Information stored in one location is vulnerable to accidental or incidental deletion or alteration.



Off-loading is a common process in information systems with limited audit storage capacity.



Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system encrypts audit records off-loaded onto a different system or media from the system being audited.



To determine if the transfer is encrypted, use the following command:



# grep -i enable_krb5 /etc/audisp/audisp-remote.conf

enable_krb5 = yes



If the value of the ""enable_krb5"" option is not set to ""yes"" or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.



If there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to encrypt the transfer of off-loaded audit records onto a different system or media from the system being audited.



Uncomment the ""enable_krb5"" option in ""/etc/audisp/audisp-remote.conf"" and set it with the following line:



enable_krb5 = yes
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001851

The information system off-loads audit records per organization-defined frequency onto a different system or media than the system being audited.

NIST SP 800-53 Revision 4 :: AU-4 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
