# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000035
#
# VULN ID
#   V-38504
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50305r1_rule
#
# STIG ID
#   RHEL-06-000035
#
# RULE TITLE
#   The /etc/shadow file must have mode 0000.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000035;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# Scar modules
use Scar qw{ get_file_permissions };
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
    if ( get_file_permissions('/etc/shadow') eq '0000' ) {
        $self->_set_finding_status('NF');
    }
    if ( !defined $self->get_finding_status() ) {
        $self->_set_finding_status('O');
    }
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
    return 'V-38504';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50305r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000035';
}

sub get_rule_title {
    return 'The /etc/shadow file must have mode 0000.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ""/etc/shadow"" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check the permissions of ""/etc/shadow"", run the command:



$ ls -l /etc/shadow



If properly configured, the output should indicate the following permissions: ""----------""

If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To properly set the permissions of ""/etc/shadow"", run the command:



# chmod 0000 /etc/shadow
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
