# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000013
#
# VULN ID
#   V-38483
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000103
#
# RULE ID
#   SV-50283r1_rule
#
# STIG ID
#   RHEL-06-000013
#
# RULE TITLE
#   The system package management tool must cryptographically verify the authenticity of system software packages during installation.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000013;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# Scar modules
use Scar qw( parse_file );
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
    if ( ingest_file( '/etc/yum.conf', 'gpgcheck\s*=\s*1' ) ) {
        $self->_set_finding_status('NF');
    }
    else {
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
    return 'V-38483';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000103';
}

sub get_rule_id {
    return 'SV-50283r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000013';
}

sub get_rule_title {
    return
        'The system package management tool must cryptographically verify the authenticity of system software packages during installation.';
}

sub get_discussion {
    return <<'DISCUSSION';
Ensuring the validity of packages' cryptographic signatures prior to installation ensures the provenance of the software and protects against malicious tampering.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine whether ""yum"" is configured to use ""gpgcheck"", inspect ""/etc/yum.conf"" and ensure the following appears in the ""[main]"" section:



gpgcheck=1



A value of ""1"" indicates that ""gpgcheck"" is enabled. Absence of a ""gpgcheck"" line or a setting of ""0"" indicates that it is disabled.

If GPG checking is not enabled, this is a finding.



If the ""yum"" system package management tool is not used to update the system, verify with the SA that installed packages are cryptographically signed.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""gpgcheck"" option should be used to ensure checking of an RPM package's signature always occurs prior to its installation. To configure yum to check package signatures before installing them, ensure the following line appears in ""/etc/yum.conf"" in the ""[main]"" section:



gpgcheck=1
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000663

The organization (or information system) enforces explicit rules governing the installation of software by users.

NIST SP 800-53 :: SA-7

NIST SP 800-53A :: SA-7.1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
