# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000015
#
# VULN ID
#   V-38487
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000103
#
# RULE ID
#   SV-50288r1_rule
#
# STIG ID
#   RHEL-06-000015
#
# RULE TITLE
#   The system package management tool must cryptographically verify the authenticity of all software packages during installation.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000015;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use Carp qw{ croak };
use English qw{ -no_matched_vars };

# Local Modules
use Scar::Commands;

# Plugin Version
our $VERSION = 0.01;

sub new {
    my ($class) = @ARG;
    my $self = bless {}, $class;

    return $self;
}

sub check {
    my ($self) = @ARG;
    print run_grep('"gpgcheck=0" /etc/yum.repos.d/*') . "\n";
    if ( run_grep('"gpgcheck=0" /etc/yum.repos.d/*') > 0 ) {
        $self->_set_finding_status('O');
    }
    if ( !defined $self->get_finding_status() ) {
        $self->_set_finding_status('NF');
    }
    return $self;
}

sub remediate {
    my ($self) = @ARG;

    return $self;
}

sub _set_finding_status {
    print @ARG;
    my ( $self, $finding_status ) = @ARG;
    $self->{finding_status} = $finding_status;
    return $self->{finding_status};
}

sub get_finding_status {
    my ($self) = @ARG;
    return $self->{finding_status};
}

sub get_vuln_id {
    return 'V-38487';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000103';
}

sub get_rule_id {
    return 'SV-50288r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000015';
}

sub get_rule_title {
    return
        'The system package management tool must cryptographically verify the authenticity of all software packages during installation.';
}

sub get_discussion {
    return <<'DISCUSSION';
Ensuring all packages' cryptographic signatures are valid prior to installation ensures the provenance of the software and protects against malicious tampering.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine whether ""yum"" has been configured to disable ""gpgcheck"" for any repos, inspect all files in ""/etc/yum.repos.d"" and ensure the following does not appear in any sections:



gpgcheck=0



A value of ""0"" indicates that ""gpgcheck"" has been disabled for that repo.

If GPG checking is disabled, this is a finding.



If the ""yum"" system package management tool is not used to update the system, verify with the SA that installed packages are cryptographically signed.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To ensure signature checking is not disabled for any repos, remove any lines from files in ""/etc/yum.repos.d"" of the form:



gpgcheck=0
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

1;

__END__
