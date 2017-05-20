# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000037
#
# VULN ID
#   V-38448
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50248r1_rule
#
# STIG ID
#   RHEL-06-000037
#
# RULE TITLE
#   The /etc/gshadow file must be group-owned by root.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000037;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# Scar modules
use Scar qw{ get_file_group };
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
    if (get_file_group('/etc/gshadow') ne 'root') {
        $self->_set_finding_status('NF');
    }
    else {
        $self->_set_finding_status('O');
    }
    return $self;
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
    return 'V-38448';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50248r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000037';
}

sub get_rule_title {
    return 'The /etc/gshadow file must be group-owned by root.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ""/etc/gshadow"" file contains group password hashes. Protection of this file is critical for system security.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check the group ownership of ""/etc/gshadow"", run the command:



$ ls -l /etc/gshadow



If properly configured, the output should indicate the following group-owner. ""root""

If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To properly set the group owner of ""/etc/gshadow"", run the command:



# chgrp root /etc/gshadow
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
