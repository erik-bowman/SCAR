# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000231
#
# VULN ID
#   V-38610
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000126
#
# RULE ID
#   SV-50411r1_rule
#
# STIG ID
#   RHEL-06-000231
#
# RULE TITLE
#   The SSH daemon must set a timeout count on idle sessions.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000231;

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
    if ( parse_file( '^ClientAliveCountMax\W+0$', '/etc/ssh/sshd_config' ) ) {
        $self->{STATUS} = 'NF';
    }
    else {
        $self->{STATUS} = 'O';
    }
    return $self;
}

sub remediate {
    my ($self) = @_;

    return $self;
}

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38610';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000126';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50411r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000231';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The SSH daemon must set a timeout count on idle sessions.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
This ensures a user login will be terminated as soon as the ""ClientAliveCountMax"" is reached.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To ensure the SSH idle timeout will occur when the ""ClientAliveCountMax"" is set, run the following command:



# grep ClientAliveCountMax /etc/ssh/sshd_config



If properly configured, output should be:



ClientAliveCountMax 0





If it is not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To ensure the SSH idle timeout occurs precisely when the ""ClientAliveCountMax"" is set, edit ""/etc/ssh/sshd_config"" as follows:



ClientAliveCountMax 0
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000879

The organization terminates sessions and network connections when nonlocal maintenance is completed.

NIST SP 800-53 :: MA-4 e

NIST SP 800-53A :: MA-4.1 (vi)

NIST SP 800-53 Revision 4 :: MA-4 e




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
