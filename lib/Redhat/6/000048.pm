# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000048
#
# VULN ID
#   V-38472
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000259
#
# RULE ID
#   SV-50272r1_rule
#
# STIG ID
#   RHEL-06-000048
#
# RULE TITLE
#   All system command files must be owned by root.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000048;

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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38472';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000259';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50272r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000048';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'All system command files must be owned by root.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
System binaries are executed by privileged users as well as system services, and restrictive permissions are necessary to ensure that their execution of these programs cannot be co-opted.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
System executables are stored in the following directories by default:



/bin

/usr/bin

/usr/local/bin

/sbin

/usr/sbin

/usr/local/sbin



All files in these directories should not be group-writable or world-writable. To find system executables that are not owned by ""root"", run the following command for each directory [DIR] which contains system executables:



$ find -L [DIR] \! -user root





If any system executables are found to not be owned by root, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
System executables are stored in the following directories by default:



/bin

/usr/bin

/usr/local/bin

/sbin

/usr/sbin

/usr/local/sbin



If any file [FILE] in these directories is found to be owned by a user other than root, correct its ownership with the following command:



# chown root [FILE]
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001499

The organization limits privileges to change software resident within software libraries.

NIST SP 800-53 :: CM-5 (6)

NIST SP 800-53A :: CM-5 (6).1

NIST SP 800-53 Revision 4 :: CM-5 (6)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
