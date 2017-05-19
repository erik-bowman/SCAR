# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000503
#
# VULN ID
#   V-38490
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000273
#
# RULE ID
#   SV-50291r5_rule
#
# STIG ID
#   RHEL-06-000503
#
# RULE TITLE
#   The operating system must enforce requirements for the connection of mobile devices to operating systems.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000503;

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
    $self->{VULN_ID} = 'V-38490';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000273';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50291r5_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000503';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must enforce requirements for the connection of mobile devices to operating systems.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
USB storage devices such as thumb drives can be used to introduce unauthorized software and other vulnerabilities. Support for these devices should be disabled and the devices themselves should be tightly controlled.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If the system is configured to prevent the loading of the ""usb-storage"" kernel module, it will contain lines inside any file in ""/etc/modprobe.d"" or the deprecated""/etc/modprobe.conf"". These lines instruct the module loading system to run another program (such as ""/bin/true"") upon a module ""install"" event. Run the following command to search for such lines in all files in ""/etc/modprobe.d"" and the deprecated ""/etc/modprobe.conf"":



$ grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d | grep -i ""/bin/true""



If no line is returned, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To prevent USB storage devices from being used, configure the kernel module loading system to prevent automatic loading of the USB storage driver. To configure the system to prevent the ""usb-storage"" kernel module from being loaded, add the following line to a file in the directory ""/etc/modprobe.d"":



install usb-storage /bin/true



This will prevent the ""modprobe"" program from loading the ""usb-storage"" module, but will not prevent an administrator (or another program) from using the ""insmod"" program to load the module manually.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000086

The organization enforces requirements for the connection of mobile devices to organizational information systems.

NIST SP 800-53 :: AC-19 d

NIST SP 800-53A :: AC-19.1 (iv)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
