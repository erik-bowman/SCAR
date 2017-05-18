#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::RHEL6
#
# DESCRIPTION
#   Performs SCAR initialization tasks specific to Red Hat 6
#
# SEE ALSO
#   SCAR SCAR::RHEL
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package SCAR::RHEL6;

# Standard modules
use utf8;
use strict;
use Carp qw( croak );
use warnings FATAL => 'all';

# SCAR modules
use SCAR qw( AWK SERVICE CHKCONFIG );
use SCAR::Log;

# Module version
our $VERSION = 0.01;

sub new {
    my ($class) = @_;
    my $self = bless {}, $class;

    my @CHKCONFIG = CHKCONFIG('--list');
    $self->services(@CHKCONFIG);

    my @FSTAB = AWK(q<'/^[^#]/ { print $ 0}' /etc/fstab>);
    $self->filesystem_table(@FSTAB);

    return $self;
}

sub services {
    my ( $self, @CHKCONFIG ) = @_;

    foreach my $ENTRY (@CHKCONFIG) {
        my @PROPERTIES = split /[:\s]+/msx, $ENTRY;
        my $SERVICE = $self->service_properties(@PROPERTIES);
        $self->{service}->{$SERVICE}->{status} = SERVICE("$SERVICE status");
    }

    return $self;
}

sub service_properties {
    my ( $self, @PROPERTIES ) = @_;
    my $SERVICE = shift @PROPERTIES;

    while (@PROPERTIES) {
        my $RUNLEVEL = shift @PROPERTIES;
        my $VALUE    = shift @PROPERTIES;
        $self->{service}->{$SERVICE}->{$RUNLEVEL} = $VALUE;
    }

    return $SERVICE;
}

sub filesystem_table {
    my ( $self, @FSTAB ) = @_;

    foreach my $ENTRY (@FSTAB) {
        my @MOUNTS = split /\s+/msx, $ENTRY;
        my ( $DEVICE, $DIRECTORY, $TYPE, $OPTIONS, $DUMP, $FSCK ) = @MOUNTS;
        $self->{fstab}->{$DIRECTORY} = {
            device  => $DEVICE,
            type    => $TYPE,
            options => $OPTIONS,
            dump    => $DUMP,
            fsck    => $FSCK,
        };
    }

    return $self;
}

1;

__END__
