#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::Log
#
# DESCRIPTION
#   Handles all logging, stdout and stderr functionality for SCAR
#
# SEE ALSO
#   SCAR
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package SCAR::Log;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard modules
use File::Spec::Functions;

# SCAR modules
use SCAR;

# Module version
our $VERSION = 0.01;

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub new {
    my ( $class, %args ) = @_;
    my $self = bless \%args, $class;

    die "Unable to start '$class': no directory specified\n"
        if !defined $self->{directory};
    die "Unable to start '$class': invalid directory specified\n"
        if !-d $self->{directory};
    die
        "Unable to start '$class': debug mode and quiet mode cannot be enabled at the same time\n"
        if $self->{debug} && $self->{quiet};

    $self->{current}
        = File::Spec::Functions::catdir( $self->{directory}, SCAR->yyyymmdd );
    mkdir $self->{current} unless -d $self->{current};

    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub error {
    my ( $self, $message ) = @_;
    $self->write_to_file( "error.log", $message );
    print SCAR->hhmmss . " ERROR: $message" if !$self->{quiet};
    die "\n";
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub info {
    my ( $self, $message ) = @_;
    $self->write_to_file( "scar.log", $message );
    print SCAR->hhmmss . "  INFO: $message" if !$self->{quiet};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub warn {
    my ( $self, $message ) = @_;
    $self->write_to_file( "scar.log", "Warning: $message" );
    print SCAR->hhmmss . "  WARN: $message" if !$self->{quiet};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub debug {
    my ( $self, $message ) = @_;
    $self->write_to_file( "debug.log", $message );
    print SCAR->hhmmss . " DEBUG: $message" if $self->{debug};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub remediation {
    my ( $self, $message ) = @_;
    $self->write_to_file( "remediations.log", $message );
    print SCAR->hhmmss . " $message" if $self->{debug};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   write_to_file
#
# DESCRIPTION
#   Writes an entry into the specified log file
#
# ARGUMENTS
#   $file       - the log file for writing to
#   $message    - the entry for the log file
#
# ------------------------------------------------------------------------------

sub write_to_file {
    my ( $self, $file, $message ) = @_;
    $file = File::Spec::Functions::catdir( $self->{current}, $file );
    open( my $fh, '>>:encoding(utf8)', $file )
        || die "Could not open file '$file' $!\n";
    print $fh SCAR->hhmmss . ": $message\n";
    close $fh;
}

# ------------------------------------------------------------------------------

1;

__END__
