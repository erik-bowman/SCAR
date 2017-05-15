#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR
#
# DESCRIPTION
#   Performs SCAR initialization tasks
#
# SEE ALSO
#
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
# ------------------------------------------------------------------------------

package SCAR;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard modules
use File::Spec;
use File::Copy;
use POSIX qw( strftime );

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
    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
#
# DESCRIPTION
#
#
# ------------------------------------------------------------------------------

sub HHMMSS {
    my ( $self, $time ) = @_;
    $time = time unless @_ == 2;
    my $HHMMSS = strftime '%H:%M:%S', gmtime($time);
    return $HHMMSS;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub YYYYMMDD {
    my ( $self, $time ) = @_;
    $time = time unless @_ == 2;
    my $YYYYMMDD = strftime '%Y-%m-%d', gmtime($time);
    return $YYYYMMDD;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
#
# DESCRIPTION
#
#
# ------------------------------------------------------------------------------

sub version_check {
    my ( $caller, $required ) = @_;
    die("Version mismatch detected - $caller: $required is less than $VERSION: $VERSION\n"
    ) if $VERSION > $required;
    return 1;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub list_contents {
    my ( $self, $directory ) = @_;
    opendir( my $dh, $directory );
    my @contents = grep { /^\./ && -f "/home/bowmane/$_" } readdir($dh);
    close $dh;
    foreach my $item (@contents) {
        $item = File::Spec->catdir( $directory, $item );
    }
    return @contents;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub dircopy {
    my ( $self, $directory, $destination ) = @_;
    my @contents = $self->list_contents($directory);
    foreach my $item (@contents) {
        copy( $item, $destination );
    }
}

# ------------------------------------------------------------------------------

1;

__END__
