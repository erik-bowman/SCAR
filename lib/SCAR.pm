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
use POSIX;

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
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub list_contents {
    my ( $self, $directory ) = @_;

    die "Unable to list contents for '$directory': not a valid directory\n"
        if !-d $directory;
    opendir( my $dh, $directory );
    my @contents = grep { -f File::Spec::Functions::catdir( $directory, $_ ) }
        readdir($dh);
    close $dh;

    foreach my $item (@contents) {
        $item = File::Spec::Functions::catdir( $directory, $item );
    }

    return @contents;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   does_file_exist
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub does_file_exist {
    my ( $self, $file ) = @_;
    return -f $file;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   does_directory_exist
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub does_directory_exist {
    my ( $self, $directory ) = @_;
    return -d $directory;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   hhmmss
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub hhmmss {
    return POSIX::strftime '%H:%M:%S', gmtime();
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   hhmmss
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub yyyymmdd {
    return POSIX::strftime '%Y-%m-%d', gmtime();
}

# ------------------------------------------------------------------------------

1;

__END__
