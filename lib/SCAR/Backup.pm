#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::Backup
#
# DESCRIPTION
#
#
# SEE ALSO
#
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package SCAR::Backup;

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

    $self->{current}
        = File::Spec::Functions::catdir( $self->{directory}, SCAR->yyyymmdd );
    mkdir $self->{current} unless -d $self->{current};

    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   create
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub create {
    my ( $self, $file ) = @_;
    my @path_info = File::Spec::Functions::splitpath($file);
    my $backup_file
        = File::Spec::Functions::catdir( $self->{current}, $path_info[2] );
    return 1 if -f $backup_file;
    open( my $input, "<:raw", $file )
        || die "Unable to open '$file': $!\n";
    open( my $output, ">:raw", $backup_file )
        || die "Unable to open '$backup_file': $!\n";
    while (<$input>) {
        print $output $_;
    }
    close $input;
    close $output;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   check_backup
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub check_backup {
    my ( $self, $file ) = @_;
    my @path_info = File::Spec::Functions::splitpath($file);
    my $backup_file
        = File::Spec::Functions::catdir( $self->{current}, $path_info[2] );
    return -f $backup_file;
}

# ------------------------------------------------------------------------------

1;

__END__
