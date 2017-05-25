package Scar::File;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use Carp qw{ croak };
use English qw{ -no_match_vars };

# Modules Hierarchy
use base qw{ Exporter };

our $VERSION = 1.40;

our @EXPORT = qw{
    read_file get_file_owner get_file_group get_file_permissions
};

sub read_file {
    my ( $file, $encoding ) = @_;
    my @file_contents;
    $encoding = $encoding ? "<:$encoding" : '<';

    open my $filehandle, $encoding, $file or croak "$OS_ERROR";
    while ( my $line = <$filehandle> ) {
        chomp $line;
        push @file_contents, $line;
    }
    close $filehandle;

    return @file_contents;
}

sub get_file_owner {
    my ($file) = @_;
    return ( stat $file or croak "$OS_ERROR" )[4];
}

sub get_file_group {
    my ($file) = @_;
    return ( stat $file or croak "$OS_ERROR" )[5];
}

sub get_file_permissions {
    my ($file) = @_;
    my $file_permissions = ( stat $file or croak "$OS_ERROR" )[2];
    return sprintf '%04o', Fcntl::S_IMODE($file_permissions);
}

1;
