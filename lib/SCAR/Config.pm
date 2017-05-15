#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::Config
#
# DESCRIPTION
#
#
# SEE ALSO
#
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
# ------------------------------------------------------------------------------

package SCAR::Config;

# Standard pragmas
use strict;
use warnings FATAL => 'all';

# Module version
our $VERSION = '2.23';

BEGIN {
    require 5.008001;
    $SCAR::Config::errstr = '';
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub new { return bless {}, shift }

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub read {
    my ( $class, $file, $encoding ) = @_;

    return $class->_error('No file name provided')
        if ( !defined $file || ( $file eq '' ) );

    $encoding = $encoding ? "<:$encoding" : '<';
    local $/ = undef;

    open( CFG, $encoding, $file )
        or
        return $class->_error("Failed to open file '$file' for reading: $!");
    my $contents = <CFG>;
    close(CFG);

    return $class->_error("Reading from '$file' returned undef")
        if ( !defined $contents );

    return $class->read_string($contents);

}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub read_string {
    my ($class) = ref $_[0] ? ref shift : shift;
    my ($self) = bless {}, $class;

    return undef unless defined $_[0];

    my $ns      = '_';
    my $counter = 0;

    foreach ( split /(?:\015{1,2}\012|\015|\012)/, shift ) {
        $counter++;

        next if /^\s*(?:\#|\;|$)/;

        s/\s\;\s.+$//g;

        if (/^\s*\[\s*(.+?)\s*\]\s*$/) {

            $self->{ $ns = $1 } ||= {};

            next;
        }

        if (/^\s*([^=]+?)\s*=\s*(.*?)\s*$/) {
            $self->{$ns}->{$1} = $2;

            next;
        }

        return $self->_error("Syntax error at line $counter: '$_'");
    }

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

sub write {
    my ($self) = shift;
    my ( $file, $encoding ) = @_;

    return $self->_error('No file name provided')
        if ( !defined $file or ( $file eq '' ) );

    $encoding = $encoding ? ">:$encoding" : '>';

    my ($string) = $self->write_string;

    return undef unless defined $string;

    open( CFG, $encoding, $file )
        or
        return $self->_error("Failed to open file '$file' for writing: $!");
    print CFG $string;
    close CFG;

    return 1;

}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub write_string {
    my ($self)     = shift;
    my ($contents) = '';

    for my $section (
        sort { ( ( $b eq '_' ) <=> ( $a eq '_' ) ) || ( $a cmp $b ) }
        keys %$self
        )
    {

        return $self->_error("Illegal whitespace in section name '$section'")
            if $section =~ /(?:^\s|\n|\s$)/s;

        my $block = $self->{$section};
        $contents .= "\n" if length $contents;
        $contents .= "[$section]\n" unless $section eq '_';

        for my $property ( sort keys %$block ) {
            return $self->_error(
                "Illegal newlines in property '$section.$property'")
                if $block->{$property} =~ /(?:\012|\015)/s;

            $contents .= "$property=$block->{$property}\n";
        }
    }

    return $contents;

}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub errstr {$SCAR::Config::errstr}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub _error { $SCAR::Config::errstr = $_[1]; undef }

# ------------------------------------------------------------------------------

1;

__END__
