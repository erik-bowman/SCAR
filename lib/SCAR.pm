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

# Standard modules
use utf8;
use strict;
use Carp qw( croak );
use base qw( Exporter );
use POSIX qw( strftime );
use File::Spec::Functions;
use warnings FATAL => 'all';

# Module version
our $VERSION = 0.01;

# Default exports
our @EXPORT = qw( AWK IMPLODEPATH EXPLODEPATH HHMMSS YYYYMMDD );

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub IMPLODEPATH {
    my @PARTS = @_;
    return File::Spec::Functions::catdir(@PARTS);
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub EXPLODEPATH {
    my @PARTS = @_;
    return File::Spec::Functions::splitpath(@PARTS);
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub HHMMSS {
    return strftime '%H:%M:%S', gmtime;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub YYYYMMDD {
    return strftime '%Y-%m-%d', gmtime;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub AWK {
    my ($CODE, $FILE) = @_;
    my @RESULTS;
    open my $AWK, " /bin/awk '$CODE' $FILE 2>&1 |" or croak 'Could not run awk';
    {
        while (my $RESULT = <$AWK>) {
            push @RESULTS, $RESULT;
        }
    }
    close $AWK;
    return @RESULTS;
}

# ------------------------------------------------------------------------------

1;

__END__
