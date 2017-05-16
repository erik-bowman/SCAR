#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   TEST1
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

package TEST1;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Module version
our $VERSION = 1.40;

# ------------------------------------------------------------------------------
# SYNOPSIS
#   new
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub new {
    my ( $class, $imports ) = @_;
    print Data::Dumper::Dumper($imports);
    $imports->callback;
    print "Initialization completed\n";
    return bless {}, $class;
}

# ------------------------------------------------------------------------------

1;

__END__
