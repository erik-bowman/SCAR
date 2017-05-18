# ------------------------------------------------------------------------------
# NAME
#   Scar::RHEL7
#
# DESCRIPTION
#   Performs Scar initialization tasks specific to Red Hat 7
#
# SEE ALSO
#   Scar Scar::RHEL
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7;

# Standard modules
use utf8;
use strict;
use Carp qw( croak );
use warnings FATAL => 'all';

# Scar modules
use Scar;
use Scar::Util::Log;

# Module version
our $VERSION = 0.01;

sub new {
    my ($class) = @_;
    my $self = bless {}, $class;
    return $self;
}

1;

__END__
