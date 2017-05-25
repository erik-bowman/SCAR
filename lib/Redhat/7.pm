package Redhat::7;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use Carp qw( croak );
use English qw{ -no_match_vars };

# Local Modules
use Scar::Loader
    require     => 1,
    search_path => [ 'Redhat::7' ],
    sub_name    => 'get_redhat7_plugins';
use Scar::Util::Log;

# Module Hierarchy
use base qw( Redhat );

# Module version
our $VERSION = 1.40;

sub new {
    my ($class) = @ARG;
    my $self = bless {}, $class;
    return $self;
}

1;

__END__
