package Redhat;

=comment

Perl Core Pragmas

=cut

use utf8;
use strict;
use warnings FATAL => 'all';

=comment

Perl Core Modules

=cut

use Carp qw{ croak };
use English qw{ -no_matched_vars };

=comment

Scar Local Modules

=cut

use Redhat::sysctl;
use Scar::Loader
    require     => 1,
    sub_name    => 'load_high_severity',
    search_path => ['Redhat::6::High'];
use Scar::Loader
    require     => 1,
    sub_name    => 'load_medium_severity',
    search_path => ['Redhat::6::Medium'];
use Scar::Loader
    require     => 1,
    sub_name    => 'load_low_severity',
    search_path => ['Redhat::6::Low'];
use Scar::Loader
    require     => 1,
    sub_name    => 'load_all',
    search_path => ['Redhat::6'];

=comment

Module Version

=cut

our $VERSION = 1.4.0;

=comment

Module Constructor

=cut

#@method
#@returns Redhat
sub new {
    my ( $class ) = @ARG;

    my $self = bless {}, $class;

    #@type Redhat::sysctl;
    our $sysctl = Redhat::sysctl->new();

    return $self;
}

1;

__END__
