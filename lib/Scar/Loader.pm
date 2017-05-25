package Scar::Loader;

use strict;
use vars qw($VERSION $FORCE_SEARCH_ALL_PATHS);
use Scar::Loader::Plugin;

use if $] > 5.017, 'deprecate';

$VERSION                = '5.2';
$FORCE_SEARCH_ALL_PATHS = 0;

sub import {
    my $class = shift;
    my %opts  = @_;

    my ( $pkg, $file ) = caller;
    my $sub = $opts{'sub_name'} || 'plugins';
    my ($package) = $opts{'package'} || $pkg;
    $opts{filename}               = $file;
    $opts{package}                = $package;
    $opts{force_search_all_paths} = $FORCE_SEARCH_ALL_PATHS
        unless exists $opts{force_search_all_paths};

    #@type Scar::Loader::Plugin
    my $finder     = Scar::Loader::Plugin->new(%opts);
    my $subroutine = sub {
        my $self = shift;
        return $finder->plugins(@_);
    };

    my $searchsub = sub {
        my $self = shift;
        my ( $action, @paths ) = @_;

        $finder->{'search_path'} = ["${package}::Plugin"]
            if $action eq 'add' and not $finder->{'search_path'};
        push @{ $finder->{'search_path'} }, @paths if $action eq 'add';
        $finder->{'search_path'} = \@paths if $action eq 'new';
        return $finder->{'search_path'};
    };

    my $onlysub = sub {
        my ( $self, $only ) = @_;

        if ( defined $only ) {
            $finder->{'only'} = $only;
        }

        return $finder->{'only'};
    };

    my $exceptsub = sub {
        my ( $self, $except ) = @_;

        if ( defined $except ) {
            $finder->{'except'} = $except;
        }

        return $finder->{'except'};
    };

    no strict 'refs';
    no warnings qw(redefine prototype);

    *{"$package\::$sub"}        = $subroutine;
    *{"$package\::search_path"} = $searchsub;
    *{"$package\::only"}        = $onlysub;
    *{"$package\::except"}      = $exceptsub;

}

1;

__END__
