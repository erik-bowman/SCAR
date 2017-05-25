package Scar::Users;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use Carp qw{ croak };
use English qw{ -no_matched_vars };

sub new {
    my ($class) = @ARG;
    my $self = bless {}, $class;

    while (
        my ( $name, $passwd, $uid, $gid, $quota, $comment, $gcos, $dir,
            $shell ) = getpwent )
    {
        $self->{$name}->{passwd}  = $passwd;
        $self->{$name}->{uid}     = $uid;
        $self->{$name}->{gid}     = $gid;
        $self->{$name}->{quota}   = $quota;
        $self->{$name}->{comment} = $comment;
        $self->{$name}->{gcos}    = $gcos;
        $self->{$name}->{dir}     = $dir;
        $self->{$name}->{shell}   = $shell;
    }
    return $self;
}

1;

__END__
