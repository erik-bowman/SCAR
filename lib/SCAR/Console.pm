#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   SCAR::Console
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

package SCAR::Console;

# Standard pragmas
use strict;
use warnings FATAL => 'all';

# Standard modules
use Data::Dumper;
use Term::ANSIColor;
use Time::HiRes qw(usleep);
use POSIX qw(strftime floor);

our $VERSION = 0.01;
$| = 1;

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
    my $self = \%args;
    my $first_expression
        = '(?:\s*|static)\s+(?:char|short)?\s+(?:\*\s+|\s+)?(.*?)\s*\[\]\s*=\s*';
    my $second_expression = '\s*\/\*\s+\d+:\s+(.*?)\s+\*\/';
    open( STATUS, "infocmp -E 2>&1 |" ) || die "can't fork: $!";
    {
        while (<STATUS>) {
            s/^$first_expression"(.*)";$/\$self->{xterm_string_data}->\{$1\} = '$2';/g;
            s/^$second_expression\s+TRUE,$/\$self->{xterm_bool_data}->\{$1\} = 1;/g;
            s/^$second_expression\s+FALSE,$/\$self->{xterm_bool_data}->\{$1\} = 0;/g;
            s/^$second_expression\s+ABSENT_NUMERIC,$/\$self->{xterm_number_data}->\{$1\} = '';/g;
            s/^$second_expression\s+ABSENT_STRING,$/\$self->\{$1\} = '';/g;
            s/^$second_expression\s+(\d+),$/\$self->{xterm_number_data}->\{$1\} = $2;/g;
            s/^\s*\/\*\s+\d+:\s+(.*?)\s+\*\/\s+(.*?),$/\$self->\{$1\} = \$self->{xterm_string_data}->\{$2\};/g;
            s/^$first_expression.\{$//g;
            s/^};//g;
            eval;
        }
    }
    close STATUS || die "bad command: $! $?";
    $self = bless $self, $class;

    $self->max_x unless defined $self->{max_x};
    $self->max_y unless defined $self->{max_y};
    $self->min_x unless defined $self->{min_x};
    $self->min_y unless defined $self->{min_y};
    (   $self->{sysname}, $self->{nodename}, $self->{release},
        $self->{version}, $self->{machine}
    ) = POSIX::uname();


    open( my $fh, '<', '/proc/cpuinfo' ) || die("Couldn't open file '/proc/cpuinfo': $!\n");
    while (my $line = <$fh>) {
        chomp $line;
        if ($line =~ /model\s+name\s+:\s+(.*)/) {
            $self->{component}->{cpu_model} = $1;
        }
    }
    close $fh;
    print Dumper($self);

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

sub min_x {
    my ($self) = @_;
    $self->{min_x} = $self->{xterm_number_data}->{cols}
        if $self->{xterm_number_data}->{cols};
    return $self->{min_x};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub min_y {
    my ($self) = @_;
    $self->{min_y} = $self->{xterm_number_data}->{lines}
        if $self->{xterm_number_data}->{lines};
    return $self->{min_y};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub max_x {
    my ($self) = @_;
    $self->{max_x} = `tput cols`;
    chomp $self->{max_x};
    return $self->{max_x};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub max_y {
    my ($self) = @_;
    $self->{max_y} = `tput lines`;
    chomp $self->{max_y};
    return $self->{max_y};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub render {
    my ($self) = @_;

}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub flash {
    my ( $self, $delay_ms ) = @_;
    return 0 unless defined $self->{flash};
    my ( $first_seq, $delay, $second_seq ) = ( $1, $2, $3 )
        if $self->{flash} =~ /(.*)(?:\$<(\d+).*>)(.*)/;
    if ( @_ == 2 ) {
        $delay = $delay_ms;
    }
    system( 'echo -en "' . $first_seq . '"' );
    usleep $delay;
    system( 'echo -en "' . $second_seq . '"' );
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

sub hide_cursor {
    my ($self) = @_;
    if ( defined $self->{civis} ) {
        system( 'echo -en "' . $self->{civis} . '"' );
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

sub show_cursor {
    my ($self) = @_;
    if ( defined $self->{cvvis} ) {
        system( 'echo -en "' . $self->{cvvis} . '"' );
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

sub move_cursor {
    my ( $self, $x, $y ) = @_;
    if ( defined $self->{cup} ) {
        my $sequence = $self->format_sequence( $self->{cup}, $x, $y );
        system( 'echo -en "' . $sequence . '"' );
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

sub insert_cursor {
    my ( $self, $insert ) = @_;
    my $sequence = $self->format_sequence( $self->{cub}, $insert );
    system( 'echo -en "' . $sequence . '"' );
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub draw_pos {
    my ( $self, $x, $y ) = @_;
    $self->move_cursor( $x, $y );
    $self->insert_cursor( $self->{screen}->{matrix}[$x][$y] );
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub format_sequence {
    my $self     = shift;
    my $sequence = shift;
    my $regex    = qr/
        (%
            (\S)
            (\d+)?
            )
        /x;
    my @to_fmt;

    if ( $sequence =~ /\\(033)/ ) {
        my $hex = sprintf "%x", $1;
        $sequence =~ s/(033)/\\x$hex/g;
    }
    while ( $sequence =~ m{\G(.*?)$regex}gs ) {
        if ( $2 eq '%i' ) {
            $_[0]++;
            $_[1]++;
            $sequence =~ s/^\\(.*?)$2/$1/;
        }
        if ( $3 eq 'p' ) {
            my $string = shift @_;
            unshift @to_fmt, $string;
            $sequence =~ s/^(.*?)$2/$1/;
        }
        if ( $2 eq '%d' ) {
            my $string = shift @to_fmt;
            $sequence =~ s/^(.*?)$2/$1$string/;
        }
    }
    return $sequence;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------i

sub component_refresh {
    my ($self) = @_;
    open( STATUS, "uptime 2>&1 |" ) || die "can't fork: $!";
    {
        $self->{component}->{uptime} = <STATUS>;
    }
    close STATUS || die "bad command: $! $?";

    open( STATUS,
        "awk '/^(Mem|Swap)(Total|Free)/ { print \$1 \$2 };' /proc/meminfo 2>&1 |"
    ) || die "can't fork: $!";
    {
        while ( my $cmd = <STATUS> ) {
            chomp $cmd;
            if ( $cmd =~ /^(\S+):(\d+)/ ) {
                $self->{component}->{$1} = $2;
            }
        }
    }
    close STATUS || die "bad command: $! $?";

    my $regex = qr|
        (\d\d:\d\d:\d\d)\s+
        (up.*?\d\d:\d\d),\s+
        .*?,\s+load\saverage:\s+
        (\d\.\d\d),\s+
        (\d\.\d\d),\s+
        (\d\.\d\d)
    |x;

    if ( $self->{component}->{uptime} =~ /$regex/ ) {
        $self->{component}->{uptime}       = "Uptime: $2";
        $self->{component}->{current_time} = $1;
        $self->{component}->{load_avg_1}   = $3;
        $self->{component}->{load_avg_5}   = $4;
        $self->{component}->{load_avg_15}  = $5;
    }

}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub component_header_frame {
    my ($self) = @_;
    my $FRAME = <<'HEADER';
uname ( $self->{sysname}, $self->{nodename}, $self->{release}, $self->{version}, $self->{machine} ) $self->{component}->{uptime}


HEADER

}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub component_scoreboard_frame {
    my ($self) = @_;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub component_message_frame {
    my ($self) = @_;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub component_error_frame {
    my ($self) = @_;
}

# ------------------------------------------------------------------------------

1;

__END__
