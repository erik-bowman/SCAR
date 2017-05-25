package Scar::File::auditd_conf;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use Carp qw{ croak };
use English qw{ -no_matched_vars };

# Local Modules
use Scar::File;
use Scar::Util::Log;

sub new {
    my ($class) = @ARG;
    my $self = bless {}, $class;

    log_info('Reading /etc/audit/auditd.conf');

    my @keywords = qw{
        log_file log_format flush
        freq num_logs max_log_file
        max_log_file_action space_left
        action_mail_acct space_left_action
        admin_space_left admin_space_left_action
        disk_full_action disk_error_action
    };

    my @file_entries = read_file('/etc/audit/auditd.conf');

    foreach my $keyword (@keywords) {

        foreach my $file_entry (@file_entries) {
            chomp $file_entry;
            if ( $file_entry =~ /^($keyword)[= ]{1,3}(.*)$/msx ) {
                push @{ $self->{$1} }, $2;
            }

        }

    }

    log_info('Done reading /etc/audit/auditd.conf');
    return $self;
}

1;

__END__
