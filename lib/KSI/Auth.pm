package KSI::Auth;

use v5.36;
use strict;
use warnings;
use Exporter 'import';
use MIME::Base64 qw(encode_base64);
use POSIX qw(strftime);
our @EXPORT_OK = qw(hash_password check_password new_token utc_after);

sub hash_password ($password) {
    my $salt = encode_base64(_random_bytes(16), '');
    $salt =~ tr{+/}{./};
    $salt = substr($salt, 0, 22);
    my $hash = crypt($password, '$2b$12$' . $salt);
    die 'bcrypt is unavailable in this Perl runtime' unless $hash =~ /^\$2[aby]\$12\$/;
    return $hash;
}

sub check_password ($password, $hash) {
    return 0 unless defined $hash && $hash =~ /^\$2[aby]\$\d\d\$/;
    my $candidate = crypt($password, $hash);
    return 0 unless length($candidate) == length($hash);
    my $diff = 0;
    $diff |= ord(substr($candidate, $_, 1)) ^ ord(substr($hash, $_, 1)) for 0 .. length($hash) - 1;
    return $diff == 0;
}

sub new_token ($bytes = 40) {
    my $token = encode_base64(_random_bytes($bytes), '');
    $token =~ tr{+/}{-_};
    $token =~ s/=+\z//;
    return $token;
}

sub utc_after ($seconds) {
    return strftime('%Y-%m-%d %H:%M:%S', gmtime(time + $seconds));
}

sub _random_bytes ($length) {
    open my $fh, '<:raw', '/dev/urandom' or die 'Cannot open secure random source';
    my $bytes;
    my $read = read $fh, $bytes, $length;
    close $fh;
    die 'Cannot read secure random source' unless defined $read && $read == $length;
    return $bytes;
}

1;
