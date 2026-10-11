use v5.36;
use strict;
use warnings;
use Test::More;
use Test::Mojo;
use File::Temp qw(tempdir);
use DBI;
use lib 'lib';
use KSI::Auth qw(hash_password);

my $dir = tempdir(CLEANUP => 1);
my $dbfile = "$dir/test.sqlite";
$ENV{SQL_ALCHEMY_URI} = "sqlite:///$dbfile";
$ENV{MOJO_SECRET} = 'test-only-secret';
my $dbh = DBI->connect("dbi:SQLite:dbname=$dbfile", '', '', {RaiseError => 1});
$dbh->do(q{CREATE TABLE users (
    id INTEGER PRIMARY KEY, email VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
    last_logged_in TEXT
)});
$dbh->do(q{CREATE TABLE oauth2_tokens (
    access_token VARCHAR(150) PRIMARY KEY, user INTEGER, expire TEXT,
    refresh_token VARCHAR(150), granted TEXT
)});
$dbh->do('INSERT INTO users (id, email, password, enabled) VALUES (?, ?, ?, ?)',
    undef, 7, 'person@example.test', hash_password('good-password'), 1);
$dbh->do('INSERT INTO users (id, email, password, enabled) VALUES (?, ?, ?, ?)',
    undef, 8, 'disabled@example.test', hash_password('good-password'), 0);
$dbh->disconnect;

my $t = Test::Mojo->new('KSI::App');
$t->post_ok('/auth' => form => {grant_type => 'password', username => 'person@example.test', password => 'good-password'})
  ->status_is(200)->json_has('/access_token')->json_is('/token_type' => 'Bearer')->json_is('/expires_in' => 3600);
my $first = $t->tx->res->json;
$t->post_ok('/auth' => form => {grant_type => 'password', username => 'person@example.test', password => 'bad'})
  ->status_is(400)->json_is('/error' => 'unauthorized_client');
$t->post_ok('/auth' => form => {grant_type => 'password', username => 'disabled@example.test', password => 'good-password'})
  ->status_is(400)->json_is('/error' => 'account_disabled');
$t->get_ok('/logout' => {Authorization => "Bearer $first->{access_token}"})->status_is(204);
$t->post_ok('/auth' => form => {grant_type => 'refresh_token', refresh_token => $first->{refresh_token}})
  ->status_is(400)->json_is('/error' => 'unauthorized_client');
$t->post_ok('/auth' => form => {grant_type => 'password', username => 'person@example.test', password => 'good-password'})
  ->status_is(200);
my $second = $t->tx->res->json;
$t->post_ok('/auth' => form => {grant_type => 'refresh_token', refresh_token => $second->{refresh_token}})
  ->status_is(200)->json_has('/access_token')->json_is('/token_type' => 'Bearer');
$t->post_ok('/auth' => form => {grant_type => 'refresh_token', refresh_token => $second->{refresh_token}})
  ->status_is(400)->json_is('/error' => 'unauthorized_client');
done_testing;
