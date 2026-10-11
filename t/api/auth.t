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
    password VARCHAR(255) NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, role TEXT NOT NULL DEFAULT 'participant',
    last_logged_in TEXT
)});
$dbh->do(q{CREATE TABLE oauth2_tokens (
    access_token VARCHAR(150) PRIMARY KEY, user INTEGER, expire TEXT,
    refresh_token VARCHAR(150), granted TEXT
)});
$dbh->do(q{CREATE TABLE years (
    id INTEGER PRIMARY KEY, year TEXT, sealed INTEGER NOT NULL, point_pad REAL NOT NULL
)});
$dbh->do(q{CREATE TABLE waves (
    id INTEGER PRIMARY KEY, year INTEGER NOT NULL, `index` INTEGER NOT NULL,
    caption TEXT, garant INTEGER NOT NULL, time_published TEXT NOT NULL
)});
$dbh->do(q{CREATE TABLE tasks (
    id INTEGER PRIMARY KEY, wave INTEGER NOT NULL
)});
$dbh->do(q{CREATE TABLE modules (
    id INTEGER PRIMARY KEY, task INTEGER NOT NULL, max_points REAL, bonus INTEGER NOT NULL DEFAULT 0
)});
$dbh->do(q{CREATE TABLE active_orgs (org INTEGER NOT NULL, year INTEGER NOT NULL, PRIMARY KEY (org, year))});
$dbh->do('INSERT INTO users (id, email, password, enabled) VALUES (?, ?, ?, ?)',
    undef, 7, 'person@example.test', hash_password('good-password'), 1);
$dbh->do('INSERT INTO users (id, email, password, enabled) VALUES (?, ?, ?, ?)',
    undef, 8, 'disabled@example.test', hash_password('good-password'), 0);
$dbh->do('INSERT INTO users (id, email, password, enabled, role) VALUES (?, ?, ?, ?, ?)',
    undef, 9, 'admin@example.test', hash_password('good-password'), 1, 'admin');
$dbh->do('INSERT INTO years VALUES (2025, ?, 0, 1.5)', undef, '2025/2026');
$dbh->do('INSERT INTO waves VALUES (10, 2025, 1, "Wave one", 9, "2020-01-01 00:00:00")');
$dbh->do('INSERT INTO waves VALUES (11, 2025, 2, "Wave two", 9, "2099-01-01 00:00:00")');
$dbh->do('INSERT INTO tasks VALUES (100, 10)');
$dbh->do('INSERT INTO tasks VALUES (101, 10)');
$dbh->do('INSERT INTO modules (id, task, max_points, bonus) VALUES (1000, 100, 5, 0)');
$dbh->do('INSERT INTO modules (id, task, max_points, bonus) VALUES (1001, 100, 3, 0)');
$dbh->do('INSERT INTO modules (id, task, max_points, bonus) VALUES (1002, 100, 2, 1)');
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
$t->get_ok('/years')->status_is(200)->json_is('/years/0/sum_points' => 8)
  ->json_is('/years/0/tasks_cnt' => 2)->json_is('/years/0/index' => 2025);
$t->get_ok('/years/2025')->status_is(200)->json_is('/year/sum_points' => 8);
$t->get_ok('/years/9999')->status_is(404);
$t->head_ok('/years')->status_is(200)->content_is('');
$t->get_ok('/waves')->status_is(200)->json_is('/waves/0/sum_points' => 8)
  ->json_is('/waves/0/tasks_cnt' => 2)->json_is('/waves/0/public' => 1);
$t->get_ok('/waves/11')->status_is(200)->json_is('/wave/public' => 0);
$t->post_ok('/years' => json => {year => {index => 2026, year => '2026/2027', sealed => 0, point_pad => 0, active_orgs => [7]}})
  ->status_is(400);
$t->post_ok('/auth' => form => {grant_type => 'password', username => 'admin@example.test', password => 'good-password'})
  ->status_is(200);
my $admin = $t->tx->res->json;
$t->get_ok('/waves' => {Authorization => "Bearer $admin->{access_token}"})
  ->status_is(200)->json_is('/waves/1/id' => 11);
$t->post_ok('/years' => {Authorization => "Bearer $admin->{access_token}"} => json => {year => {index => 2026, year => '2026/2027', sealed => 0, point_pad => 0, active_orgs => [7]}})
  ->status_is(200)->json_is('/year/index' => 2026)->json_is('/year/sum_points' => 0);
$t->get_ok('/years/2026')->status_is(200)->json_is('/year/tasks_cnt' => 0);
$t->delete_ok('/years/2025' => {Authorization => "Bearer $admin->{access_token}"})->status_is(403);
$t->delete_ok('/years/2026' => {Authorization => "Bearer $admin->{access_token}"})->status_is(200)->json_is({});
done_testing;
