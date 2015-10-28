#!perl6

use v6;
use lib 'lib';
use Test;

use Object::Permission;

class Foo {
   method test-one() is authorised-by('test-1-ok') {
       "test-one";
   }

   method test-two() is authorised-by('test-2-notok') {
       "test-two";
   }
}

my $foo = Foo.new;

$*AUTH-USER = Object::Permission::User.new(permissions => <test-1-ok>);


my $ret;
lives-ok { $ret = $foo.test-one() }, "okay for method we have permission for";
is $ret, "test-one", "sanity check we got something back";
throws-like { $foo.test-two() }, X::NotAuthorised, permission => 'test-2-notok', "throws for the other one";

$*AUTH-USER.permissions.push('test-2-notok');
lives-ok { $ret = $foo.test-two() }, "okay for method we have just add the permission for";
is $ret, "test-two", "sanity check we got something back";

done-testing;

# vim: expandtab shiftwidth=4 ft=perl6
