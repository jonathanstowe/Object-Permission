module Object::Permission
{
    role User {
        has @.permissions is rw;
    }

    class X::NotAuthorised is Exception {
        has Method $.method;
        has Str $.permission;
        method message() {
            "method '{ $!method.name }' requires permission '{ $.permission }'"
        }
    }

    role PermissionedThing {
        has Str $.permission is rw;
    }
    role PermissionedMethod does PermissionedThing {

    }

    multi sub trait_mod:<is> (Method:D $meth, Str :$authorised-by!) is export {

        if $authorised-by.defined {
            $meth does PermissionedMethod;
            $meth.permission = $authorised-by;
            my $rw = so $meth.rw;
            my $wrapper = $rw ?? method (|c) is rw {
                if !?$*AUTH-USER.permissions.grep($meth.permission) {
                    X::NotAuthorised.new(method => $meth, permission => $meth.permission).throw;
                }
                callsame;
            }
            !! 
            method (|c) {
                if !?$*AUTH-USER.permissions.grep($meth.permission) {
                    X::NotAuthorised.new(method => $meth, permission => $meth.permission).throw;
                }
                nextsame;
            };

            $meth.wrap($wrapper);
        }
    }

    role PermissionedAttribute does PermissionedThing {

        # A bit icky but better than over-riding compose altogether
        method compose(Mu $package) {
            # not sure if the return matters
            my $r = callsame;
            if self.has_accessor {
                my $meth_name = self.name.substr(2);
                if $package.can($meth_name)[0] -> $meth {
                    trait_mod:<is>($meth, authorised-by => $.permission);
                }
            }
            $r;
        }
    }


    multi sub trait_mod:<is> (Attribute:D $attr, :$authorised-by!) is export {

        if $authorised-by.defined {
            $attr does PermissionedAttribute;
            $attr.permission = $authorised-by;
        }
    }

    # This is by the way of a hack to type constrain the
    # global dynamic variable
    my User $user;
    PROCESS::<$AUTH-USER> := Proxy.new(
                                    FETCH => sub ($) {
                                                        $user;
                                    },
                                    STORE => sub ($, User $val) {
												$user = $val;
								    }
                                );


}
