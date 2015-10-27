module Object::Permission
{
    role User {
        has @.permissions is rw;
    }

    class X::NotAuthorised is Exception {
    }

    role PermissionedMethod {

    }

    role PermissionedAttribute {

    }

    multi sub trait_mod:<is> (Method:D $meth, :$authorised-by!) is export {

        $meth does PermissionedMethod;

    }

    multi sub trait_mod:<is> (Attribute:D $attr, :$authorised-by!) is export {
        $attr does PermissionedAttribute;
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
