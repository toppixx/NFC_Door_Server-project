from rest_framework import permissions


class UpdateOwnProfile(permissions.BasePermission):
    """Allow useres to edit their own profile"""

    def has_object_permission(self,request,view,obj):
        """Check user is trying to edit their own profile:"""

        if request.method in permissions.SAFE_METHODS:
            return True

        print(obj.id)
        print(request.user)
        print(request.user.id)
        print(obj.id == request.user.id)
        print (request.user.is_authenticated)
        return request.user.is_authenticated
        return obj.id == request.user.id


class PostOwnStatus(permissions.BasePermission):
    """ Allow users to update their own status."""

    def has_object_permission(self,request,view,obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        print(obj.id)
        print(obj.user_profile)

        print(obj.status_text)

        print(obj.created_on)
        print(request.user.id)


        return obj.user_profile.id == request.user.id
