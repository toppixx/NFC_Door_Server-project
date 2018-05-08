from rest_framework import permissions

class CreateNewUser(permissions.BasePermission):
    """Allow staff useres to create new user profile"""

    def has_object_permission(self,request,view,obj):
        """Check if accessing user is staff:"""

        if request.method in permissions.SAFE_METHODS:
            print(request.user.is_staff)
            print('i was herer first')
            return True
        print(request.user.is_staff)
        print('i was herer last')
        return request.user.is_staff #TODO not shure if thats right

class UpdateOwnProfile(permissions.BasePermission):
    """Allow useres to edit their own profile"""

    def has_object_permission(self,request,view,obj):
        """Check user is trying to edit their own profile:"""

        if request.method in permissions.SAFE_METHODS:
            print('safe Methods True')
            return True
        print('safe Methods False')
        return obj.id == request.user.id


class PostOwnStatus(permissions.BasePermission):
    """ Allow users to update their own status."""

    def has_object_permission(self,request,view,obj):
        if request.method in permissions.SAFE_METHODS:
            return True

        return obj.user_profile.id == request.user.id

class DoorAccesControll(permissions.BasePermission):
    """Allow useres to access a door"""

    def has_object_permission(self,request,view,obj):
        """Check user is trying to get acces to a door:"""

        if request.method in permissions.SAFE_METHODS:
            return True

        return obj.user_profile.id == request.user.id
