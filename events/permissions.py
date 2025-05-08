from rest_framework import permissions

class IsOrganizerOrReadOnly(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        
        if request.user.is_superuser:
            return True
        
        if request.user.role == 'Organizer':
            return True
        
        if request.method in permissions.SAFE_METHODS:
            return True
        
        return False
