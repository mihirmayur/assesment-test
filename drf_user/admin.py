from django.contrib import admin
from django.contrib.auth.admin import Group
from django.contrib.auth.admin import GroupAdmin
from django.contrib.auth.admin import UserAdmin
from django.utils.text import gettext_lazy as _

from .models import AuthTransaction
from .models import OTPValidation
from .models import Role
from .models import User


class DRFUserAdmin(UserAdmin):
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (_("Personal info"), {"fields": ("name", "profile_image", "email", "mobile")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (
            _("Important dates"),
            {"fields": ("last_login", "date_joined", "update_date")},
        ),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("username", "email", "mobile", "password1", "password2"),
            },
        ),
    )
    list_display = ("username", "email", "name", "mobile", "is_staff")
    search_fields = ("username", "name", "email", "mobile")
    readonly_fields = ("date_joined", "last_login", "update_date")


class OTPValidationAdmin(admin.ModelAdmin):
    list_display = ("destination", "otp", "prop")


class AuthTransactionAdmin(admin.ModelAdmin):
    list_display = ("created_by", "ip_address", "create_date")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.unregister(Group)
admin.site.register(Role, GroupAdmin)

admin.site.register(User, DRFUserAdmin)
admin.site.register(OTPValidation, OTPValidationAdmin)
admin.site.register(AuthTransaction, AuthTransactionAdmin)
