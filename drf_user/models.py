from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Group
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.utils.text import gettext_lazy as _

from drf_user.managers import UserManager
from drf_user.variables import DESTINATION_CHOICES
from drf_user.variables import EMAIL


class Role(Group):
    class Meta:
        proxy = True
        verbose_name = _("Role")
        verbose_name_plural = _("Roles")


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(
        verbose_name=_("Unique UserName"), max_length=254, unique=True
    )
    email = models.EmailField(verbose_name=_("Email Address"), unique=True)
    mobile = models.CharField(
        verbose_name=_("Mobile Number"),
        max_length=150,
        unique=True,
        null=True,
        blank=True,
    )
    name = models.CharField(verbose_name=_("Full Name"), max_length=500, blank=False)
    profile_image = models.ImageField(
        verbose_name=_("Profile Photo"), upload_to="user_images", null=True, blank=True
    )
    date_joined = models.DateTimeField(verbose_name=_("Date Joined"), auto_now_add=True)
    update_date = models.DateTimeField(verbose_name=_("Date Modified"), auto_now=True)
    is_active = models.BooleanField(verbose_name=_("Activated"), default=False)
    is_staff = models.BooleanField(verbose_name=_("Staff Status"), default=False)

    # Renamed Groups to Roles
    groups = models.ManyToManyField(
        Role,
        verbose_name=_("Roles"),
        blank=True,
        help_text=_(
            "The roles this user belongs to. A user will get all permissions "
            "granted to each of their roles."
        ),
        related_name="user_set",
        related_query_name="user",
    )

    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["name", "email"]

    class Meta:
        verbose_name = _("User")
        verbose_name_plural = _("Users")

    def get_full_name(self) -> str:
        return str(self.name)

    def __str__(self):
        return str(self.name) + " | " + str(self.username)


class AuthTransaction(models.Model):
    ip_address = models.GenericIPAddressField(blank=False, null=False)
    token = models.TextField(verbose_name=_("JWT Access Token"))
    session = models.TextField(verbose_name=_("Session Passed"))
    refresh_token = models.TextField(
        blank=True,
        verbose_name=_("JWT Refresh Token"),
    )
    expires_at = models.DateTimeField(
        blank=True, null=True, verbose_name=_("Expires At")
    )
    create_date = models.DateTimeField(
        verbose_name=_("Create Date/Time"), auto_now_add=True
    )
    update_date = models.DateTimeField(
        verbose_name=_("Date/Time Modified"), auto_now=True
    )
    created_by = models.ForeignKey(to=User, on_delete=models.PROTECT)

    def __str__(self):
        return str(self.created_by.name) + " | " + str(self.created_by.username)

    class Meta:
        verbose_name = _("Authentication Transaction")
        verbose_name_plural = _("Authentication Transactions")


class OTPValidation(models.Model):
    otp = models.CharField(verbose_name=_("OTP Code"), max_length=10)
    destination = models.CharField(
        verbose_name=_("Destination Address (Mobile/EMail)"),
        max_length=254,
        unique=True,
    )
    create_date = models.DateTimeField(verbose_name=_("Create Date"), auto_now_add=True)
    update_date = models.DateTimeField(verbose_name=_("Date Modified"), auto_now=True)
    is_validated = models.BooleanField(verbose_name=_("Is Validated"), default=False)
    validate_attempt = models.IntegerField(
        verbose_name=_("Attempted Validation"), default=3
    )
    prop = models.CharField(
        verbose_name=_("Destination Property"),
        default=EMAIL,
        max_length=3,
        choices=DESTINATION_CHOICES,
    )
    send_counter = models.IntegerField(verbose_name=_("OTP Sent Counter"), default=0)
    sms_id = models.CharField(
        verbose_name=_("SMS ID"), max_length=254, null=True, blank=True
    )
    reactive_at = models.DateTimeField(verbose_name=_("ReActivate Sending OTP"))

    def __str__(self):
        return self.destination

    class Meta:
        verbose_name = _("OTP Validation")
        verbose_name_plural = _("OTP Validations")
