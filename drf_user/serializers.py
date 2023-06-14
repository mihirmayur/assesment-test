from django.contrib.auth.password_validation import validate_password
from django.core.validators import EmailValidator
from django.core.validators import ValidationError
from django.utils.text import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import NotFound
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from drf_user import user_settings
from drf_user.models import User
from drf_user.utils import check_validation
from drf_user.variables import EMAIL
from drf_user.variables import MOBILE


class UserSerializer(serializers.ModelSerializer):

    def validate_email(self, value: str) -> str:

        if not user_settings["EMAIL_VALIDATION"]:
            return value

        if check_validation(value=value):
            return value
        else:
            raise serializers.ValidationError(
                "The email must be " "pre-validated via OTP."
            )

    def validate_mobile(self, value: str) -> str:

        if not user_settings["MOBILE_VALIDATION"]:
            return value

        if check_validation(value=value):
            return value
        else:
            raise serializers.ValidationError(
                "The mobile must be " "pre-validated via OTP."
            )

    def validate_password(self, value: str) -> str:
        validate_password(value)
        return value

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "name",
            "email",
            "mobile",
            "password",
            "is_superuser",
            "is_staff",
        )
        read_only_fields = ("is_superuser", "is_staff")
        extra_kwargs = {"password": {"write_only": True}}


class UserShowSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "name")
        read_only_fields = ("username", "name")


class OTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    is_login = serializers.BooleanField(default=False)
    verify_otp = serializers.CharField(required=False)
    destination = serializers.CharField(required=True)

    def get_user(self, prop: str, destination: str) -> User:

        if prop == MOBILE:
            try:
                user = User.objects.get(mobile=destination)
            except User.DoesNotExist:
                user = None
        else:
            try:
                user = User.objects.get(email=destination)
            except User.DoesNotExist:
                user = None

        return user

    def validate(self, attrs: dict) -> dict:

        validator = EmailValidator()
        try:
            validator(attrs["destination"])
        except ValidationError:
            attrs["prop"] = MOBILE
        else:
            attrs["prop"] = EMAIL

        user = self.get_user(attrs.get("prop"), attrs.get("destination"))

        if not user:
            if attrs["is_login"]:
                raise NotFound(_("No user exists with provided details"))
            if "email" not in attrs.keys() and "verify_otp" not in attrs.keys():
                raise serializers.ValidationError(
                    _(
                        "email field is compulsory while verifying a"
                        " non-existing user's OTP."
                    )
                )
        else:
            attrs["email"] = user.email
            attrs["user"] = user

        return attrs


class CheckUniqueSerializer(serializers.Serializer):
    prop = serializers.ChoiceField(choices=("email", "mobile", "username"))
    value = serializers.CharField()


class OTPLoginRegisterSerializer(serializers.Serializer):
    name = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    verify_otp = serializers.CharField(default=None, required=False)
    mobile = serializers.CharField(required=True)

    @staticmethod
    def get_user(email: str, mobile: str):
        """Fetches user object"""
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            try:
                user = User.objects.get(mobile=mobile)
            except User.DoesNotExist:
                user = None

        if user:
            if user.email != email:
                raise serializers.ValidationError(
                    _(
                        "Your account is registered with {mobile} does not has "
                        "{email} as registered email. Please login directly via "
                        "OTP with your mobile.".format(mobile=mobile, email=email)
                    )
                )
            if user.mobile != mobile:
                raise serializers.ValidationError(
                    _(
                        "Your account is registered with {email} does not has "
                        "{mobile} as registered mobile. Please login directly via "
                        "OTP with your email.".format(mobile=mobile, email=email)
                    )
                )
        return user

    def validate(self, attrs: dict) -> dict:
        """Validates the response"""

        attrs["user"] = self.get_user(
            email=attrs.get("email"), mobile=attrs.get("mobile")
        )
        return attrs


class PasswordResetSerializer(serializers.Serializer):
    otp = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)

    def get_user(self, destination: str) -> User:

        try:
            user = User.objects.get(email=destination)
        except User.DoesNotExist:
            user = None

        return user

    def validate(self, attrs: dict) -> dict:

        validator = EmailValidator()
        validator(attrs.get("email"))
        user = self.get_user(attrs.get("email"))

        if not user:
            raise NotFound(_("User with the provided email does not exist."))

        return attrs


class ImageSerializer(serializers.ModelSerializer):
    profile_image = serializers.ImageField(required=True)

    class Meta:
        model = User
        fields = ("profile_image",)


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    default_error_messages = {
        "no_active_account": _("username or password is invalid.")
    }

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        if hasattr(user, "email"):
            token["email"] = user.email

        if hasattr(user, "mobile"):
            token["mobile"] = user.mobile

        if hasattr(user, "name"):
            token["name"] = user.name

        return token
