import datetime
from typing import Dict
from typing import Optional
from typing import Union

import pytz
from django.http import HttpRequest
from django.utils import timezone
from django.utils.text import gettext_lazy as _
from drfaddons.utils import send_message
from rest_framework.exceptions import APIException
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.exceptions import NotFound
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.utils import datetime_from_epoch

from drf_user import update_user_settings
from drf_user.models import AuthTransaction
from drf_user.models import OTPValidation
from drf_user.models import User

user_settings: Dict[
    str, Union[bool, Dict[str, Union[int, str, bool]]]
] = update_user_settings()
otp_settings: Dict[str, Union[str, int]] = user_settings["OTP"]


def get_client_ip(request: HttpRequest) -> Optional[str]:
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    else:
        return request.META.get("REMOTE_ADDR")


def datetime_passed_now(source: datetime.datetime) -> bool:
    if source.tzinfo is not None and source.tzinfo.utcoffset(source) is not None:
        return source <= datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
    else:
        return source <= datetime.datetime.now()


def check_unique(prop: str, value: str) -> bool:
    user = User.objects.extra(where=[prop + " = '" + value + "'"])
    return user.count() == 0


def generate_otp(prop: str, value: str) -> OTPValidation:
    random_number: str = User.objects.make_random_password(
        length=otp_settings["LENGTH"], allowed_chars=otp_settings["ALLOWED_CHARS"]
    )

    while OTPValidation.objects.filter(otp__exact=random_number).filter(
            is_validated=False
    ):
        random_number: str = User.objects.make_random_password(
            length=otp_settings["LENGTH"], allowed_chars=otp_settings["ALLOWED_CHARS"]
        )

    try:
        otp_object: OTPValidation = OTPValidation.objects.get(destination=value)
    except OTPValidation.DoesNotExist:
        otp_object: OTPValidation = OTPValidation()
        otp_object.destination = value
    else:
        if not datetime_passed_now(otp_object.reactive_at):
            return otp_object

    otp_object.otp = random_number
    otp_object.prop = prop

    otp_object.is_validated = False

    otp_object.validate_attempt = otp_settings["VALIDATION_ATTEMPTS"]

    otp_object.reactive_at = timezone.now() - datetime.timedelta(minutes=1)
    otp_object.save()
    return otp_object


def send_otp(value: str, otpobj: OTPValidation, recip: str) -> Dict:
    otp: str = otpobj.otp

    if not datetime_passed_now(otpobj.reactive_at):
        raise PermissionDenied(
            detail=_(f"OTP sending not allowed until: {otpobj.reactive_at}")
        )

    message = (
        f"OTP for verifying {otpobj.get_prop_display()}: {value} is {otp}."
        f"  Don't share this with anyone!"
    )

    try:
        rdata: dict = send_message(message, otp_settings["SUBJECT"], [value], [recip])
    except ValueError as err:
        raise APIException(_(f"Server configuration error occurred: {err}"))

    otpobj.reactive_at = timezone.now() + datetime.timedelta(
        minutes=otp_settings["COOLING_PERIOD"]
    )
    otpobj.save()

    return rdata


def login_user(user: User, request: HttpRequest) -> Dict[str, str]:
    token: RefreshToken = RefreshToken.for_user(user)

    if hasattr(user, "email"):
        token["email"] = user.email

    if hasattr(user, "mobile"):
        token["mobile"] = user.mobile

    if hasattr(user, "name"):
        token["name"] = user.name

    user.last_login = timezone.now()
    user.save()

    AuthTransaction(
        created_by=user,
        ip_address=get_client_ip(request),
        token=str(token.access_token),
        refresh_token=str(token),
        session=user.get_session_auth_hash(),
        expires_at=datetime_from_epoch(token["exp"]),
    ).save()

    return {
        "refresh_token": str(token),
        "token": str(token.access_token),
        "session": user.get_session_auth_hash(),
    }


def check_validation(value: str) -> bool:
    try:
        otp_object: OTPValidation = OTPValidation.objects.get(destination=value)
        return otp_object.is_validated
    except OTPValidation.DoesNotExist:
        return False


def validate_otp(value: str, otp: int) -> bool:
    try:
        otp_object: OTPValidation = OTPValidation.objects.get(
            destination=value, is_validated=False
        )
    except OTPValidation.DoesNotExist:
        raise NotFound(
            detail=_(
                "No pending OTP validation request found for provided "
                "destination. Kindly send an OTP first"
            )
        )

    otp_object.validate_attempt -= 1

    if str(otp_object.otp) == str(otp):
        otp_object.is_validated = True
        otp_object.save()
        return True

    elif otp_object.validate_attempt <= 0:
        generate_otp(otp_object.prop, value)
        raise AuthenticationFailed(
            detail=_("Incorrect OTP. Attempt exceeded! OTP has been reset.")
        )

    else:
        otp_object.save()
        raise AuthenticationFailed(
            detail=_(
                f"OTP Validation failed! {otp_object.validate_attempt} attempts left!"
            )
        )
