from datetime import timedelta

import pytest
from django.test import override_settings
from django.urls import reverse
from model_bakery import baker
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from drf_user.models import AuthTransaction
from drf_user.models import User
from tests.settings import BASE_DIR


class TestLoginView(APITestCase):
    def setUp(self) -> None:
        self.url = reverse("Login")

        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            name="user",
            mobile=1234569877,
            is_active=True,
        )

        self.user.set_password("pass123")
        self.user.save()

    @pytest.mark.django_db
    def test_fields_missing(self):
        response = self.client.post(self.url, data={})
        self.assertEqual(400, response.status_code)
        self.assertIn(User.USERNAME_FIELD, response.data)
        self.assertIn("password", response.data)

    @pytest.mark.django_db
    def test_object_created(self):
        self.assertEqual(1, User.objects.count())

    @pytest.mark.django_db
    def test_successful_login_view(self):
        response = self.client.post(
            self.url, data={"username": "user", "password": "pass123"}
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("token", response.data)
        self.assertIn("refresh_token", response.data)

        self.assertEqual(1, AuthTransaction.objects.count())

    @pytest.mark.django_db
    def test_login_using_mobile_as_username(self):
        response = self.client.post(
            self.url, data={"username": "1234569877", "password": "pass123"}
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("token", response.data)
        self.assertIn("refresh_token", response.data)

        self.assertEqual(1, AuthTransaction.objects.count())

    @pytest.mark.django_db
    def test_login_using_email_as_username(self):
        response = self.client.post(
            self.url, data={"username": "user@email.com", "password": "pass123"}
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("token", response.data)
        self.assertIn("refresh_token", response.data)

        self.assertEqual(1, AuthTransaction.objects.count())

    @pytest.mark.django_db
    def test_unsuccessful_login_view(self):
        response = self.client.post(
            self.url, data={"username": "user", "password": "pass1234"}
        )

        self.assertEqual(403, response.status_code)
        self.assertIn("username or password is invalid.", response.data["detail"])


class TestRetrieveUpdateUserAccountView(APITestCase):
    def setUp(self) -> None:
        self.url = reverse("Retrieve Update Profile")

        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            mobile=1234569877,
            password="old_password",
        )

        self.auth_transaction = baker.make(
            "drf_user.AuthTransaction",
            created_by=self.user,
        )

    @pytest.mark.django_db
    def test_object_created(self):
        self.assertEqual(1, User.objects.count())
        self.assertEqual(1, AuthTransaction.objects.count())

    @pytest.mark.django_db
    def test_get_user_account_view(self):
        self.client.force_authenticate(self.user)
        response = self.client.get(self.url)

        self.assertEqual(200, response.status_code)
        self.assertEqual(self.user.username, response.data["username"])

    @pytest.mark.django_db
    def test_update_username(self):
        self.client.force_authenticate(self.user)
        response = self.client.patch(self.url, {"username": "updated_username"})

        self.assertEqual(200, response.status_code)
        self.assertEqual("updated_username", self.user.username)

    @pytest.mark.django_db
    def test_update_password(self):
        self.client.force_authenticate(self.user)
        self.assertEqual("old_password", self.user.password)

        response = self.client.patch(self.url, {"password": "my_unique_password"})

        self.assertEqual(200, response.status_code)
        self.assertIn("md5", self.user.password)


class TestCheckUniqueView(APITestCase):
    def setUp(self) -> None:
        self.url = reverse("Check Unique")

        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            mobile=1234569877,
        )

    @pytest.mark.django_db
    def test_user_object_created(self):
        self.assertEqual(1, User.objects.count())

    @pytest.mark.django_db
    def test_is_unique(self):
        response = self.client.post(self.url, {"prop": "username", "value": "user7"})

        self.assertEqual(200, response.status_code)
        self.assertTrue(response.json()["data"][0]["unique"])

    @pytest.mark.django_db
    def test_is_not_unique(self):
        response = self.client.post(self.url, {"prop": "username", "value": "user"})

        self.assertEqual(200, response.status_code)
        self.assertFalse(response.json()["data"][0]["unique"])

    @pytest.mark.django_db
    def test_data_invalid(self):
        response = self.client.post(self.url, {"prop": "invalid", "value": "user"})
        self.assertEqual(422, response.status_code)


class TestRegisterView(APITestCase):
    def setUp(self) -> None:
        self.validated_email = baker.make(
            "drf_user.OTPValidation", destination="random@django.com", is_validated=True
        )
        self.validated_mobile = baker.make(
            "drf_user.OTPValidation", destination="1234567890", is_validated=True
        )
        self.url = reverse("Register")
        self.validated_data = {
            "username": "my_username",
            "password": "test_password",
            "name": "random_name",
            "email": "random@django.com",
            "mobile": 1234567890,
        }
        self.not_validated_data = {
            "username": "random",
            "password": "test_password",
            "name": "random_name",
            "email": "random@example.com",
            "mobile": 8800880080,
        }

        self.data_without_mobile = {
            "username": "jake123",
            "password": "test_password",
            "name": "jake",
            "email": "random@django.com",
        }

    @pytest.mark.django_db
    def test_register_with_validated_email_and_mobile(self):
        response = self.client.post(self.url, self.validated_data)

        self.assertEqual(201, response.status_code)
        self.assertEqual("my_username", response.json()["username"])
        self.assertEqual("random_name", response.json()["name"])

    @pytest.mark.django_db
    def test_raise_validation_error_when_email_mobile_not_validated(self):
        response = self.client.post(self.url, self.not_validated_data)

        self.assertEqual(400, response.status_code)
        self.assertEqual(
            ["The email must be pre-validated via OTP."], response.json()["email"]
        )
        self.assertEqual(
            ["The mobile must be pre-validated via OTP."], response.json()["mobile"]
        )

    @pytest.mark.django_db
    def test_register_user_without_mobile_number(self):
        response = self.client.post(self.url, self.data_without_mobile)
        self.assertEqual(201, response.status_code)
        self.assertEqual("jake", response.json()["name"])

    @pytest.mark.django_db
    def test_register_user_with_mobile(self):
        with override_settings(USER_SETTINGS={"MOBILE_OPTIONAL": False}):
            response = self.client.post(self.url, self.data_without_mobile)
            self.assertEqual(400, response.status_code)
            self.assertEqual("Mobile is required.", response.json()["error"])

            response = self.client.post(self.url, self.validated_data)
            self.assertEqual(201, response.status_code)
            self.assertEqual("1234567890", response.json()["mobile"])


class TestOTPView(APITestCase):
    def setUp(self) -> None:
        self.user = baker.make("drf_user.User", email="user@example.com")
        self.otp_user = baker.make(
            "drf_user.OTPValidation", destination="user@example.com", otp=888383
        )
        self.otp_object = baker.make(
            "drf_user.OTPValidation", destination="email@django.com", otp=123456
        )
        self.url = reverse("OTP")

    @pytest.mark.django_db
    def test_request_otp_on_email(self):
        response = self.client.post(
            self.url, {"destination": "email@django.com", "email": "email@django.com"}
        )

        self.assertEqual(201, response.status_code)
        self.assertEqual("Message sent successfully!", response.json()["message"])

    @pytest.mark.django_db
    def test_request_otp_on_email_and_mobile(self):
        response = self.client.post(
            self.url, {"destination": 1231242492, "email": "email@django.com"}
        )

        self.assertEqual(201, response.status_code)
        self.assertEqual("Message sent successfully!", response.json()["message"])

    @pytest.mark.django_db
    def test_raise_api_exception_when_email_invalid(self):
        response = self.client.post(
            self.url, {"destination": "a.b", "email": "abc@d.com"}
        )

        self.assertEqual(500, response.status_code)
        self.assertEqual(
            "Server configuration error occurred: Invalid recipient.",
            response.json()["detail"],
        )

    @pytest.mark.django_db
    def test_raise_validation_error_when_email_not_response_when_user_is_new(self):
        response = self.client.post(self.url, {"destination": "email@django.com"})

        self.assertEqual(
            ["email field is compulsory while verifying a non-existing user's OTP."],
            response.json()["non_field_errors"],
        )
        self.assertEqual(400, response.status_code)

    @pytest.mark.django_db
    def test_raise_validation_error_when_is_login_response_when_user_is_new(self):
        response = self.client.post(
            self.url, {"destination": "email@django.com", "is_login": True}
        )

        self.assertEqual(
            "No user exists with provided details", response.json()["detail"]
        )
        self.assertEqual(404, response.status_code)

    @pytest.mark.django_db
    def test_verify_otp_in_response(self):
        response = self.client.post(
            self.url,
            {
                "destination": "email@django.com",
                "email": "email@django.com",
                "verify_otp": 123456,
            },
        )

        self.assertEqual(202, response.status_code)
        assert "OTP Validated successfully!" in response.json()["OTP"]

    @pytest.mark.django_db
    def test_is_login_in_response(self):
        response = self.client.post(
            self.url,
            {"destination": "user@example.com", "verify_otp": 888383, "is_login": True},
        )

        self.assertEqual(202, response.status_code)


class TestOTPLoginView(APITestCase):
    def setUp(self) -> None:
        self.url = reverse("OTP-Register-LogIn")

        self.user = baker.make(
            "drf_user.User",
            username="my_user",
            email="my_user@django.com",
            mobile=2848482848,
        )
        self.user_otp = baker.make(
            "drf_user.OTPValidation", destination="my_user@django.com", otp=437474
        )

        self.random_user_otp = baker.make(
            "drf_user.OTPValidation", destination="random@django.com", otp=888383
        )
        self.data = {
            "name": "random_name",
            "email": "random@django.com",
            "mobile": 1234567890,
        }
        self.data_with_incorrect_email_mobile = {
            "name": "name",
            "email": "r@o.com",
            "mobile": 97,
        }
        self.data_with_correct_otp = {
            "name": "random_name",
            "email": "random@django.com",
            "mobile": 1234567890,
            "verify_otp": 888383,
        }
        self.data_with_incorrect_otp = {
            "name": "random_name",
            "email": "random@django.com",
            "mobile": 1234567890,
            "verify_otp": 999999,
        }
        self.data_registered_user = {
            "name": "my_user",
            "email": "my_user@django.com",
            "mobile": 2848482848,
            "verify_otp": 437474,
        }
        self.data_registered_user_with_different_mobile = {
            "name": "my_user",
            "email": "my_user@django.com",
            "mobile": 2846482848,
            "verify_otp": 437474,
        }
        self.data_registered_user_with_different_email = {
            "name": "my_user",
            "email": "ser@django.com",
            "mobile": 2848482848,
            "verify_otp": 437474,
        }
        self.data_random_user = {
            "name": "test_user1",
            "email": "test_user1@django.com",
            "mobile": 2848444448,
            "verify_otp": 585858,
        }

    @pytest.mark.django_db
    def test_when_only_name_is_passed(self):
        response = self.client.post(self.url, data={"name": "test"}, format="json")

        self.assertEqual(400, response.status_code)
        self.assertEqual(["This field is required."], response.json()["email"])
        self.assertEqual(["This field is required."], response.json()["mobile"])

    @pytest.mark.django_db
    def test_when_name_email_is_passed(self):
        response = self.client.post(
            self.url, data={"name": "test", "email": "test@random.com"}, format="json"
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual(["This field is required."], response.json()["mobile"])

    @pytest.mark.django_db
    def test_when_name_mobile_is_passed(self):
        response = self.client.post(
            self.url, data={"name": "test", "mobile": 1234838884}, format="json"
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual(["This field is required."], response.json()["email"])

    @pytest.mark.django_db
    def test_when_email_mobile_is_passed(self):
        response = self.client.post(
            self.url,
            data={"email": "test@example.com", "mobile": 1234838884},
            format="json",
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual(["This field is required."], response.json()["name"])

    @pytest.mark.django_db
    def test_sent_otp_when_name_email_mobile_is_passed(self):
        response = self.client.post(self.url, data=self.data, format="json")

        self.assertEqual(201, response.status_code)
        self.assertEqual(
            "OTP has been sent successfully.", response.json()["email"]["otp"]
        )
        self.assertEqual(
            "OTP has been sent successfully.", response.json()["mobile"]["otp"]
        )

    @pytest.mark.django_db
    def test_login_with_incorrect_otp_for_registered_user(self):
        response = self.client.post(
            self.url, data=self.data_with_incorrect_otp, format="json"
        )

        self.assertEqual(403, response.status_code)
        self.assertEqual(
            "OTP Validation failed! 2 attempts left!", response.json()["detail"]
        )

    @pytest.mark.django_db
    def test_login_with_incorrect_otp_for_new_user_without_validated_otp(self):
        response = self.client.post(self.url, data=self.data_random_user, format="json")

        self.assertEqual(404, response.status_code)
        self.assertEqual(
            "No pending OTP validation request found for provided destination. "
            "Kindly send an OTP first",
            response.json()["detail"],
        )

    @pytest.mark.django_db
    def test_login_with_correct_otp_for_new_user(self):
        response = self.client.post(
            self.url, data=self.data_with_correct_otp, format="json"
        )

        self.assertEqual(202, response.status_code)
        self.assertContains(text="token", response=response, status_code=202)
        self.assertTrue(User.objects.get(email="random@django.com"))

    @pytest.mark.django_db
    def test_login_with_incorrect_email_mobile(self):
        response = self.client.post(
            self.url, data=self.data_with_incorrect_email_mobile, format="json"
        )

        self.assertEqual(500, response.status_code)
        self.assertEqual(
            "Server configuration error occurred: Invalid recipient.",
            response.json()["detail"],
        )

    @pytest.mark.django_db
    def test_login_with_different_email(self):
        response = self.client.post(
            self.url, data=self.data_registered_user_with_different_email, format="json"
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual(
            [
                "Your account is registered with 2848482848 does not has ser@django.com as "  # noqa:E501
                "registered email. Please login directly via OTP with your mobile."
            ],
            response.json()["non_field_errors"],
        )

    @pytest.mark.django_db
    def test_login_with_different_mobile(self):
        response = self.client.post(
            self.url,
            data=self.data_registered_user_with_different_mobile,
            format="json",
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual(
            [
                "Your account is registered with my_user@django.com does not has 2846482848"  # noqa:E501
                " as registered mobile. Please login directly via OTP with your email."
            ],
            response.json()["non_field_errors"],
        )


class TestPasswordResetView(APITestCase):
    def setUp(self) -> None:
        self.url = reverse("reset_user_password")

        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            name="user",
            mobile=1234569877,
            is_active=True,
        )

        self.user_otp = baker.make(
            "drf_user.OTPValidation", destination="user@email.com", otp=437474
        )

        self.data_correct_otp = {
            "otp": 437474,
            "email": "user@email.com",
            "password": "test@123",
        }

        self.data_incorrect_otp = {
            "otp": 767474,
            "email": "user@email.com",
            "password": "test@123",
        }

        self.data_incorrect_email = {
            "otp": 437474,
            "email": "meh@email.com",
            "password": "test@123",
        }

        self.user.set_password("pass123")
        self.user.save()

    @pytest.mark.django_db
    def test_object_created(self):
        self.assertEqual(1, User.objects.count())

    @pytest.mark.django_db
    def test_when_nothing_is_passed(self):
        response = self.client.post(self.url, data={}, format="json")

        self.assertEqual(400, response.status_code)
        self.assertEqual(["This field is required."], response.json()["otp"])
        self.assertEqual(["This field is required."], response.json()["email"])
        self.assertEqual(["This field is required."], response.json()["email"])

    @pytest.mark.django_db
    def test_when_incorrect_email_passed(self):
        response = self.client.post(
            self.url, data=self.data_incorrect_email, format="json"
        )

        self.assertEqual(404, response.status_code)

    @pytest.mark.django_db
    def test_when_incorrect_otp_passed(self):
        response = self.client.post(
            self.url, data=self.data_incorrect_otp, format="json"
        )

        self.assertEqual(403, response.status_code)

    @pytest.mark.django_db
    def test_when_correct_otp_email_passed(self):
        response = self.client.post(self.url, data=self.data_correct_otp, format="json")

        self.assertEqual(202, response.status_code)


class TestUploadImageView(APITestCase):
    def setUp(self) -> None:
        self.url = reverse("upload_profile_image")

        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            name="user",
            mobile=1234569877,
            is_active=True,
        )

    @pytest.mark.django_db
    def test_object_created(self):
        self.assertEqual(1, User.objects.count())

    @pytest.mark.django_db
    def test_when_nothing_is_passed(self):
        self.client.force_authenticate(self.user)
        response = self.client.post(self.url, data={}, format="multipart")

        self.assertEqual(400, response.status_code)
        self.assertEqual("No file was submitted.", response.json()["profile_image"][0])

    @pytest.mark.django_db
    def test_when_upload_image_passed(self):
        self.client.force_authenticate(self.user)
        with open(f"{BASE_DIR}/tests/fixtures/test.jpg", "rb") as f:
            response = self.client.post(
                self.url, data={"profile_image": f}, format="multipart"
            )

        self.assertEqual(201, response.status_code)
        self.assertEqual("Profile Image Uploaded.", response.json()["detail"])


class TestCustomTokenRefreshView(APITestCase):

    def setUp(self) -> None:
        self.url = reverse("refresh_token")

        self.login_url = reverse("Login")

        self.user = baker.make(
            "drf_user.User",
            username="user",
            email="user@email.com",
            name="user",
            mobile=1234569877,
            is_active=True,
        )

        self.user.set_password("pass123")
        self.user.save()

    def test_fields_missing(self):
        res = self.client.post(self.url, data={})
        self.assertEqual(400, res.status_code)
        self.assertIn("refresh", res.data)

    def test_api_should_return_401_if_token_invalid(self):
        token = RefreshToken()
        del token["exp"]

        response = self.client.post(self.url, data={"refresh": str(token)})
        self.assertEqual(401, response.status_code)
        self.assertEqual("token_not_valid", response.data["code"])

        token.set_exp(lifetime=-timedelta(seconds=1))

        response = self.client.post(self.url, data={"refresh": str(token)})
        self.assertEqual(401, response.status_code)
        self.assertEqual("token_not_valid", response.data["code"])

    @pytest.mark.django_db
    def test_it_should_return_access_token_if_everything_ok(self):
        login_response = self.client.post(
            self.login_url, data={"username": "user", "password": "pass123"}
        )

        response = self.client.post(
            self.url, data={"refresh": str(login_response.data["refresh_token"])}
        )

        self.assertEqual(200, response.status_code)
        self.assertIn("token", response.data)
