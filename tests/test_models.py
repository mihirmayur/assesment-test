import pytest
from django.test import TestCase
from model_bakery import baker

from drf_user.models import AuthTransaction
from drf_user.models import OTPValidation
from drf_user.models import User


class TestUserModel(TestCase):

    def setUp(self) -> None:
        self.user = baker.make(
            "drf_user.User", name="test_user", username="my_unique_username"
        )

    @pytest.mark.django_db
    def test_object_created(self):
        self.assertEqual(1, User.objects.count())

    @pytest.mark.django_db
    def test_get_full_name(self):
        self.assertEqual("test_user", self.user.get_full_name())

    @pytest.mark.django_db
    def test_str_method(self):
        self.assertEqual("test_user | my_unique_username", str(self.user))


class TestAuthTransactionModel(TestCase):
    def setUp(self) -> None:
        self.auth_transaction = baker.make(
            "drf_user.AuthTransaction",
            created_by__name="test_name",
            created_by__username="test_username",
        )

    @pytest.mark.django_db
    def test_object_created(self):
        assert AuthTransaction.objects.count() == 1
        self.assertEqual(1, AuthTransaction.objects.count())

    @pytest.mark.django_db
    def test_str_method(self):
        self.assertEqual("test_name | test_username", str(self.auth_transaction))


class TestOTPValidationModel(TestCase):
    def setUp(self) -> None:
        self.otp_validation = baker.make("drf_user.OTPValidation", destination="mobile")

    @pytest.mark.django_db
    def test_object_created(self):
        self.assertEqual(1, OTPValidation.objects.count())

    @pytest.mark.django_db
    def test_str_method(self):
        self.assertEqual("mobile", str(self.otp_validation))
