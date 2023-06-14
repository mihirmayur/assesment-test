from unittest import TestCase

import pytest
from faker import Faker

from drf_user.models import User

faker: Faker = Faker()


class TestUserManager(TestCase):

    @pytest.mark.django_db
    def test_create_normal_user_without_mobile(self):
        name = faker.name()
        user_name = faker.user_name()
        email = faker.email()
        password = faker.password()

        user = User.objects.create_user(
            username=user_name, email=email, password=password, name=name
        )

        self.assertEqual(name, user.name)
        self.assertEqual(user_name, user.username)
        self.assertEqual(email, user.email)
        self.assertIsNone(user.mobile)
        self.assertFalse(user.is_superuser)

    @pytest.mark.django_db
    def test_create_normal_user_with_mobile(self):
        name = faker.name()
        user_name = faker.user_name()
        email = faker.email()
        password = faker.password()
        mobile = faker.phone_number()

        user = User.objects.create_user(
            username=user_name, email=email, password=password, name=name, mobile=mobile
        )

        self.assertEqual(name, user.name)
        self.assertEqual(user_name, user.username)
        self.assertEqual(email, user.email)
        self.assertEqual(mobile, user.mobile)
        self.assertFalse(user.is_superuser)

    @pytest.mark.django_db
    def test_create_super_user_without_mobile(self):
        name = faker.name()
        user_name = faker.user_name()
        email = faker.email()
        password = faker.password()

        user = User.objects.create_superuser(
            username=user_name, email=email, password=password, name=name
        )

        self.assertEqual(name, user.name)
        self.assertEqual(user_name, user.username)
        self.assertEqual(email, user.email)
        self.assertIsNone(user.mobile)
        self.assertTrue(user.is_superuser)

    @pytest.mark.django_db
    def test_create_super_user_with_mobile(self):
        name = faker.name()
        user_name = faker.user_name()
        email = faker.email()
        password = faker.password()
        mobile = faker.phone_number()

        user = User.objects.create_superuser(
            username=user_name, email=email, password=password, name=name, mobile=mobile
        )

        self.assertEqual(name, user.name)
        self.assertEqual(user_name, user.username)
        self.assertEqual(email, user.email)
        self.assertEqual(mobile, user.mobile)
        self.assertTrue(user.is_superuser)

    @pytest.mark.django_db
    def test_create_super_user_raises_value_error_when_is_super_user_false(self):
        name = faker.name()
        user_name = faker.user_name()
        email = faker.email()
        password = faker.password()
        mobile = faker.phone_number()

        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                username=user_name,
                email=email,
                password=password,
                name=name,
                mobile=mobile,
                is_superuser=False,
            )

    @pytest.mark.django_db
    def test_create_super_user_raises_value_error_when_is_staff_false(self):
        name = faker.name()
        user_name = faker.user_name()
        email = faker.email()
        password = faker.password()
        mobile = faker.phone_number()

        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                username=user_name,
                email=email,
                password=password,
                name=name,
                mobile=mobile,
                is_staff=False,
            )
