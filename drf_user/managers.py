from typing import Optional

from django.contrib.auth.base_user import BaseUserManager

from drf_user import update_user_settings


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(
            self,
            username: str,
            email: str,
            password: str,
            fullname: str,
            mobile: Optional[str] = None,
            **kwargs
    ):

        email = self.normalize_email(email)
        user = self.model(
            username=username, email=email, name=fullname, mobile=mobile, **kwargs
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(
            self,
            username: str,
            email: str,
            password: str,
            name: str,
            mobile: Optional[str] = None,
            **kwargs
    ):

        vals = update_user_settings()

        kwargs.setdefault("is_superuser", False)
        kwargs.setdefault("is_staff", False)
        kwargs.setdefault("is_active", vals.get("DEFAULT_ACTIVE_STATE", False))

        return self._create_user(username, email, password, name, mobile, **kwargs)

    def create_superuser(
            self,
            username: str,
            email: str,
            password: str,
            name: str,
            mobile: Optional[str] = None,
            **kwargs
    ):

        vals = update_user_settings()

        kwargs.setdefault("is_superuser", True)
        kwargs.setdefault("is_staff", True)
        kwargs.setdefault("is_active", vals.get("DEFAULT_ACTIVE_STATE", False))

        if kwargs.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        if kwargs.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")

        return self._create_user(username, email, password, name, mobile, **kwargs)
