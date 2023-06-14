import re

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


class MultiFieldModelBackend(ModelBackend):
    user_model = get_user_model()

    def authenticate(self, request, username=None, password=None, **kwargs) -> None:

        if username is None:
            username = kwargs.get(self.user_model.USERNAME_FIELD)

        if username.isdigit():
            kwargs = {"mobile": username}
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", username):
            kwargs = {"username": username}
        else:
            kwargs = {"email": username}
        try:
            user = self.user_model.objects.get(**kwargs)
            if user.check_password(password):
                return user
        except self.user_model.DoesNotExist:
            return None

    def get_user(self, username: int) -> None:

        try:
            return self.user_model.objects.get(pk=username)
        except self.user_model.DoesNotExist:
            return None
