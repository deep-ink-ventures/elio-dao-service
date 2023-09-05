from django.urls import path

from .views import install_account_and_policy

urlpatterns = [
    path("accounts/install", install_account_and_policy, name="install-account"),
]
