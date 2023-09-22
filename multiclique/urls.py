from django.urls import path
from rest_framework import routers

from multiclique import views
from multiclique.views import install_account_and_policy

router = routers.SimpleRouter()
router.register(r"accounts", views.MultiCliqueAccountViewSet, "multiclique-accounts")
router.register(r"transactions", views.MultiCliqueTransactionViewSet, "multiclique-transactions")

urlpatterns = router.urls + [
    path("accounts/install", install_account_and_policy, name="install-account"),
]
