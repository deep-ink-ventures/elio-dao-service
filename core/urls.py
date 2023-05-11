from django.urls import path
from rest_framework import routers

from core import views

router = routers.SimpleRouter()
router.register(r"accounts", views.AccountViewSet, "core-account")
router.register(r"daos", views.DaoViewSet, "core-dao")
router.register(r"assets", views.AssetViewSet, "core-asset")
router.register(r"asset-holdings", views.AssetHoldingViewSet, "core-asset-holding")
router.register(r"proposals", views.ProposalViewSet, "core-proposal")

urlpatterns = router.urls + [
    path(r"", views.welcome, name="core-welcome"),
    path(r"stats/", views.stats, name="core-stats"),
    path(r"config/", views.config, name="core-config"),
]
