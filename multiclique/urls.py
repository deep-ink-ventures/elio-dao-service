from rest_framework import routers

from multiclique import views

router = routers.SimpleRouter()
router.register(r"contracts", views.MultiCliqueContractViewSet, "multiclique-contracts")
router.register(r"accounts", views.MultiCliqueAccountViewSet, "multiclique-accounts")
router.register(r"transactions", views.MultiCliqueTransactionViewSet, "multiclique-transactions")

urlpatterns = router.urls
