"""elio-dao-service URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.staticfiles import views as static_views
from django.urls import include, path, re_path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

from core import urls as core_urls

schema_view = get_schema_view(
    openapi.Info(
        title="Elio Dao Service",
        default_version="v1",
        contact=openapi.Contact(email="admin@deep-ink.ventures"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

# noinspection PyUnresolvedReferences
urlpatterns = [
    path("admin/", admin.site.urls),
    path("multiclique/", include("multiclique.urls")),
    path("", include(core_urls.urlpatterns)),
    re_path(r"^redoc/$", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"),
]

if settings.DEBUG:
    urlpatterns += static("static", static_views.serve)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
