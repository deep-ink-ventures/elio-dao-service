from django.core.cache import cache
from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin


class HealthCheckMiddleware(MiddlewareMixin):
    @staticmethod
    def process_request(request):
        if request.META["PATH_INFO"] == "/ping/":
            return HttpResponse("pong")


class BlockMetadataMiddleware(MiddlewareMixin):
    @staticmethod
    def process_response(_request, response):
        if current_block_number := cache.get("current_block_number"):
            response.headers["Block-Number"] = current_block_number
        return response
