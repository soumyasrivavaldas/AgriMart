from django.contrib import admin
from .models import *
# Register your models here.
admin.site.register(User)
admin.site.register(Product)
admin.site.register(Cart)
admin.site.register(Customer)
admin.site.register(OrderPlaced)
admin.site.register(OrderList)
admin.site.register(Feedback)
# @admin.register(Customer)
# class custAdmin(admin.ModelAdmin):
#     list_display=["user","name","locality"]